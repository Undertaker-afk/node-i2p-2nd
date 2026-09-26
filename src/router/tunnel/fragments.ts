import { createHash, randomBytes, randomInt } from 'node:crypto';
import type { I2npMessage } from '../protocol/i2np.ts';
import { encodeI2np } from '../protocol/i2np.ts';
import { TUNNEL_MESSAGE_SIZE } from './data.ts';

const IV_LENGTH = 16;
const BODY_LENGTH = TUNNEL_MESSAGE_SIZE - IV_LENGTH;
const BODY_FIXED_PREFIX = 4;
export type TunnelDelivery =
  | { type: 'local' }
  | { type: 'router'; identityHash: Buffer }
  | { type: 'tunnel'; gatewayHash: Buffer; tunnelId: number };
export type TunnelFragment = {
  iv: Buffer;
  delivery: TunnelDelivery;
  followOn: boolean;
  fragmentNumber: number;
  lastFragment: boolean;
  messageId?: number;
  data: Buffer;
};

function deliveryType(delivery: TunnelDelivery): number {
  if (delivery.type === 'local') return 0;
  if (delivery.type === 'tunnel') return 1;
  return 2;
}
function deliveryHeader(delivery: TunnelDelivery): Buffer {
  if (delivery.type === 'local') return Buffer.alloc(0);
  if (!Buffer.isBuffer(delivery.type === 'router' ? delivery.identityHash : delivery.gatewayHash) || (delivery.type === 'router' ? delivery.identityHash : delivery.gatewayHash).length !== 32) throw new Error('Tunnel delivery identity hash must be 32 bytes');
  if (delivery.type === 'router') return Buffer.from(delivery.identityHash);
  if (!Number.isSafeInteger(delivery.tunnelId) || delivery.tunnelId < 1 || delivery.tunnelId > 0xffff_ffff) throw new RangeError('Tunnel delivery ID must be a nonzero uint32');
  const output = Buffer.allocUnsafe(36); output.writeUInt32BE(delivery.tunnelId, 0); delivery.gatewayHash.copy(output, 4); return output;
}
function makeBody(iv: Buffer, instructionAndData: Buffer, random: (size: number) => Buffer): Buffer {
  const room = BODY_LENGTH - BODY_FIXED_PREFIX - 1 - instructionAndData.length;
  if (room < 0) throw new RangeError('Tunnel fragment does not fit in one message');
  const padding = random(room);
  if (!Buffer.isBuffer(padding) || padding.length !== room) throw new Error('Random source returned the wrong tunnel padding length');
  for (let index = 0; index < padding.length; index++) if (padding[index] === 0) padding[index] = 1;
  const output = Buffer.allocUnsafe(BODY_LENGTH);
  const checksum = createHash('sha256').update(instructionAndData).update(iv).digest();
  checksum.copy(output, 0, 0, 4);
  padding.copy(output, 4);
  output[4 + room] = 0;
  instructionAndData.copy(output, 5 + room);
  return output;
}

/** Creates fixed-size plaintext tunnel messages carrying the fragment(s) of one I2NP message. */
export function buildTunnelMessageFragments(
  message: I2npMessage,
  delivery: TunnelDelivery,
  options: { iv?: Buffer; random?: (size: number) => Buffer } = {},
): Buffer[] {
  const bytes = encodeI2np(message);
  const random = options.random ?? randomBytes;
  const iv = options.iv ? Buffer.from(options.iv) : randomBytes(IV_LENGTH);
  if (iv.length !== IV_LENGTH) throw new Error('Tunnel IV must be 16 bytes');
  const route = deliveryHeader(delivery);
  const typeBits = deliveryType(delivery) << 5;
  const initialFixed = 1 + route.length + 2;
  const firstCapacity = BODY_LENGTH - BODY_FIXED_PREFIX - 1 - initialFixed;
  const isFragmented = bytes.length > firstCapacity;
  const initialHeaderLength = initialFixed + (isFragmented ? 4 : 0);
  const initialCapacity = BODY_LENGTH - BODY_FIXED_PREFIX - 1 - initialHeaderLength;
  const fragments: Buffer[] = [];
  let offset = 0;
  const firstSize = Math.min(bytes.length, initialCapacity);
  if (firstSize < 1) throw new RangeError('I2NP message cannot fit a tunnel fragment');
  const control = Buffer.from([typeBits | (isFragmented ? 0x08 : 0)]);
  const firstHeader = Buffer.allocUnsafe(initialHeaderLength);
  let p = 0; control.copy(firstHeader, p); p++;
  route.copy(firstHeader, p); p += route.length;
  if (isFragmented) { firstHeader.writeUInt32BE(message.id >>> 0, p); p += 4; }
  firstHeader.writeUInt16BE(firstSize, p);
  const firstData = Buffer.concat([firstHeader, bytes.subarray(0, firstSize)]);
  const firstBody = makeBody(iv, firstData, random);
  fragments.push(Buffer.concat([iv, firstBody]));
  offset += firstSize;

  let fragmentNumber = 1;
  while (offset < bytes.length) {
    if (fragmentNumber > 63) throw new RangeError('I2NP message requires more than 63 tunnel fragments');
    const size = Math.min(bytes.length - offset, BODY_LENGTH - BODY_FIXED_PREFIX - 1 - 7);
    const isLast = offset + size === bytes.length;
    const header = Buffer.allocUnsafe(7);
    header[0] = 0x80 | (fragmentNumber << 1) | (isLast ? 1 : 0);
    header.writeUInt32BE(message.id >>> 0, 1);
    header.writeUInt16BE(size, 5);
    const instructionAndData = Buffer.concat([header, bytes.subarray(offset, offset + size)]);
    const fragmentIv = randomBytes(IV_LENGTH);
    fragments.push(Buffer.concat([fragmentIv, makeBody(fragmentIv, instructionAndData, random)]));
    offset += size;
    fragmentNumber++;
  }
  return fragments;
}

/** Parses the checksum-protected inner message of a decrypted 1024-byte tunnel message. */
export function parseTunnelMessageFragment(message: Buffer): TunnelFragment {
  if (!Buffer.isBuffer(message) || message.length !== TUNNEL_MESSAGE_SIZE) throw new Error('Decrypted tunnel message must be exactly 1024 bytes');
  const iv = Buffer.from(message.subarray(0, IV_LENGTH));
  const body = message.subarray(IV_LENGTH);
  let delimiter = BODY_FIXED_PREFIX;
  while (delimiter < body.length && body[delimiter] !== 0) delimiter++;
  if (delimiter >= body.length) throw new Error('Tunnel message padding delimiter is missing');
  const instructions = body.subarray(delimiter + 1);
  if (instructions.length < 3) throw new Error('Tunnel message delivery instruction is truncated');
  const control = instructions[0]!;
  let delivery: TunnelDelivery;
  let offset = 1;
  const type = (control >>> 5) & 3;
  if (control & 0x80) {
    if (instructions.length < 7) throw new Error('Follow-on fragment instruction is truncated');
    const fragmentNumber = (control >>> 1) & 0x3f;
    const messageId = instructions.readUInt32BE(1);
    const fragmentLength = instructions.readUInt16BE(5);
    if (fragmentNumber < 1 || fragmentLength < 1 || 7 + fragmentLength !== instructions.length) throw new Error('Follow-on fragment fields are invalid or trailing bytes are present');
    validateChecksum(body, iv, instructions);
    return { iv, delivery: { type: 'local' }, followOn: true, fragmentNumber, lastFragment: Boolean(control & 1), messageId, data: Buffer.from(instructions.subarray(7, 7 + fragmentLength)) };
  }
  if ((control & 0x03) !== 0 || type === 3) throw new Error('Unsupported tunnel delivery instruction flags/type');
  if (control & 0x10) throw new Error('Tunnel message delay is not supported');
  if (control & 0x04) throw new Error('Tunnel message extended options are not supported');
  if (type === 0) delivery = { type: 'local' };
  else if (type === 1) {
    if (offset + 36 > instructions.length) throw new Error('Tunnel delivery instruction lacks tunnel ID/hash');
    const tunnelId = instructions.readUInt32BE(offset); offset += 4;
    if (!tunnelId) throw new Error('Tunnel delivery ID must be nonzero');
    delivery = { type: 'tunnel', tunnelId, gatewayHash: Buffer.from(instructions.subarray(offset, offset + 32)) }; offset += 32;
  } else {
    if (offset + 32 > instructions.length) throw new Error('Router delivery instruction lacks identity hash');
    delivery = { type: 'router', identityHash: Buffer.from(instructions.subarray(offset, offset + 32)) }; offset += 32;
  }
  const fragmented = Boolean(control & 0x08);
  let messageId: number | undefined;
  if (fragmented) {
    if (offset + 4 > instructions.length) throw new Error('Initial fragment lacks message ID');
    messageId = instructions.readUInt32BE(offset); offset += 4;
  }
  if (offset + 2 > instructions.length) throw new Error('Tunnel fragment length is truncated');
  const fragmentLength = instructions.readUInt16BE(offset); offset += 2;
  if (fragmentLength < 1 || offset + fragmentLength !== instructions.length) throw new Error('Tunnel fragment length is invalid or trailing bytes are present');
  const data = Buffer.from(instructions.subarray(offset, offset + fragmentLength));
  validateChecksum(body, iv, instructions);
  return { iv, delivery, followOn: false, fragmentNumber: 0, lastFragment: !fragmented, ...(messageId === undefined ? {} : { messageId }), data };
}

function validateChecksum(body: Buffer, iv: Buffer, instructions: Buffer): void {
  const expected = createHash('sha256').update(instructions).update(iv).digest().subarray(0, 4);
  if (!body.subarray(0, 4).equals(expected)) throw new Error('Tunnel message checksum mismatch');
}
