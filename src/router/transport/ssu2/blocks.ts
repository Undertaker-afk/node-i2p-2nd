import net from 'node:net';
import { randomBytes } from 'node:crypto';
import type { I2npMessage } from '../../protocol/i2np.ts';

/** SSU2 payload block types. See https://i2p.net/en/docs/specs/ssu2/#noise-payload */
export const BLK_DATETIME = 0;
export const BLK_OPTIONS = 1;
export const BLK_ROUTER_INFO = 2;
export const BLK_I2NP = 3;
export const BLK_FIRST_FRAGMENT = 4;
export const BLK_FOLLOW_ON_FRAGMENT = 5;
export const BLK_TERMINATION = 6;
export const BLK_RELAY_REQUEST = 7;
export const BLK_RELAY_RESPONSE = 8;
export const BLK_RELAY_INTRO = 9;
export const BLK_PEER_TEST = 10;
export const BLK_ACK = 12;
export const BLK_ADDRESS = 13;
export const BLK_RELAY_TAG_REQUEST = 15;
export const BLK_RELAY_TAG = 16;
export const BLK_NEW_TOKEN = 17;
export const BLK_PATH_CHALLENGE = 18;
export const BLK_PATH_RESPONSE = 19;
export const BLK_CONGESTION = 21;
export const BLK_PADDING = 254;

export const TERMINATION_NORMAL = 0;
export const TERMINATION_RECEIVED = 1;
export const TERMINATION_IDLE = 2;
export const TERMINATION_SHUTDOWN = 3;
export const TERMINATION_CLOCK_SKEW = 7;
export const TERMINATION_SESSION_CONFIRMED_ERROR = 13;
export const TERMINATION_TIMEOUT = 14;
export const TERMINATION_BAD_TOKEN = 18;
export const TERMINATION_WRONG_NET_ID = 21;

export type Ssu2Block = { type: number; data: Buffer };

export function encodeBlock(block: Ssu2Block): Buffer {
  if (!Number.isInteger(block.type) || block.type < 0 || block.type > 255) throw new RangeError('SSU2 block type must be uint8');
  if (block.data.length > 0xffff) throw new RangeError('SSU2 block too large');
  const header = Buffer.allocUnsafe(3); header[0] = block.type; header.writeUInt16BE(block.data.length, 1);
  return Buffer.concat([header, block.data]);
}

export function encodeBlocks(blocks: readonly Ssu2Block[]): Buffer {
  return Buffer.concat(blocks.map(encodeBlock));
}

/** Parses TLV blocks; never reads beyond the payload. Unknown types are returned for the caller to ignore. */
export function decodeBlocks(payload: Buffer): Ssu2Block[] {
  const blocks: Ssu2Block[] = [];
  let offset = 0;
  while (offset < payload.length) {
    if (payload.length - offset < 3) throw new Error('Truncated SSU2 block header');
    const type = payload[offset]!; const length = payload.readUInt16BE(offset + 1);
    offset += 3;
    if (length > payload.length - offset) throw new Error('SSU2 block overruns payload');
    blocks.push({ type, data: Buffer.from(payload.subarray(offset, offset + length)) });
    offset += length;
  }
  return blocks;
}

export function blocksSize(blocks: readonly Ssu2Block[]): number {
  return blocks.reduce((sum, block) => sum + 3 + block.data.length, 0);
}

export function dateTimeBlock(nowMs = Date.now()): Ssu2Block {
  const data = Buffer.allocUnsafe(4); data.writeUInt32BE(Math.floor((nowMs + 500) / 1000) >>> 0, 0);
  return { type: BLK_DATETIME, data };
}

export function parseDateTime(block: Ssu2Block): number {
  if (block.type !== BLK_DATETIME || block.data.length < 4) throw new Error('Invalid SSU2 DateTime block');
  return block.data.readUInt32BE(0) * 1000;
}

/** Padding block of exactly `total` bytes including its 3-byte header (total >= 3). */
export function paddingBlock(total: number): Ssu2Block {
  if (!Number.isInteger(total) || total < 3) throw new RangeError('Padding block needs at least 3 bytes');
  return { type: BLK_PADDING, data: randomBytes(total - 3) };
}

/** Appends padding so the payload is at least `min` bytes and stays within `max`. */
export function padBlocks(blocks: Ssu2Block[], min: number, max: number, randomExtra = 0): Ssu2Block[] {
  const size = blocksSize(blocks);
  let target = Math.max(min, size + (randomExtra > 0 ? Math.floor(Math.random() * (randomExtra + 1)) : 0));
  target = Math.min(target, max);
  if (target - size >= 3) return [...blocks, paddingBlock(target - size)];
  if (size < min) return [...blocks, paddingBlock(Math.min(max - size, Math.max(3, min - size)))];
  return blocks;
}

export function i2npBlock(message: I2npMessage, type = BLK_I2NP): Ssu2Block {
  const header = encodeShortI2npHeader(message);
  return { type, data: Buffer.concat([header, message.payload]) };
}

export function encodeShortI2npHeader(message: I2npMessage): Buffer {
  if (!Number.isInteger(message.type) || message.type < 0 || message.type > 255) throw new RangeError('Invalid I2NP type');
  if (!Number.isInteger(message.id) || message.id < 0 || message.id > 0xffff_ffff) throw new RangeError('Invalid I2NP message id');
  const header = Buffer.allocUnsafe(9);
  header[0] = message.type; header.writeUInt32BE(message.id >>> 0, 1);
  header.writeUInt32BE(Math.floor(message.expiration / 1000) >>> 0, 5);
  return header;
}

export function decodeI2npBlockData(data: Buffer): I2npMessage {
  if (data.length < 9) throw new Error('SSU2 I2NP block shorter than its 9-byte header');
  return { type: data[0]!, id: data.readUInt32BE(1), expiration: data.readUInt32BE(5) * 1000, payload: Buffer.from(data.subarray(9)) };
}

/**
 * Splits an I2NP message into First Fragment + Follow-on Fragment blocks,
 * each fitting in `maxBlockSize` bytes including the 3-byte block header.
 * Returns a single I2NP block when it fits.
 */
export function fragmentI2np(message: I2npMessage, maxBlockSize: number): Ssu2Block[] {
  const whole = i2npBlock(message);
  if (3 + whole.data.length <= maxBlockSize) return [whole];
  const header = encodeShortI2npHeader(message);
  const firstPart = maxBlockSize - 3 - 9;
  const followPart = maxBlockSize - 3 - 5;
  if (firstPart < 1 || followPart < 1) throw new RangeError('maxBlockSize too small for fragmentation');
  const body = message.payload;
  const blocks: Ssu2Block[] = [{ type: BLK_FIRST_FRAGMENT, data: Buffer.concat([header, body.subarray(0, firstPart)]) }];
  let offset = firstPart; let fragment = 1;
  while (offset < body.length) {
    const chunk = body.subarray(offset, offset + followPart);
    offset += chunk.length;
    if (fragment > 127) throw new RangeError('I2NP message needs more than 127 SSU2 fragments');
    const info = Buffer.allocUnsafe(5);
    info[0] = (fragment << 1) | (offset >= body.length ? 1 : 0);
    info.writeUInt32BE(message.id >>> 0, 1);
    blocks.push({ type: BLK_FOLLOW_ON_FRAGMENT, data: Buffer.concat([info, chunk]) });
    fragment++;
  }
  return blocks;
}

export type AckBlock = { ackThrough: number; acnt: number; ranges: Array<[nacks: number, acks: number]> };

export function encodeAckBlock(ack: AckBlock): Ssu2Block {
  const data = Buffer.allocUnsafe(5 + ack.ranges.length * 2);
  data.writeUInt32BE(ack.ackThrough >>> 0, 0); data[4] = ack.acnt;
  ack.ranges.forEach(([nacks, acks], index) => { data[5 + index * 2] = nacks; data[6 + index * 2] = acks; });
  return { type: BLK_ACK, data };
}

export function decodeAckBlock(block: Ssu2Block): AckBlock {
  if (block.type !== BLK_ACK || block.data.length < 5 || (block.data.length - 5) % 2 !== 0) throw new Error('Invalid SSU2 ACK block');
  const ranges: Array<[number, number]> = [];
  for (let offset = 5; offset < block.data.length; offset += 2) ranges.push([block.data[offset]!, block.data[offset + 1]!]);
  return { ackThrough: block.data.readUInt32BE(0), acnt: block.data[4]!, ranges };
}

/** Expands an ACK block into the list of acknowledged packet numbers. */
export function ackedPacketNumbers(ack: AckBlock): number[] {
  const result: number[] = [];
  let current = ack.ackThrough;
  for (let index = 0; index <= ack.acnt && current >= 0; index++) result.push(current--);
  for (const [nacks, acks] of ack.ranges) {
    current -= nacks;
    for (let index = 0; index < acks && current >= 0; index++) result.push(current--);
    if (current < 0) break;
  }
  return result;
}

/**
 * Builds an ACK block from a set of received packet numbers (highest first),
 * limited to `maxRanges` nack/ack ranges.
 */
export function buildAckBlock(received: Iterable<number>, maxRanges = 16): AckBlock | undefined {
  const sorted = [...new Set(received)].sort((a, b) => b - a);
  if (!sorted.length) return undefined;
  const ackThrough = sorted[0]!;
  let index = 1; let acnt = 0; let expected = ackThrough - 1;
  while (index < sorted.length && sorted[index] === expected && acnt < 255) { acnt++; index++; expected--; }
  const ranges: Array<[number, number]> = [];
  while (index < sorted.length && ranges.length < maxRanges) {
    const gap = expected - sorted[index]!;
    if (gap > 255) break;
    expected -= gap;
    let acks = 0;
    while (index < sorted.length && sorted[index] === expected && acks < 255) { acks++; index++; expected--; }
    ranges.push([gap, acks]);
  }
  return { ackThrough, acnt, ranges };
}

export function terminationBlock(reason: number, validPackets = 0n): Ssu2Block {
  const data = Buffer.alloc(9); data.writeBigUInt64BE(validPackets, 0); data[8] = reason;
  return { type: BLK_TERMINATION, data };
}

export function parseTermination(block: Ssu2Block): { validPackets: bigint; reason: number } {
  if (block.type !== BLK_TERMINATION || block.data.length < 9) throw new Error('Invalid SSU2 Termination block');
  return { validPackets: block.data.readBigUInt64BE(0), reason: block.data[8]! };
}

export function addressBlock(host: string, port: number): Ssu2Block | undefined {
  if (net.isIPv4(host)) {
    const data = Buffer.allocUnsafe(6); data.writeUInt16BE(port, 0);
    host.split('.').forEach((part, index) => { data[2 + index] = Number(part); });
    return { type: BLK_ADDRESS, data };
  }
  return undefined;
}

export function parseAddressBlock(block: Ssu2Block): { host: string; port: number } | undefined {
  if (block.type !== BLK_ADDRESS) return undefined;
  if (block.data.length === 6) return { port: block.data.readUInt16BE(0), host: [...block.data.subarray(2, 6)].join('.') };
  if (block.data.length === 18) {
    const groups: string[] = [];
    for (let offset = 2; offset < 18; offset += 2) groups.push(block.data.readUInt16BE(offset).toString(16));
    return { port: block.data.readUInt16BE(0), host: groups.join(':') };
  }
  return undefined;
}

export function newTokenBlock(token: Buffer, expiresMs: number): Ssu2Block {
  if (token.length !== 8) throw new Error('SSU2 token must be 8 bytes');
  const data = Buffer.allocUnsafe(12); data.writeUInt32BE(Math.floor(expiresMs / 1000) >>> 0, 0); token.copy(data, 4);
  return { type: BLK_NEW_TOKEN, data };
}

export function parseNewToken(block: Ssu2Block): { expiresMs: number; token: Buffer } {
  if (block.type !== BLK_NEW_TOKEN || block.data.length < 12) throw new Error('Invalid SSU2 New Token block');
  return { expiresMs: block.data.readUInt32BE(0) * 1000, token: Buffer.from(block.data.subarray(4, 12)) };
}

/** Session Confirmed RouterInfo block: flag (bit1 = gzip), frag (always 0/1). */
export function routerInfoBlock(routerInfo: Buffer, gzip: boolean, flood = false): Ssu2Block {
  const data = Buffer.allocUnsafe(2 + routerInfo.length);
  data[0] = (flood ? 1 : 0) | (gzip ? 2 : 0); data[1] = 0x01;
  routerInfo.copy(data, 2);
  return { type: BLK_ROUTER_INFO, data };
}

/** Blocks that elicit an ACK. ACK, padding, and termination alone do not. */
export function isAckEliciting(blocks: readonly Ssu2Block[]): boolean {
  return blocks.some(block => block.type !== BLK_ACK && block.type !== BLK_PADDING && block.type !== BLK_TERMINATION);
}
