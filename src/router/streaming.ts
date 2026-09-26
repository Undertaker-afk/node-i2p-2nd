import { randomInt, sign, verify } from 'node:crypto';
import { parseDestination } from './protocol/destination.ts';
import { publicEd25519 } from './crypto/x25519.ts';
import type { DestinationKeys } from './protocol/destination.ts';

export const STREAM_SYN = 1 << 0;
export const STREAM_CLOSE = 1 << 1;
export const STREAM_RESET = 1 << 2;
export const STREAM_SIGNATURE = 1 << 3;
export const STREAM_FROM = 1 << 5;
export const STREAM_DELAY = 1 << 6;
export const STREAM_MAX_PACKET = 1 << 7;
export const STREAM_NO_ACK = 1 << 10;
export const STREAM_MAX_PACKET_SIZE = 1730;

export type StreamingPacket = {
  sendStreamId: number;
  receiveStreamId: number;
  sequenceNum: number;
  ackThrough: number;
  nacks: number[];
  resendDelay: number;
  flags: number;
  delayRequested?: number;
  from?: Buffer;
  maxPacketSize?: number;
  signature?: Buffer;
  payload: Buffer;
};

function writeU32(value: number): Buffer {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value >>> 0);
  return bytes;
}

function optionOrder(flags: number): Buffer[] {
  const parts: Buffer[] = [];
  return parts;
  void flags;
}

export function encodeStreamingPacket(packet: StreamingPacket, signWith?: DestinationKeys): Buffer {
  if (!Number.isInteger(packet.sendStreamId) || packet.sendStreamId < 0 || packet.sendStreamId > 0xffff_ffff) throw new RangeError('sendStreamId is out of range');
  if (!Number.isInteger(packet.receiveStreamId) || packet.receiveStreamId < 0 || packet.receiveStreamId > 0xffff_ffff) throw new RangeError('receiveStreamId is out of range');
  if (!Array.isArray(packet.nacks) || packet.nacks.length > 255) throw new RangeError('NACK count is out of range');
  if (!Buffer.isBuffer(packet.payload)) throw new TypeError('payload must be a Buffer');
  const optionChunks: Buffer[] = [];
  if (packet.flags & STREAM_DELAY) {
    const delay = packet.delayRequested ?? 0;
    const bytes = Buffer.allocUnsafe(2); bytes.writeUInt16BE(delay); optionChunks.push(bytes);
  }
  if (packet.flags & STREAM_FROM) {
    if (!Buffer.isBuffer(packet.from)) throw new Error('FROM_INCLUDED requires a Destination');
    optionChunks.push(packet.from);
  }
  if (packet.flags & STREAM_MAX_PACKET) {
    const size = packet.maxPacketSize ?? STREAM_MAX_PACKET_SIZE;
    const bytes = Buffer.allocUnsafe(2); bytes.writeUInt16BE(size); optionChunks.push(bytes);
  }
  const signatureLength = packet.flags & STREAM_SIGNATURE ? 64 : 0;
  if (signatureLength) optionChunks.push(Buffer.alloc(64));
  const optionData = Buffer.concat(optionChunks);
  const header = Buffer.concat([
    writeU32(packet.sendStreamId), writeU32(packet.receiveStreamId), writeU32(packet.sequenceNum), writeU32(packet.ackThrough),
    Buffer.from([packet.nacks.length]), ...packet.nacks.map(writeU32), Buffer.from([packet.resendDelay]),
  ]);
  const flags = Buffer.allocUnsafe(2); flags.writeUInt16BE(packet.flags);
  const optSize = Buffer.allocUnsafe(2); optSize.writeUInt16BE(optionData.length);
  const encoded = Buffer.concat([header, flags, optSize, optionData, packet.payload]);
  if (signatureLength) {
    if (!signWith) throw new Error('SIGNATURE_INCLUDED requires destination signing keys');
    const signatureOffset = encoded.length - packet.payload.length - 64;
    sign(null, encoded, signWith.signingPrivateKey).copy(encoded, signatureOffset);
  }
  void optionOrder;
  return encoded;
}

export function parseStreamingPacket(bytes: Buffer): StreamingPacket {
  if (!Buffer.isBuffer(bytes) || bytes.length < 22) throw new Error('Streaming packet is truncated');
  let offset = 0;
  const sendStreamId = bytes.readUInt32BE(offset); offset += 4;
  const receiveStreamId = bytes.readUInt32BE(offset); offset += 4;
  const sequenceNum = bytes.readUInt32BE(offset); offset += 4;
  const ackThrough = bytes.readUInt32BE(offset); offset += 4;
  const nackCount = bytes[offset]!; offset += 1;
  const nacks: number[] = [];
  for (let index = 0; index < nackCount; index++) {
    nacks.push(bytes.readUInt32BE(offset)); offset += 4;
  }
  const resendDelay = bytes[offset]!; offset += 1;
  const flags = bytes.readUInt16BE(offset); offset += 2;
  const optionSize = bytes.readUInt16BE(offset); offset += 2;
  if (offset + optionSize > bytes.length) throw new Error('Streaming option data is truncated');
  const optionData = bytes.subarray(offset, offset + optionSize);
  offset += optionSize;
  let optionOffset = 0;
  let delayRequested: number | undefined;
  let from: Buffer | undefined;
  let maxPacketSize: number | undefined;
  let signature: Buffer | undefined;
  if (flags & STREAM_DELAY) {
    delayRequested = optionData.readUInt16BE(optionOffset); optionOffset += 2;
  }
  if (flags & STREAM_FROM) {
    if (optionOffset + 387 > optionData.length) throw new Error('Streaming FROM destination is truncated');
    const certLen = optionData.readUInt16BE(optionOffset + 385);
    const destLen = 387 + certLen;
    from = Buffer.from(optionData.subarray(optionOffset, optionOffset + destLen));
    parseDestination(from);
    optionOffset += destLen;
  }
  if (flags & STREAM_MAX_PACKET) {
    maxPacketSize = optionData.readUInt16BE(optionOffset); optionOffset += 2;
  }
  if (flags & STREAM_SIGNATURE) {
    if (optionOffset + 64 > optionData.length) throw new Error('Streaming signature is truncated');
    signature = Buffer.from(optionData.subarray(optionOffset, optionOffset + 64));
    optionOffset += 64;
  }
  const payload = Buffer.from(bytes.subarray(offset));
  const packet: StreamingPacket = {
    sendStreamId, receiveStreamId, sequenceNum, ackThrough, nacks, resendDelay, flags, payload,
    ...(delayRequested === undefined ? {} : { delayRequested }),
    ...(from === undefined ? {} : { from }),
    ...(maxPacketSize === undefined ? {} : { maxPacketSize }),
    ...(signature === undefined ? {} : { signature }),
  };
  if (signature && from) {
    const copy = Buffer.from(bytes);
    const sigOffset = bytes.length - payload.length - 64;
    copy.fill(0, sigOffset, sigOffset + 64);
    const dest = parseDestination(from);
    if (!verify(null, copy, publicEd25519(dest.signingPublicKey), signature)) throw new Error('Streaming packet signature is invalid');
  }
  return packet;
}

export function createSynPacket(local: DestinationKeys, receiveStreamId = randomInt(1, 0x1_0000_0000)): Buffer {
  return encodeStreamingPacket({
    sendStreamId: 0, receiveStreamId, sequenceNum: 0, ackThrough: 0, nacks: [], resendDelay: 1,
    flags: STREAM_SYN | STREAM_SIGNATURE | STREAM_FROM | STREAM_MAX_PACKET | STREAM_NO_ACK,
    from: local.destination, maxPacketSize: STREAM_MAX_PACKET_SIZE, payload: Buffer.alloc(0),
  }, local);
}

export function createSynAckPacket(local: DestinationKeys, sendStreamId: number, receiveStreamId: number): Buffer {
  return encodeStreamingPacket({
    sendStreamId, receiveStreamId, sequenceNum: 0, ackThrough: 0, nacks: [], resendDelay: 1,
    flags: STREAM_SYN | STREAM_SIGNATURE | STREAM_FROM | STREAM_MAX_PACKET,
    from: local.destination, maxPacketSize: STREAM_MAX_PACKET_SIZE, payload: Buffer.alloc(0),
  }, local);
}

export function createDataPacket(sendStreamId: number, receiveStreamId: number, sequenceNum: number, ackThrough: number, payload: Buffer): Buffer {
  return encodeStreamingPacket({
    sendStreamId, receiveStreamId, sequenceNum, ackThrough, nacks: [], resendDelay: 1, flags: 0, payload,
  });
}

export function createClosePacket(local: DestinationKeys, sendStreamId: number, receiveStreamId: number, sequenceNum: number, ackThrough: number): Buffer {
  return encodeStreamingPacket({
    sendStreamId, receiveStreamId, sequenceNum, ackThrough, nacks: [], resendDelay: 1,
    flags: STREAM_CLOSE | STREAM_SIGNATURE, payload: Buffer.alloc(0),
  }, local);
}

export const I2NP_DATA = 20;

export function encodeDataMessage(payload: Buffer, id: number, expiration = Date.now() + 60_000): { type: number; id: number; expiration: number; payload: Buffer } {
  if (!Buffer.isBuffer(payload) || payload.length > 0xffff) throw new RangeError('I2NP Data payload is too large');
  return { type: I2NP_DATA, id: id >>> 0, expiration, payload };
}
