import { createHash } from 'node:crypto';

export type I2npMessage = {
  type: number;
  id: number;
  expiration: number;
  payload: Buffer;
};
export type ShortI2npHeader = { type: number; id: number; expirationSeconds: number };
export const I2NP_HEADER_LENGTH = 16;
export const I2NP_MAX_PAYLOAD = 0xffff;
export const I2NP_SHORT_HEADER_LENGTH = 9;

function assertInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${name} must be an integer in range ${min}..${max}`);
}

/** Encodes the 16-byte standard I2NP header and payload. */
export function encodeI2np(message: I2npMessage): Buffer {
  assertInteger('type', message.type, 0, 255);
  assertInteger('id', message.id, 0, 0xffff_ffff);
  assertInteger('expiration', message.expiration, 0, Number.MAX_SAFE_INTEGER);
  if (!Buffer.isBuffer(message.payload)) throw new TypeError('payload must be a Buffer');
  if (message.payload.length > I2NP_MAX_PAYLOAD) throw new RangeError('I2NP payload exceeds 65535 bytes');
  const packet = Buffer.allocUnsafe(I2NP_HEADER_LENGTH + message.payload.length);
  packet.writeUInt8(message.type, 0);
  packet.writeUInt32BE(message.id, 1);
  packet.writeBigUInt64BE(BigInt(message.expiration), 5);
  packet.writeUInt16BE(message.payload.length, 13);
  packet[15] = createHash('sha256').update(message.payload).digest()[0]!;
  message.payload.copy(packet, I2NP_HEADER_LENGTH);
  return packet;
}

/** Decodes exactly one standard I2NP message; trailing or truncated bytes are rejected. */
export function decodeI2np(packet: Buffer): I2npMessage {
  if (!Buffer.isBuffer(packet)) throw new TypeError('packet must be a Buffer');
  if (packet.length < I2NP_HEADER_LENGTH) throw new Error('Truncated I2NP header');
  const length = packet.readUInt16BE(13);
  if (packet.length !== I2NP_HEADER_LENGTH + length) throw new Error('I2NP payload length does not match packet length');
  const payload = packet.subarray(I2NP_HEADER_LENGTH);
  const checksum = createHash('sha256').update(payload).digest()[0]!;
  if (packet[15] !== checksum) throw new Error('I2NP payload checksum mismatch');
  const expirationBig = packet.readBigUInt64BE(5);
  if (expirationBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('I2NP expiration exceeds safe integer range');
  return { type: packet.readUInt8(0), id: packet.readUInt32BE(1), expiration: Number(expirationBig), payload: Buffer.from(payload) };
}

/** Incremental decoder for streams carrying standard-format I2NP messages. */
export class I2npStreamDecoder {
  private buffered = Buffer.alloc(0);
  private ended = false;
  readonly maxBufferedBytes: number;
  constructor(maxBufferedBytes = I2NP_HEADER_LENGTH + I2NP_MAX_PAYLOAD) {
    this.maxBufferedBytes = maxBufferedBytes;
    if (!Number.isSafeInteger(maxBufferedBytes) || maxBufferedBytes < I2NP_HEADER_LENGTH + I2NP_MAX_PAYLOAD) {
      throw new RangeError(`maxBufferedBytes must be at least ${I2NP_HEADER_LENGTH + I2NP_MAX_PAYLOAD}`);
    }
  }
  push(chunk: Buffer): I2npMessage[] {
    if (this.ended) throw new Error('I2NP decoder is already ended');
    if (!Buffer.isBuffer(chunk)) throw new TypeError('chunk must be a Buffer');
    const messages: I2npMessage[] = [];
    let offset = 0;
    while (offset < chunk.length || this.buffered.length >= I2NP_HEADER_LENGTH) {
      if (this.buffered.length < I2NP_HEADER_LENGTH) {
        const count = Math.min(I2NP_HEADER_LENGTH - this.buffered.length, chunk.length - offset);
        if (count > 0) { this.buffered = Buffer.concat([this.buffered, chunk.subarray(offset, offset + count)]); offset += count; }
        if (this.buffered.length < I2NP_HEADER_LENGTH) break;
      }
      const packetLength = I2NP_HEADER_LENGTH + this.buffered.readUInt16BE(13);
      if (this.buffered.length < packetLength) {
        const count = Math.min(packetLength - this.buffered.length, chunk.length - offset);
        if (count > 0) { this.buffered = Buffer.concat([this.buffered, chunk.subarray(offset, offset + count)]); offset += count; }
        if (this.buffered.length < packetLength) break;
      }
      messages.push(decodeI2np(this.buffered.subarray(0, packetLength)));
      this.buffered = this.buffered.subarray(packetLength);
    }
    if (this.buffered.length > this.maxBufferedBytes) throw new Error('I2NP decoder buffer limit exceeded');
    return messages;
  }
  finish(): void {
    this.ended = true;
    if (this.buffered.length) throw new Error('Truncated I2NP stream');
  }
  get pendingBytes(): number { return this.buffered.length; }
}

/** Encodes the 9-byte short header used by NTCP2/SSU2 encapsulations. */
export function encodeShortI2npHeader(header: ShortI2npHeader): Buffer {
  assertInteger('type', header.type, 0, 255);
  assertInteger('id', header.id, 0, 0xffff_ffff);
  assertInteger('expirationSeconds', header.expirationSeconds, 0, 0xffff_ffff);
  const result = Buffer.allocUnsafe(I2NP_SHORT_HEADER_LENGTH);
  result.writeUInt8(header.type, 0); result.writeUInt32BE(header.id, 1); result.writeUInt32BE(header.expirationSeconds, 5);
  return result;
}

export function decodeShortI2npHeader(header: Buffer): ShortI2npHeader {
  if (!Buffer.isBuffer(header) || header.length !== I2NP_SHORT_HEADER_LENGTH) throw new Error('Short I2NP header must be exactly 9 bytes');
  return { type: header.readUInt8(0), id: header.readUInt32BE(1), expirationSeconds: header.readUInt32BE(5) };
}
