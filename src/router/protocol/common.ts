import { TextDecoder } from 'node:util';

const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
export const I2P_HASH_LENGTH = 32;

export class ByteReader {
  private offset = 0;
  readonly input: Buffer;
  readonly maxInputBytes: number;
  constructor(input: Buffer, maxInputBytes = 16 * 1024 * 1024) {
    this.input = input; this.maxInputBytes = maxInputBytes;
    if (!Buffer.isBuffer(input)) throw new TypeError('input must be a Buffer');
    if (!Number.isSafeInteger(maxInputBytes) || maxInputBytes < 0) throw new RangeError('maxInputBytes must be a non-negative safe integer');
    if (input.length > maxInputBytes) throw new RangeError('Input exceeds configured limit');
  }
  get remaining(): number { return this.input.length - this.offset; }
  get position(): number { return this.offset; }
  readBytes(length: number): Buffer {
    if (!Number.isSafeInteger(length) || length < 0) throw new RangeError('length must be a non-negative safe integer');
    if (length > this.remaining) throw new Error(`Truncated input at offset ${this.offset}: need ${length}, have ${this.remaining}`);
    const value = this.input.subarray(this.offset, this.offset + length); this.offset += length; return value;
  }
  readUInt8(): number { return this.readBytes(1).readUInt8(0); }
  readUInt16(): number { return this.readBytes(2).readUInt16BE(0); }
  readUInt32(): number { return this.readBytes(4).readUInt32BE(0); }
  readDate(): number {
    const value = this.readBytes(8).readBigUInt64BE(0);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('Date exceeds safe integer range');
    return Number(value);
  }
  readHash(): Buffer { return this.readBytes(I2P_HASH_LENGTH); }
  readString(): string {
    const length = this.readUInt8();
    try { return strictUtf8.decode(this.readBytes(length)); }
    catch (error) { throw new Error(`Invalid UTF-8 string at offset ${this.offset - length}: ${error instanceof Error ? error.message : String(error)}`); }
  }
  assertEnd(): void { if (this.remaining !== 0) throw new Error(`Unexpected ${this.remaining} trailing byte(s)`); }
}

export function encodeDate(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('Date must be a non-negative safe integer');
  const result = Buffer.allocUnsafe(8); result.writeBigUInt64BE(BigInt(value)); return result;
}

export function encodeString(value: string): Buffer {
  if (typeof value !== 'string') throw new TypeError('String value required');
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > 255) throw new RangeError('I2P string exceeds 255 encoded bytes');
  if (strictUtf8.decode(bytes) !== value) throw new Error('String contains invalid Unicode surrogate data');
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}
