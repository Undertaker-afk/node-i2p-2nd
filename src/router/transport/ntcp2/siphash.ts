export type SipHashKeys = { key1: Buffer; key2: Buffer; iv: Buffer };
const MASK64 = 0xffff_ffff_ffff_ffffn;
function rotateLeft(value: bigint, shift: bigint): bigint { return ((value << shift) | (value >> (64n - shift))) & MASK64; }
function readLittleEndian64(bytes: Buffer, offset: number): bigint {
  let value = 0n;
  for (let index = 7; index >= 0; index--) value = (value << 8n) | BigInt(bytes[offset + index]!);
  return value;
}
function sipRound(v: [bigint, bigint, bigint, bigint]): void {
  v[0] = (v[0]! + v[1]!) & MASK64; v[1] = rotateLeft(v[1]!, 13n); v[1] ^= v[0]!; v[0] = rotateLeft(v[0]!, 32n);
  v[2] = (v[2]! + v[3]!) & MASK64; v[3] = rotateLeft(v[3]!, 16n); v[3] ^= v[2]!;
  v[0] = (v[0]! + v[3]!) & MASK64; v[3] = rotateLeft(v[3]!, 21n); v[3] ^= v[0]!;
  v[2] = (v[2]! + v[1]!) & MASK64; v[1] = rotateLeft(v[1]!, 17n); v[1] ^= v[2]!; v[2] = rotateLeft(v[2]!, 32n);
}

/** SipHash-2-4, returning the 64-bit digest in little-endian byte order. */
export function sipHash24(key1: Buffer, key2: Buffer, message: Buffer): Buffer {
  if (!Buffer.isBuffer(key1) || key1.length !== 8 || !Buffer.isBuffer(key2) || key2.length !== 8) throw new Error('SipHash keys must each be 8 bytes');
  if (!Buffer.isBuffer(message)) throw new TypeError('SipHash message must be a Buffer');
  const k0 = readLittleEndian64(key1, 0); const k1 = readLittleEndian64(key2, 0);
  const state: [bigint, bigint, bigint, bigint] = [
    0x736f6d6570736575n ^ k0, 0x646f72616e646f6dn ^ k1,
    0x6c7967656e657261n ^ k0, 0x7465646279746573n ^ k1,
  ];
  let offset = 0;
  while (offset + 8 <= message.length) {
    const word = readLittleEndian64(message, offset); state[3] ^= word;
    sipRound(state); sipRound(state); state[0] ^= word; offset += 8;
  }
  let tail = BigInt(message.length & 0xff) << 56n;
  for (let index = 0; offset + index < message.length; index++) tail |= BigInt(message[offset + index]!) << BigInt(8 * index);
  state[3] ^= tail; sipRound(state); sipRound(state); state[0] ^= tail; state[2] ^= 0xffn;
  sipRound(state); sipRound(state); sipRound(state); sipRound(state);
  const digest = (state[0]! ^ state[1]! ^ state[2]! ^ state[3]!) & MASK64;
  const output = Buffer.allocUnsafe(8); output.writeBigUInt64LE(digest); return output;
}

export class SipHashLengthCipher {
  private readonly key1: Buffer; private readonly key2: Buffer; private iv: Buffer;
  constructor(keys: SipHashKeys) {
    if (keys.key1.length !== 8 || keys.key2.length !== 8 || keys.iv.length !== 8) throw new Error('SipHash length state values must be 8 bytes');
    this.key1 = Buffer.from(keys.key1); this.key2 = Buffer.from(keys.key2); this.iv = Buffer.from(keys.iv);
  }
  private nextMask(): number {
    this.iv = sipHash24(this.key1, this.key2, this.iv);
    return this.iv.readUInt16LE(0);
  }
  encode(length: number): number {
    if (!Number.isInteger(length) || length < 16 || length > 0xffff) throw new RangeError('NTCP2 encrypted frame length must be 16..65535');
    return length ^ this.nextMask();
  }
  decode(obfuscated: number): number {
    if (!Number.isInteger(obfuscated) || obfuscated < 0 || obfuscated > 0xffff) throw new RangeError('Obfuscated frame length must be uint16');
    const length = obfuscated ^ this.nextMask();
    if (length < 16 || length > 0xffff) throw new Error('Invalid de-obfuscated NTCP2 frame length');
    return length;
  }
  destroy(): void { this.key1.fill(0); this.key2.fill(0); this.iv.fill(0); }
}
