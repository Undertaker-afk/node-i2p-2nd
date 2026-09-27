/** I2P uses a URL-safe base64 alphabet with `-` for `+` and `~` for `/`. */
export function encodeI2pBase64(value: Buffer): string {
  if (!Buffer.isBuffer(value)) throw new TypeError('value must be a Buffer');
  return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~');
}

export function decodeI2pBase64(value: string, expectedLength?: number, field = 'I2P base64'): Buffer {
  if (typeof value !== 'string') throw new TypeError(`${field} must be a string`);
  const match = /^([A-Za-z0-9~-]+)(={0,2})$/.exec(value);
  if (!match) throw new Error(`Invalid ${field}`);
  const raw = match[1]!;
  const suppliedPadding = match[2]!.length;
  const requiredPadding = (4 - raw.length % 4) % 4;
  if (requiredPadding === 3 || (suppliedPadding !== 0 && suppliedPadding !== requiredPadding)) throw new Error(`Invalid ${field} padding`);
  const normalized = raw.replace(/-/g, '+').replace(/~/g, '/') + '='.repeat(requiredPadding);
  const result = Buffer.from(normalized, 'base64');
  if (expectedLength !== undefined && result.length !== expectedLength) throw new Error(`${field} must decode to ${expectedLength} bytes`);
  return result;
}

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** I2P .b32.i2p names are the lowercase base32 of a SHA-256 destination hash, truncated to 52 characters. */
export function encodeI2pBase32(value: Buffer): string {
  if (!Buffer.isBuffer(value) || value.length === 0) throw new Error('base32 input must be a non-empty Buffer');
  let bits = 0;
  let acc = 0;
  let output = '';
  for (const byte of value) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(acc << (5 - bits)) & 31];
  return output;
}

export function decodeI2pBase32(value: string): Buffer {
  if (typeof value !== 'string' || !/^[a-z2-7]+$/.test(value)) throw new Error('Invalid I2P base32');
  const bytes: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const char of value) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid I2P base32 character');
    acc = (acc << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

export function b32AddressFromHash(identityHash: Buffer): string {
  if (!Buffer.isBuffer(identityHash) || identityHash.length !== 32) throw new Error('Destination hash must be 32 bytes');
  return `${encodeI2pBase32(identityHash).slice(0, 52)}.b32.i2p`;
}

export function parseB32Hostname(hostname: string): Buffer | undefined {
  const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
  const match = /^([a-z2-7]{52})\.b32\.i2p$/.exec(normalized);
  if (!match) return undefined;
  const decoded = decodeI2pBase32(match[1]!);
  if (decoded.length < 32) throw new Error('Invalid .b32.i2p hash');
  return decoded.subarray(0, 32);
}

export function compareXorDistance(a: Buffer, b: Buffer, target: Buffer): number {
  for (let index = 0; index < 32; index++) {
    const left = a[index]! ^ target[index]!;
    const right = b[index]! ^ target[index]!;
    if (left !== right) return left - right;
  }
  return 0;
}
