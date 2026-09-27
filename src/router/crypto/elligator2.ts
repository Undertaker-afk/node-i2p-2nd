import { randomBytes, type KeyObject } from 'node:crypto';
import { generateX25519KeyPair } from './x25519.ts';

const P = (1n << 255n) - 19n;
const A = 486662n;
const U = 2n;
const P_MINUS_1_OVER_2 = (P - 1n) / 2n;
const SQRT_M1 = modPow(2n, (P - 1n) / 4n);

function mod(value: bigint): bigint {
  const reduced = value % P;
  return reduced < 0n ? reduced + P : reduced;
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let value = mod(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * value);
    value = mod(value * value);
    power >>= 1n;
  }
  return result;
}

function invert(value: bigint): bigint { return modPow(value, P - 2n); }

function legendre(value: bigint): number {
  const reduced = mod(value);
  if (reduced === 0n) return 0;
  const symbol = modPow(reduced, P_MINUS_1_OVER_2);
  if (symbol === 1n) return 1;
  if (symbol === 0n) return 0;
  return -1;
}

function sqrt(value: bigint): bigint {
  const x = mod(value);
  let root = modPow(x, (P + 3n) / 8n);
  const tomega = modPow(x, (P - 1n) / 4n);
  if (mod(tomega + 1n) === 0n) root = mod(root * SQRT_M1);
  if (root > P_MINUS_1_OVER_2) root = P - root;
  return root;
}

function swapEndian(bytes: Buffer): Buffer {
  const output = Buffer.allocUnsafe(32);
  for (let index = 0; index < 32; index++) output[index] = bytes[31 - index]!;
  return output;
}

function bnToBe(value: bigint): Buffer {
  let remaining = mod(value);
  const output = Buffer.alloc(32);
  for (let index = 31; index >= 0; index--) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function beToBn(bytes: Buffer): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/**
 * Encodes a little-endian X25519 public key as an Elligator2 representative.
 * Returns undefined when the point is not in the image of the map (~50% of keys).
 */
export function encodeElligator2(publicKey: Buffer, options: { highY?: boolean; randomize?: boolean } = {}): Buffer | undefined {
  if (!Buffer.isBuffer(publicKey) || publicKey.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  const x = beToBn(swapEndian(publicKey));
  const xA = mod(-(x + A));
  if (legendre(mod(U * x * xA)) === -1) return undefined;
  const highY = options.highY ?? false;
  const representative = sqrt(highY ? mod(invert(x) * xA * invert(U)) : mod(invert(xA) * x * invert(U)));
  const encoded = bnToBe(representative);
  if (options.randomize !== false) encoded[0] = encoded[0]! | (randomBytes(1)[0]! & 0xc0);
  return swapEndian(encoded);
}

/** Recovers the little-endian X25519 public key from an Elligator2 representative. */
export function decodeElligator2(encoded: Buffer): Buffer {
  if (!Buffer.isBuffer(encoded) || encoded.length !== 32) throw new Error('Elligator2 representative must be 32 bytes');
  const bigEndian = swapEndian(encoded);
  bigEndian[0] = bigEndian[0]! & 0x3f;
  const r = beToBn(bigEndian);
  if (r > P_MINUS_1_OVER_2) throw new Error('Elligator2 representative is out of range');
  const v = mod(-A * invert(mod(1n + U * r * r)));
  const t = mod(v * v * mod(v + A) + v);
  const x = legendre(t) === 1 ? v : mod(-v - A);
  return swapEndian(bnToBe(x));
}

/** Generates an X25519 keypair whose public key can be Elligator2-encoded. */
export function encodeElligator2OrThrow(publicKey: Buffer): Buffer {
  const encoded = encodeElligator2(publicKey);
  if (!encoded) throw new Error('X25519 public key is not Elligator2-encodable');
  return encoded;
}

/** Generates an X25519 key pair whose public key is in the Elligator2 image. */
export function generateElligator2KeyPair(): { privateKey: KeyObject; publicKey: Buffer; encoded: Buffer } {
  for (let attempt = 0; attempt < 64; attempt++) {
    const pair = generateX25519KeyPair();
    const encoded = encodeElligator2(pair.publicKey);
    if (encoded) return { privateKey: pair.privateKey, publicKey: pair.publicKey, encoded };
  }
  throw new Error('Unable to generate an Elligator2-eligible X25519 key pair');
}
