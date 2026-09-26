import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject,
} from 'node:crypto';

export const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
export const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
export const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function sha256(...parts: Buffer[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function rawPublicKey(key: KeyObject): Buffer {
  const encoded = key.export({ format: 'der', type: 'spki' });
  if (!Buffer.isBuffer(encoded) || encoded.length < 32) throw new Error('Unexpected public key encoding');
  return Buffer.from(encoded.subarray(encoded.length - 32));
}

export function publicX25519(raw: Buffer): KeyObject {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function privateX25519(raw: Buffer): KeyObject {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new Error('X25519 private key must be 32 bytes');
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

export function publicEd25519(raw: Buffer): KeyObject {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function generateX25519KeyPair(): { privateKey: KeyObject; publicKey: Buffer } {
  const pair = generateKeyPairSync('x25519');
  return { privateKey: pair.privateKey, publicKey: rawPublicKey(pair.publicKey) };
}

export function x25519SharedSecret(privateKey: KeyObject, publicKey: Buffer): Buffer {
  const shared = diffieHellman({ privateKey, publicKey: publicX25519(publicKey) });
  if (shared.length !== 32 || shared.every(byte => byte === 0)) throw new Error('Invalid low-order X25519 public key');
  return shared;
}

export function hkdf(ck: Buffer, input: Buffer, info = '', length = 64): Buffer {
  return Buffer.from(hkdfSync('sha256', input, ck, Buffer.from(info, 'ascii'), length));
}

export function mixKey(ck: Buffer, input: Buffer): { ck: Buffer; key: Buffer } {
  const output = hkdf(ck, input, '', 64);
  return { ck: output.subarray(0, 32), key: output.subarray(32, 64) };
}

export function deriveKey(ck: Buffer, label: string): { ck: Buffer; key: Buffer } {
  const output = hkdf(ck, Buffer.alloc(0), label, 64);
  return { ck: output.subarray(0, 32), key: output.subarray(32, 64) };
}

export function noiseNonce(counter: number, recordIndex?: number): Buffer {
  const nonce = Buffer.alloc(12);
  if (recordIndex !== undefined) nonce[4] = recordIndex;
  else nonce.writeBigUInt64LE(BigInt(counter), 4);
  return nonce;
}

export function encryptAead(key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

export function decryptAead(key: Buffer, nonce: Buffer, aad: Buffer, ciphertextAndTag: Buffer): Buffer {
  if (ciphertextAndTag.length < 16) throw new Error('AEAD payload is truncated');
  const ciphertext = ciphertextAndTag.subarray(0, -16);
  const tag = ciphertextAndTag.subarray(-16);
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function chacha20Xor(key: Buffer, nonce12: Buffer, data: Buffer): Buffer {
  const chachaIv = Buffer.alloc(16);
  chachaIv.writeUInt32LE(1, 0);
  nonce12.copy(chachaIv, 4);
  const cipher = createCipheriv('chacha20', key, chachaIv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
