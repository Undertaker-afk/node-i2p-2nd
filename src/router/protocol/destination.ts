import { createHash, generateKeyPairSync, randomFillSync, sign, verify, type KeyObject } from 'node:crypto';
import { publicEd25519, rawPublicKey } from '../crypto/x25519.ts';
import { decodeI2pBase64, encodeI2pBase64 } from '../util/encoding.ts';

const KEY_CERTIFICATE = 5;
const EDDSA_SHA512_ED25519 = 7;
const DEST_CRYPTO_UNUSED = 0;

export type DestinationKeys = {
  destination: Buffer;
  destinationHash: Buffer;
  signingPrivateKey: KeyObject;
  encryptionPrivateKey: KeyObject;
  encryptionPublicKey: Buffer;
};

/** Creates an Ed25519 destination with a separate X25519 ECIES key published in LeaseSet2. */
export function createDestinationKeys(): DestinationKeys {
  const signing = generateKeyPairSync('ed25519');
  const encryption = generateKeyPairSync('x25519');
  const destination = Buffer.alloc(391);
  randomFillSync(destination.subarray(0, 256));
  const padding = randomFillSync(Buffer.alloc(32));
  for (let offset = 256; offset < 352; offset += padding.length) padding.copy(destination, offset);
  rawPublicKey(signing.publicKey).copy(destination, 352);
  destination[384] = KEY_CERTIFICATE;
  destination.writeUInt16BE(4, 385);
  destination.writeUInt16BE(EDDSA_SHA512_ED25519, 387);
  destination.writeUInt16BE(DEST_CRYPTO_UNUSED, 389);
  return {
    destination,
    destinationHash: createHash('sha256').update(destination).digest(),
    signingPrivateKey: signing.privateKey,
    encryptionPrivateKey: encryption.privateKey,
    encryptionPublicKey: rawPublicKey(encryption.publicKey),
  };
}

export function parseDestination(bytes: Buffer): { destination: Buffer; destinationHash: Buffer; signingPublicKey: Buffer; signatureType: number } {
  if (!Buffer.isBuffer(bytes) || bytes.length < 387) throw new Error('Destination is truncated');
  const certificateType = bytes[384]!;
  const certificateLength = bytes.readUInt16BE(385);
  if (bytes.length !== 387 + certificateLength) throw new Error('Destination length does not match its certificate');
  let signatureType = 0;
  if (certificateType === KEY_CERTIFICATE) {
    if (certificateLength < 4) throw new Error('Destination key certificate is truncated');
    signatureType = bytes.readUInt16BE(387);
  } else if (certificateType !== 0) throw new Error(`Unsupported Destination certificate type ${certificateType}`);
  if (signatureType !== 0 && signatureType !== EDDSA_SHA512_ED25519) throw new Error(`Unsupported Destination signature type ${signatureType}`);
  const signingPublicKey = signatureType === EDDSA_SHA512_ED25519 ? Buffer.from(bytes.subarray(352, 384)) : Buffer.from(bytes.subarray(256, 384));
  return {
    destination: Buffer.from(bytes),
    destinationHash: createHash('sha256').update(bytes).digest(),
    signingPublicKey,
    signatureType,
  };
}

export function signDestinationBytes(keys: DestinationKeys, data: Buffer): Buffer {
  return sign(null, data, keys.signingPrivateKey);
}

export function verifyDestinationSignature(destination: Buffer, data: Buffer, signature: Buffer): boolean {
  const parsed = parseDestination(destination);
  if (parsed.signatureType !== EDDSA_SHA512_ED25519) throw new Error('Destination signature verification requires Ed25519');
  if (!Buffer.isBuffer(signature) || signature.length !== 64) throw new Error('Ed25519 signature must be 64 bytes');
  return verify(null, data, publicEd25519(parsed.signingPublicKey), signature);
}

export function encodeDestinationBase64(destination: Buffer): string {
  parseDestination(destination);
  return encodeI2pBase64(destination);
}

export function decodeDestinationBase64(value: string): Buffer {
  const bytes = decodeI2pBase64(value, undefined, 'destination');
  parseDestination(bytes);
  return bytes;
}
