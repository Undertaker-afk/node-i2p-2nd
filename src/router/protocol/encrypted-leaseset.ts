import { createHash } from 'node:crypto';
import { ByteReader } from './common.ts';
import { parseDestination, signDestinationBytes, verifyDestinationSignature, type DestinationKeys } from './destination.ts';
import { decryptAead, encryptAead, hkdf } from '../crypto/x25519.ts';

/**
 * EncryptedLeaseSet (DatabaseStore type 5) as a locally encrypted LeaseSet2.
 * This is not proposal-123 blinded-destination crypto; the outer Destination is
 * the same as the inner LS2 Destination, and the AEAD key is derived from a
 * shared secret supplied by the publisher.
 */
export type EncryptedLeaseSet = {
  destination: Buffer;
  destinationHash: Buffer;
  publishedSeconds: number;
  expiresOffsetSeconds: number;
  flags: number;
  ciphertext: Buffer;
  signature: Buffer;
  signedData: Buffer;
};

const INFO_LABEL = Buffer.from('I2PEncryptedLeaseSet', 'ascii');

export function deriveEncryptedLeaseSetKey(secret: Buffer, destinationHash: Buffer): Buffer {
  if (!Buffer.isBuffer(secret) || secret.length < 1 || secret.length > 255) throw new RangeError('EncryptedLeaseSet secret must be 1..255 bytes');
  if (!Buffer.isBuffer(destinationHash) || destinationHash.length !== 32) throw new Error('Destination hash must be 32 bytes');
  return Buffer.from(hkdf(destinationHash, secret, INFO_LABEL.toString('ascii'), 32));
}

function nonceFor(publishedSeconds: number, destinationHash: Buffer): Buffer {
  const published = Buffer.allocUnsafe(4);
  published.writeUInt32BE(publishedSeconds >>> 0);
  return createHash('sha256').update(published).update(destinationHash).digest().subarray(0, 12);
}

export function encryptLeaseSet2(innerLeaseSetBytes: Buffer, keys: DestinationKeys, secret: Buffer, options: {
  publishedSeconds?: number;
  expiresOffsetSeconds?: number;
  flags?: number;
} = {}): Buffer {
  if (!Buffer.isBuffer(innerLeaseSetBytes) || innerLeaseSetBytes.length < 64) throw new Error('Inner LeaseSet2 is truncated');
  const publishedSeconds = options.publishedSeconds ?? Math.floor(Date.now() / 1000);
  const expiresOffsetSeconds = options.expiresOffsetSeconds ?? 600;
  const flags = options.flags ?? 0;
  if (!Number.isInteger(publishedSeconds) || publishedSeconds < 0 || publishedSeconds > 0xffff_ffff) throw new RangeError('publishedSeconds is out of range');
  if (!Number.isInteger(expiresOffsetSeconds) || expiresOffsetSeconds < 1 || expiresOffsetSeconds > 0xffff) throw new RangeError('expiresOffsetSeconds is out of range');
  if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) throw new RangeError('flags is out of range');
  const key = deriveEncryptedLeaseSetKey(secret, keys.destinationHash);
  const ciphertext = encryptAead(key, nonceFor(publishedSeconds, keys.destinationHash), keys.destinationHash, innerLeaseSetBytes);
  const header = Buffer.allocUnsafe(keys.destination.length + 8);
  keys.destination.copy(header, 0);
  header.writeUInt32BE(publishedSeconds, keys.destination.length);
  header.writeUInt16BE(expiresOffsetSeconds, keys.destination.length + 4);
  header.writeUInt16BE(flags, keys.destination.length + 6);
  if (ciphertext.length > 0xffff) throw new RangeError('EncryptedLeaseSet ciphertext exceeds 65535 bytes');
  const length = Buffer.allocUnsafe(2);
  length.writeUInt16BE(ciphertext.length);
  const signedData = Buffer.concat([header, length, ciphertext]);
  const signature = signDestinationBytes(keys, signedData);
  return Buffer.concat([signedData, signature]);
}

export function parseEncryptedLeaseSet(encoded: Buffer): EncryptedLeaseSet {
  if (!Buffer.isBuffer(encoded) || encoded.length < 387 + 8 + 2 + 16 + 64) throw new Error('EncryptedLeaseSet is truncated');
  const certificateLength = encoded.readUInt16BE(385);
  const destinationLength = 387 + certificateLength;
  if (encoded.length < destinationLength + 8 + 2 + 16 + 64) throw new Error('EncryptedLeaseSet destination is truncated');
  const destination = encoded.subarray(0, destinationLength);
  const parsedDest = parseDestination(destination);
  const reader = new ByteReader(encoded.subarray(destinationLength), encoded.length);
  const publishedSeconds = reader.readUInt32();
  const expiresOffsetSeconds = reader.readUInt16();
  const flags = reader.readUInt16();
  const cipherLength = reader.readUInt16();
  if (cipherLength < 16) throw new Error('EncryptedLeaseSet ciphertext is truncated');
  const ciphertext = Buffer.from(reader.readBytes(cipherLength));
  if (reader.remaining !== 64) throw new Error('EncryptedLeaseSet signature size mismatch');
  const signature = Buffer.from(reader.readBytes(64));
  const signedData = Buffer.from(encoded.subarray(0, encoded.length - 64));
  return {
    destination: Buffer.from(destination),
    destinationHash: parsedDest.destinationHash,
    publishedSeconds,
    expiresOffsetSeconds,
    flags,
    ciphertext,
    signature,
    signedData,
  };
}

export function verifyEncryptedLeaseSet(record: EncryptedLeaseSet): boolean {
  return verifyDestinationSignature(record.destination, record.signedData, record.signature);
}

export function decryptEncryptedLeaseSet(record: EncryptedLeaseSet, secret: Buffer): Buffer {
  if (!verifyEncryptedLeaseSet(record)) throw new Error('EncryptedLeaseSet signature is invalid');
  const key = deriveEncryptedLeaseSetKey(secret, record.destinationHash);
  return decryptAead(key, nonceFor(record.publishedSeconds, record.destinationHash), record.destinationHash, record.ciphertext);
}
