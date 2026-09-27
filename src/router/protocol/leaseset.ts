import { ByteReader, encodeString } from './common.ts';
import { parseDestination, signDestinationBytes, verifyDestinationSignature, type DestinationKeys } from './destination.ts';

export const LS2_CRYPTO_X25519 = 4;
const MAX_LEASES = 16;

export type Lease2 = { gatewayHash: Buffer; tunnelId: number; expiresAtSeconds: number };
export type LeaseSet2 = {
  destination: Buffer;
  destinationHash: Buffer;
  publishedSeconds: number;
  expiresOffsetSeconds: number;
  flags: number;
  options: Map<string, string>;
  encryptionKeys: { type: number; key: Buffer }[];
  leases: Lease2[];
  signature: Buffer;
  signedData: Buffer;
};

function encodeMapping(entries: Map<string, string>): Buffer {
  const keys = [...entries.keys()].sort();
  const chunks: Buffer[] = [];
  for (const key of keys) {
    const value = entries.get(key)!;
    chunks.push(encodeString(key), Buffer.from('='), encodeString(value), Buffer.from(';'));
  }
  const body = Buffer.concat(chunks);
  if (body.length > 0xffff) throw new RangeError('Mapping exceeds 65535 bytes');
  const length = Buffer.allocUnsafe(2); length.writeUInt16BE(body.length);
  return Buffer.concat([length, body]);
}

function readMapping(reader: ByteReader): Map<string, string> {
  const byteLength = reader.readUInt16();
  const mappingReader = new ByteReader(reader.readBytes(byteLength), 65_535);
  const result = new Map<string, string>();
  while (mappingReader.remaining) {
    const key = mappingReader.readString();
    if (mappingReader.readUInt8() !== 0x3d) throw new Error('Mapping entry is missing equals delimiter');
    const value = mappingReader.readString();
    if (mappingReader.readUInt8() !== 0x3b) throw new Error('Mapping entry is missing semicolon delimiter');
    if (result.has(key)) throw new Error(`Duplicate mapping key: ${key}`);
    result.set(key, value);
  }
  return result;
}

export function encodeLease2(lease: Lease2): Buffer {
  if (!Buffer.isBuffer(lease.gatewayHash) || lease.gatewayHash.length !== 32) throw new Error('Lease gateway hash must be 32 bytes');
  if (!Number.isSafeInteger(lease.tunnelId) || lease.tunnelId < 1 || lease.tunnelId > 0xffff_ffff) throw new RangeError('Lease tunnel ID must be a nonzero uint32');
  if (!Number.isInteger(lease.expiresAtSeconds) || lease.expiresAtSeconds < 0 || lease.expiresAtSeconds > 0xffff_ffff) throw new RangeError('Lease expiration is out of range');
  const bytes = Buffer.allocUnsafe(40);
  lease.gatewayHash.copy(bytes, 0);
  bytes.writeUInt32BE(lease.tunnelId, 32);
  bytes.writeUInt32BE(lease.expiresAtSeconds, 36);
  return bytes;
}

export function parseLease2(bytes: Buffer): Lease2 {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 40) throw new Error('Lease2 must be 40 bytes');
  const tunnelId = bytes.readUInt32BE(32);
  if (tunnelId === 0) throw new Error('Lease tunnel ID must be nonzero');
  return { gatewayHash: Buffer.from(bytes.subarray(0, 32)), tunnelId, expiresAtSeconds: bytes.readUInt32BE(36) };
}

/** Builds a signed LeaseSet2 advertising one X25519 ECIES key and the given inbound leases. */
export function createLeaseSet2(keys: DestinationKeys, leases: readonly Lease2[], options: {
  publishedSeconds?: number;
  expiresOffsetSeconds?: number;
  flags?: number;
  mapping?: Map<string, string>;
} = {}): Buffer {
  if (!Array.isArray(leases) || leases.length < 1 || leases.length > MAX_LEASES) throw new RangeError('LeaseSet2 must contain 1..16 leases');
  const publishedSeconds = options.publishedSeconds ?? Math.floor(Date.now() / 1000);
  const expiresOffsetSeconds = options.expiresOffsetSeconds ?? 600;
  const flags = options.flags ?? 0;
  if (!Number.isInteger(publishedSeconds) || publishedSeconds < 0 || publishedSeconds > 0xffff_ffff) throw new RangeError('publishedSeconds is out of range');
  if (!Number.isInteger(expiresOffsetSeconds) || expiresOffsetSeconds < 1 || expiresOffsetSeconds > 0xffff) throw new RangeError('expiresOffsetSeconds is out of range');
  if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff || (flags & 1) !== 0) throw new RangeError('Unsupported LeaseSet2 flags');
  const header = Buffer.allocUnsafe(keys.destination.length + 8);
  keys.destination.copy(header, 0);
  header.writeUInt32BE(publishedSeconds, keys.destination.length);
  header.writeUInt16BE(expiresOffsetSeconds, keys.destination.length + 4);
  header.writeUInt16BE(flags, keys.destination.length + 6);
  const keyBlock = Buffer.allocUnsafe(1 + 4 + 32);
  keyBlock[0] = 1;
  keyBlock.writeUInt16BE(LS2_CRYPTO_X25519, 1);
  keyBlock.writeUInt16BE(32, 3);
  keys.encryptionPublicKey.copy(keyBlock, 5);
  const leaseBytes = Buffer.concat([Buffer.from([leases.length]), ...leases.map(encodeLease2)]);
  const signedData = Buffer.concat([header, encodeMapping(options.mapping ?? new Map()), keyBlock, leaseBytes]);
  const signature = signDestinationBytes(keys, signedData);
  return Buffer.concat([signedData, signature]);
}

export function parseLeaseSet2(encoded: Buffer): LeaseSet2 {
  if (!Buffer.isBuffer(encoded) || encoded.length < 391 + 8 + 2 + 1 + 4 + 32 + 1 + 40 + 64) throw new Error('LeaseSet2 is truncated');
  const destLengthPrefix = 387;
  const certificateLength = encoded.readUInt16BE(385);
  const destinationLength = destLengthPrefix + certificateLength;
  if (encoded.length < destinationLength + 8 + 64) throw new Error('LeaseSet2 destination is truncated');
  const destination = encoded.subarray(0, destinationLength);
  const parsedDest = parseDestination(destination);
  const reader = new ByteReader(encoded.subarray(destinationLength), encoded.length);
  const publishedSeconds = reader.readUInt32();
  const expiresOffsetSeconds = reader.readUInt16();
  const flags = reader.readUInt16();
  if (flags & 1) throw new Error('Offline-signed LeaseSet2 is not supported');
  const options = readMapping(reader);
  const keyCount = reader.readUInt8();
  if (keyCount < 1 || keyCount > 8) throw new Error(`Invalid LeaseSet2 encryption key count ${keyCount}`);
  const encryptionKeys: { type: number; key: Buffer }[] = [];
  for (let index = 0; index < keyCount; index++) {
    const type = reader.readUInt16();
    const length = reader.readUInt16();
    if (length < 1 || length > 256) throw new Error('LeaseSet2 encryption key length is invalid');
    encryptionKeys.push({ type, key: Buffer.from(reader.readBytes(length)) });
  }
  const leaseCount = reader.readUInt8();
  if (leaseCount < 1 || leaseCount > MAX_LEASES) throw new Error(`Invalid LeaseSet2 lease count ${leaseCount}`);
  const leases: Lease2[] = [];
  for (let index = 0; index < leaseCount; index++) leases.push(parseLease2(Buffer.from(reader.readBytes(40))));
  if (reader.remaining !== 64) throw new Error('LeaseSet2 signature size mismatch');
  const signature = Buffer.from(reader.readBytes(64));
  const signedData = Buffer.from(encoded.subarray(0, encoded.length - 64));
  return {
    destination: Buffer.from(destination), destinationHash: parsedDest.destinationHash,
    publishedSeconds, expiresOffsetSeconds, flags, options, encryptionKeys, leases, signature, signedData,
  };
}

export function verifyLeaseSet2(ls: LeaseSet2): boolean {
  return verifyDestinationSignature(ls.destination, ls.signedData, ls.signature);
}

export function selectX25519Key(ls: LeaseSet2): Buffer {
  const key = ls.encryptionKeys.find(entry => entry.type === LS2_CRYPTO_X25519 && entry.key.length === 32);
  if (!key) throw new Error('LeaseSet2 does not advertise an X25519 ECIES key');
  return Buffer.from(key.key);
}
