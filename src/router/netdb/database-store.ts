import { gunzipSync, gzipSync } from 'node:zlib';
import { ByteReader } from '../protocol/common.ts';
import { parseRouterInfo, type RouterInfo } from '../protocol/router-info.ts';
import { parseLeaseSet2, verifyLeaseSet2, type LeaseSet2 } from '../protocol/leaseset.ts';
import { parseEncryptedLeaseSet, verifyEncryptedLeaseSet, type EncryptedLeaseSet } from '../protocol/encrypted-leaseset.ts';

export type DatabaseStoreRouterInfo = {
  key: Buffer;
  replyToken: number;
  replyTunnelId?: number;
  replyGateway?: Buffer;
  routerInfo: RouterInfo;
};
const MAX_COMPRESSED_ROUTER_INFO = 0xffff;
const MAX_ROUTER_INFO = 1024 * 1024;

/** Encodes a RouterInfo DatabaseStore record without reply routing metadata. */
export function encodeDatabaseStoreRouterInfo(routerInfoBytes: Buffer): Buffer {
  if (!Buffer.isBuffer(routerInfoBytes) || routerInfoBytes.length === 0 || routerInfoBytes.length > MAX_ROUTER_INFO) throw new RangeError('RouterInfo size is invalid');
  const info = parseRouterInfo(routerInfoBytes);
  const compressed = gzipSync(routerInfoBytes);
  if (compressed.length > MAX_COMPRESSED_ROUTER_INFO) throw new RangeError('Compressed RouterInfo exceeds 65535 bytes');
  const length = Buffer.allocUnsafe(2); length.writeUInt16BE(compressed.length);
  const payload = Buffer.concat([info.identityHash, Buffer.from([0]), Buffer.alloc(4), length, compressed]);
  if (payload.length > 0xffff) throw new RangeError('DatabaseStore payload exceeds I2NP size limit');
  return payload;
}

/** Parses the RouterInfo form of an I2NP DatabaseStore payload. */
export function parseDatabaseStoreRouterInfo(payload: Buffer): DatabaseStoreRouterInfo {
  const reader = new ByteReader(payload, MAX_COMPRESSED_ROUTER_INFO + 128);
  const key = Buffer.from(reader.readHash());
  const type = reader.readUInt8();
  if ((type & 1) !== 0 || (type & 0x0e) !== 0) throw new Error(`Unsupported DatabaseStore record type ${type}`);
  const replyToken = reader.readUInt32();
  let replyTunnelId: number | undefined;
  let replyGateway: Buffer | undefined;
  if (replyToken !== 0) {
    replyTunnelId = reader.readUInt32(); replyGateway = Buffer.from(reader.readHash());
  }
  const compressedLength = reader.readUInt16();
  if (compressedLength === 0 || compressedLength > MAX_COMPRESSED_ROUTER_INFO) throw new Error('Invalid compressed RouterInfo length');
  const compressed = reader.readBytes(compressedLength); reader.assertEnd();
  let decoded: Buffer;
  try { decoded = gunzipSync(compressed, { maxOutputLength: MAX_ROUTER_INFO }); }
  catch (error) { throw new Error(`Invalid or oversized compressed RouterInfo: ${error instanceof Error ? error.message : String(error)}`); }
  const routerInfo = parseRouterInfo(decoded);
  if (!routerInfo.identityHash.equals(key)) throw new Error('DatabaseStore key does not match RouterInfo identity hash');
  return { key, replyToken, ...(replyTunnelId === undefined ? {} : { replyTunnelId }), ...(replyGateway === undefined ? {} : { replyGateway }), routerInfo };
}

export type DatabaseStoreLeaseSet2 = {
  key: Buffer;
  replyToken: number;
  replyTunnelId?: number;
  replyGateway?: Buffer;
  leaseSet: LeaseSet2;
};

const DATABASE_STORE_LS2 = 3;
const DATABASE_STORE_ENCRYPTED_LS = 5;

export type DatabaseStoreEncryptedLeaseSet = {
  key: Buffer;
  replyToken: number;
  replyTunnelId?: number;
  replyGateway?: Buffer;
  leaseSet: EncryptedLeaseSet;
};

/** Encodes an EncryptedLeaseSet DatabaseStore (type 5). */
export function encodeDatabaseStoreEncryptedLeaseSet(encoded: Buffer, options: { replyToken?: number; replyTunnelId?: number; replyGateway?: Buffer } = {}): Buffer {
  const record = parseEncryptedLeaseSet(encoded);
  if (!verifyEncryptedLeaseSet(record)) throw new Error('EncryptedLeaseSet signature is invalid');
  const replyToken = options.replyToken ?? 0;
  const header = Buffer.concat([record.destinationHash, Buffer.from([DATABASE_STORE_ENCRYPTED_LS])]);
  const token = Buffer.allocUnsafe(4); token.writeUInt32BE(replyToken >>> 0);
  let routing = Buffer.alloc(0);
  if (replyToken !== 0) {
    if (!options.replyGateway || !Buffer.isBuffer(options.replyGateway) || options.replyGateway.length !== 32) throw new Error('DatabaseStore reply gateway is required when a reply token is set');
    const tunnel = Buffer.allocUnsafe(4); tunnel.writeUInt32BE(options.replyTunnelId ?? 0);
    routing = Buffer.concat([tunnel, options.replyGateway]);
  }
  const payload = Buffer.concat([header, token, routing, encoded]);
  if (payload.length > 0xffff) throw new RangeError('DatabaseStore payload exceeds I2NP size limit');
  return payload;
}

export function parseDatabaseStoreEncryptedLeaseSet(payload: Buffer): DatabaseStoreEncryptedLeaseSet {
  const reader = new ByteReader(payload, 1_048_576);
  const key = Buffer.from(reader.readHash());
  const type = reader.readUInt8();
  if (type !== DATABASE_STORE_ENCRYPTED_LS) throw new Error(`Unsupported DatabaseStore record type ${type}`);
  const replyToken = reader.readUInt32();
  let replyTunnelId: number | undefined;
  let replyGateway: Buffer | undefined;
  if (replyToken !== 0) {
    replyTunnelId = reader.readUInt32(); replyGateway = Buffer.from(reader.readHash());
  }
  const leaseSet = parseEncryptedLeaseSet(Buffer.from(reader.readBytes(reader.remaining)));
  if (!verifyEncryptedLeaseSet(leaseSet)) throw new Error('EncryptedLeaseSet signature is invalid');
  if (!leaseSet.destinationHash.equals(key)) throw new Error('DatabaseStore key does not match EncryptedLeaseSet destination hash');
  return { key, replyToken, ...(replyTunnelId === undefined ? {} : { replyTunnelId }), ...(replyGateway === undefined ? {} : { replyGateway }), leaseSet };
}

/** Encodes an uncompressed LeaseSet2 DatabaseStore (type 3). */
export function encodeDatabaseStoreLeaseSet2(leaseSetBytes: Buffer, options: { replyToken?: number; replyTunnelId?: number; replyGateway?: Buffer } = {}): Buffer {
  const ls = parseLeaseSet2(leaseSetBytes);
  if (!verifyLeaseSet2(ls)) throw new Error('LeaseSet2 signature is invalid');
  const replyToken = options.replyToken ?? 0;
  const header = Buffer.concat([ls.destinationHash, Buffer.from([DATABASE_STORE_LS2])]);
  const token = Buffer.allocUnsafe(4); token.writeUInt32BE(replyToken >>> 0);
  let routing = Buffer.alloc(0);
  if (replyToken !== 0) {
    if (!options.replyGateway || !Buffer.isBuffer(options.replyGateway) || options.replyGateway.length !== 32) throw new Error('DatabaseStore reply gateway is required when a reply token is set');
    const tunnel = Buffer.allocUnsafe(4); tunnel.writeUInt32BE(options.replyTunnelId ?? 0);
    routing = Buffer.concat([tunnel, options.replyGateway]);
  }
  const payload = Buffer.concat([header, token, routing, leaseSetBytes]);
  if (payload.length > 0xffff) throw new RangeError('DatabaseStore payload exceeds I2NP size limit');
  return payload;
}

export function parseDatabaseStoreLeaseSet2(payload: Buffer): DatabaseStoreLeaseSet2 {
  const reader = new ByteReader(payload, 1_048_576);
  const key = Buffer.from(reader.readHash());
  const type = reader.readUInt8();
  if (type !== DATABASE_STORE_LS2) throw new Error(`Unsupported DatabaseStore record type ${type}`);
  const replyToken = reader.readUInt32();
  let replyTunnelId: number | undefined;
  let replyGateway: Buffer | undefined;
  if (replyToken !== 0) {
    replyTunnelId = reader.readUInt32(); replyGateway = Buffer.from(reader.readHash());
  }
  const leaseSet = parseLeaseSet2(Buffer.from(reader.readBytes(reader.remaining)));
  if (!verifyLeaseSet2(leaseSet)) throw new Error('LeaseSet2 signature is invalid');
  if (!leaseSet.destinationHash.equals(key)) throw new Error('DatabaseStore key does not match LeaseSet2 destination hash');
  return { key, replyToken, ...(replyTunnelId === undefined ? {} : { replyTunnelId }), ...(replyGateway === undefined ? {} : { replyGateway }), leaseSet };
}

export function parseDatabaseStore(payload: Buffer): { kind: 'routerInfo'; record: DatabaseStoreRouterInfo } | { kind: 'leaseSet2'; record: DatabaseStoreLeaseSet2 } | { kind: 'encryptedLeaseSet'; record: DatabaseStoreEncryptedLeaseSet } {
  if (!Buffer.isBuffer(payload) || payload.length < 33) throw new Error('DatabaseStore payload is truncated');
  const type = payload[32]!;
  if ((type & 1) === 0) return { kind: 'routerInfo', record: parseDatabaseStoreRouterInfo(payload) };
  if (type === DATABASE_STORE_LS2) return { kind: 'leaseSet2', record: parseDatabaseStoreLeaseSet2(payload) };
  if (type === DATABASE_STORE_ENCRYPTED_LS) return { kind: 'encryptedLeaseSet', record: parseDatabaseStoreEncryptedLeaseSet(payload) };
  throw new Error(`Unsupported DatabaseStore record type ${type}`);
}
