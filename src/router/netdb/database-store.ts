import { gunzipSync, gzipSync } from 'node:zlib';
import { ByteReader } from '../protocol/common.ts';
import { parseRouterInfo, type RouterInfo } from '../protocol/router-info.ts';

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
