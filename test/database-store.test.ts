import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { createRouterIdentity } from '../src/router/identity.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { encodeDatabaseStoreRouterInfo, parseDatabaseStoreRouterInfo } from '../src/router/netdb/database-store.ts';
import { createRouterInfoRecord } from '../src/router/protocol/router-info.ts';

function databaseStorePayload(routerInfo: Buffer, replyToken = 0): Buffer {
  const parsedKey = routerInfoIdentityHash(routerInfo);
  const compressed = gzipSync(routerInfo);
  const header = Buffer.alloc(37 + (replyToken ? 36 : 0));
  parsedKey.copy(header, 0); header[32] = 0; header.writeUInt32BE(replyToken, 33);
  if (replyToken) { header.writeUInt32BE(17, 37); Buffer.alloc(32, 0x44).copy(header, 41); }
  const length = Buffer.alloc(2); length.writeUInt16BE(compressed.length);
  return Buffer.concat([header, length, compressed]);
}
function routerInfoIdentityHash(encoded: Buffer): Buffer {
  // RouterIdentity is the first 391 bytes for the modern profile used in these tests.
  return createHash('sha256').update(encoded.subarray(0, 391)).digest();
}
function makeInfo() {
  const keys = createRouterIdentity();
  const info = createRouterInfoRecord(keys, Date.now(), [], new Map([['netId', '2']]));
  return { keys, info };
}

test('parses gzip RouterInfo DatabaseStore and optional reply routing metadata', () => {
  const { keys, info } = makeInfo();
  const record = parseDatabaseStoreRouterInfo(databaseStorePayload(info, 1234));
  assert.deepEqual(record.key, keys.identityHash);
  assert.equal(record.replyToken, 1234);
  assert.equal(record.replyTunnelId, 17);
  assert.deepEqual(record.replyGateway, Buffer.alloc(32, 0x44));
  assert.equal(record.routerInfo.published > 0, true);
});

test('encodes a direct RouterInfo DatabaseStore payload without reply routing', () => {
  const { keys, info } = makeInfo();
  const payload = encodeDatabaseStoreRouterInfo(info);
  const record = parseDatabaseStoreRouterInfo(payload);
  assert.deepEqual(record.key, keys.identityHash);
  assert.equal(record.replyToken, 0);
  assert.equal(record.replyTunnelId, undefined);
  assert.deepEqual(record.routerInfo.identity, keys.identity);
});

test('integrates verified DatabaseStore records into bounded netDb cache', () => {
  const { keys, info } = makeInfo();
  const store = new VerifiedRouterInfoStore();
  assert.equal(store.storeDatabaseStore(databaseStorePayload(info)), true);
  assert.deepEqual(store.get(keys.identityHash)?.identity, keys.identity);
});

test('rejects malformed or mismatched DatabaseStore records', () => {
  const { info } = makeInfo(); const payload = databaseStorePayload(info);
  assert.throws(() => parseDatabaseStoreRouterInfo(payload.subarray(0, 30)), /Truncated/);
  const corrupt = Buffer.from(payload); corrupt[0] = corrupt[0]! ^ 1;
  assert.throws(() => parseDatabaseStoreRouterInfo(corrupt), /key does not match/);
  const badType = Buffer.from(payload); badType[32] = 1;
  assert.throws(() => parseDatabaseStoreRouterInfo(badType), /Unsupported DatabaseStore record type/);
  const badGzip = Buffer.from(payload); badGzip[badGzip.length - 1] = badGzip[badGzip.length - 1]! ^ 0xff;
  assert.throws(() => parseDatabaseStoreRouterInfo(badGzip), /Invalid or oversized compressed/);
});
