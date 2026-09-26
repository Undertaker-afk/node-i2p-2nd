import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHash, generateKeyPairSync, privateEncrypt, type KeyObject } from 'node:crypto';
import { createRouterIdentity } from '../src/router/identity.ts';
import { createRouterInfoRecord } from '../src/router/protocol/router-info.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { importSu3Reseed, loadReseedSigners } from '../src/router/netdb/reseed.ts';

function crc32(bytes: Buffer): number {
  let value = 0xffff_ffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  }
  return (value ^ 0xffff_ffff) >>> 0;
}
function zipEntry(name: string, data: Buffer): Buffer {
  const filename = Buffer.from(name); const checksum = crc32(data);
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8);
  local.writeUInt32LE(checksum, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(filename.length, 26);
  const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0, 8); central.writeUInt16LE(0, 10);
  central.writeUInt32LE(checksum, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(filename.length, 28);
  const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + filename.length, 12); eocd.writeUInt32LE(30 + filename.length + data.length, 16);
  return Buffer.concat([local, filename, data, central, filename, eocd]);
}
function makeSu3(signer: string, privateKey: KeyObject, routerInfo: Buffer): Buffer {
  const zip = zipEntry('routerInfo-test.dat', routerInfo); const version = Buffer.from('1'); const signerBytes = Buffer.from(signer);
  const header = Buffer.alloc(40); Buffer.from('I2Psu3\0', 'ascii').copy(header, 0); header[7] = 0; header.writeUInt16BE(6, 8); header.writeUInt16BE(512, 10);
  header[13] = version.length; header[15] = signerBytes.length; header.writeBigUInt64BE(BigInt(zip.length), 16); header[25] = 0; header[27] = 3;
  const signed = Buffer.concat([header, version, signerBytes, zip]); const digest = createHash('sha512').update(signed).digest();
  const encodedDigest = Buffer.alloc(512); digest.copy(encodedDigest, 512 - digest.length);
  const signature = privateEncrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, encodedDigest);
  return Buffer.concat([signed, signature]);
}

test('loads pinned reseed signer certificates', async () => {
  const signers = await loadReseedSigners();
  assert.ok(signers.size >= 10);
  assert.ok(signers.has('reseed@diva.exchange'));
});

test('verifies signed SU3 ZIP and imports only verified RouterInfos atomically', () => {
  const pair = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 });
  const signer = 'test-reseed@example.net'; const identity = createRouterIdentity();
  const info = createRouterInfoRecord(identity, Date.now(), [], new Map([['netId', '2']]));
  const bundle = makeSu3(signer, pair.privateKey, info); const store = new VerifiedRouterInfoStore();
  const result = importSu3Reseed(bundle, new Map([[signer, pair.publicKey]]), store, { minRouterInfos: 1 });
  assert.equal(result.signer, signer); assert.equal(result.imported, 1); assert.equal(store.size, 1);
  assert.deepEqual(store.get(identity.identityHash)?.identity, identity.identity);

  const corrupt = Buffer.from(bundle); corrupt[70] = corrupt[70]! ^ 1;
  const empty = new VerifiedRouterInfoStore();
  assert.throws(() => importSu3Reseed(corrupt, new Map([[signer, pair.publicKey]]), empty), /signature verification failed/);
  assert.equal(empty.size, 0, 'invalid bundle must not mutate the store');
  assert.throws(() => importSu3Reseed(bundle, new Map(), new VerifiedRouterInfoStore()), /not trusted/);
});

test('rejects unsafe, malformed, or wrong-network reseed archives', () => {
  const pair = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 });
  const signer = 'test-reseed@example.net'; const keys = createRouterIdentity();
  const wrongNetwork = createRouterInfoRecord(keys, Date.now(), [], new Map([['netId', '3']]));
  const bundle = makeSu3(signer, pair.privateKey, wrongNetwork);
  const store = new VerifiedRouterInfoStore(100, '2');
  assert.throws(() => importSu3Reseed(bundle, new Map([[signer, pair.publicKey]]), store), /usable RouterInfos/);
  assert.equal(store.size, 0);
  const badHeader = Buffer.from(bundle); badHeader[27] = 1;
  assert.throws(() => importSu3Reseed(badHeader, new Map([[signer, pair.publicKey]]), new VerifiedRouterInfoStore()), /not a reseed ZIP/);
});
