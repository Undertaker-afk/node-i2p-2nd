import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { createSessionRequest, createSessionConfirmed, processSessionCreated } from '../src/router/transport/ntcp2/handshake.ts';
import { createRouterIdentity } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo } from '../src/router/protocol/router-info.ts';

const xPrefix = Buffer.from('302a300506032b656e032100', 'hex');
function rawPublic(key: KeyObject): Buffer { return Buffer.from(key.export({ format: 'der', type: 'spki' }).subarray(-32)); }
function publicKey(raw: Buffer) { return createPublicKey({ key: Buffer.concat([xPrefix, raw]), format: 'der', type: 'spki' }); }
function mac(key: Buffer, data: Buffer): Buffer { return createHmac('sha256', key).update(data).digest(); }
function makeBobResponse(alice: ReturnType<typeof createSessionRequest>, time: number, padding = Buffer.from([1, 2, 3])) {
  const bobEphemeral = generateKeyPairSync('x25519'); const bobPublic = rawPublic(bobEphemeral.publicKey);
  const aes = createCipheriv('aes-256-cbc', alice.publishedRouterHash, alice.aesChainingIv); aes.setAutoPadding(false);
  const encryptedY = Buffer.concat([aes.update(bobPublic), aes.final()]);
  let h = createHash('sha256').update(Buffer.concat([alice.handshakeHash, bobPublic])).digest();
  const dh = diffieHellman({ privateKey: bobEphemeral.privateKey, publicKey: publicKey(alice.ephemeralPublicKey) });
  const temp = mac(alice.chainingKey, dh); const ck = mac(temp, Buffer.from([1])); const key = mac(temp, Buffer.concat([ck, Buffer.from([2])]));
  const options = Buffer.alloc(16); options.writeUInt16BE(padding.length, 10); options.writeUInt32BE(time, 12);
  const cipher = createCipheriv('chacha20-poly1305', key, Buffer.alloc(12), { authTagLength: 16 });
  cipher.setAAD(h, { plaintextLength: options.length });
  const encryptedOptions = Buffer.concat([cipher.update(options), cipher.final(), cipher.getAuthTag()]);
  h = createHash('sha256').update(Buffer.concat([h, encryptedOptions])).digest();
  if (padding.length) h = createHash('sha256').update(Buffer.concat([h, padding])).digest();
  return { message: Buffer.concat([encryptedY, encryptedOptions, padding]), bobPublic, bobEphemeralPrivateKey: bobEphemeral.privateKey, message2Key: key, chainingKey: ck, hashAfterMessage2: h };
}
test('processes authenticated NTCP2 SessionCreated and advances Noise state', () => {
  const bobStatic = generateKeyPairSync('x25519');
  const alice = createSessionRequest({ networkId: 2, publishedRouterHash: Buffer.alloc(32, 0x19), publishedIv: Buffer.alloc(16, 0x20), publishedStaticKey: rawPublic(bobStatic.publicKey), message3Part2Length: 512, timestampSeconds: 1_800_000_000 });
  const bob = makeBobResponse(alice, 1_800_000_005);
  const updated = processSessionCreated(alice, bob.message, { nowSeconds: 1_800_000_010 });
  assert.deepEqual(updated.peerEphemeralPublicKey, bob.bobPublic);
  assert.equal(updated.sessionCreatedCiphertext?.length, 32);
  assert.deepEqual(updated.sessionCreatedPadding, Buffer.from([1, 2, 3]));
  assert.notDeepEqual(updated.chainingKey, alice.chainingKey);
  assert.throws(() => processSessionCreated(updated, bob.message), /already processed/);
});

test('builds authenticated SessionConfirmed and derives directional data keys', () => {
  const bobStatic = generateKeyPairSync('x25519');
  const localIdentity = createRouterIdentity();
  const routerInfoBytes = createRouterInfoRecord(localIdentity, Date.now(), [], new Map([['netId', '2']]));
  const part2Length = routerInfoBytes.length + 4 + 16;
  const alice = createSessionRequest({ networkId: 2, publishedRouterHash: Buffer.alloc(32, 0x51), publishedIv: Buffer.alloc(16, 0x62), publishedStaticKey: rawPublic(bobStatic.publicKey), message3Part2Length: part2Length });
  const bob = makeBobResponse(alice, Math.floor(Date.now() / 1000));
  const afterMessage2 = processSessionCreated(alice, bob.message);
  assert.deepEqual(afterMessage2.handshakeHash, bob.hashAfterMessage2);
  const confirmed = createSessionConfirmed(afterMessage2, localIdentity, routerInfoBytes);
  const wire = confirmed.sessionConfirmedCiphertext!;
  assert.equal(wire.length, 48 + part2Length);

  const decipherStatic = createDecipheriv('chacha20-poly1305', bob.message2Key, nonce(1), { authTagLength: 16 });
  decipherStatic.setAAD(bob.hashAfterMessage2, { plaintextLength: 32 }); decipherStatic.setAuthTag(wire.subarray(32, 48));
  const aliceStatic = Buffer.concat([decipherStatic.update(wire.subarray(0, 32)), decipherStatic.final()]);
  assert.deepEqual(aliceStatic, localIdentity.identity.subarray(0, 32));
  const se = diffieHellman({ privateKey: bob.bobEphemeralPrivateKey, publicKey: publicKey(aliceStatic) });
  const temp = mac(bob.chainingKey, se); const ck3 = mac(temp, Buffer.from([1])); const key3 = mac(temp, Buffer.concat([ck3, Buffer.from([2])]));
  const frame2 = wire.subarray(48); const h3 = createHash('sha256').update(Buffer.concat([bob.hashAfterMessage2, wire.subarray(0, 48)])).digest();
  const decipherInfo = createDecipheriv('chacha20-poly1305', key3, nonce(0), { authTagLength: 16 });
  decipherInfo.setAAD(h3, { plaintextLength: frame2.length - 16 }); decipherInfo.setAuthTag(frame2.subarray(-16));
  const block = Buffer.concat([decipherInfo.update(frame2.subarray(0, -16)), decipherInfo.final()]);
  assert.equal(block[0], 2); assert.equal(block.readUInt16BE(1), routerInfoBytes.length + 1); assert.equal(block[3], 0);
  assert.deepEqual(block.subarray(4), routerInfoBytes);
  assert.deepEqual(parseRouterInfo(block.subarray(4)).identity, localIdentity.identity);
  const split = mac(ck3, Buffer.alloc(0)); const expectedSend = mac(split, Buffer.from([1])); const expectedReceive = mac(split, Buffer.concat([expectedSend, Buffer.from([2])]));
  assert.deepEqual(confirmed.sendKey, expectedSend); assert.deepEqual(confirmed.receiveKey, expectedReceive);
  const askMaster = mac(split, Buffer.concat([Buffer.from('ask'), Buffer.from([1])]));
  const sipTemp = mac(askMaster, Buffer.concat([confirmed.handshakeHash, Buffer.from('siphash')]));
  const sipMaster = mac(sipTemp, Buffer.from([1])); const sipTemp2 = mac(sipMaster, Buffer.alloc(0));
  const sipAb = mac(sipTemp2, Buffer.from([1])); const sipBa = mac(sipTemp2, Buffer.concat([sipAb, Buffer.from([2])]));
  assert.deepEqual(confirmed.sendLengthKeys, { key1: sipAb.subarray(0, 8), key2: sipAb.subarray(8, 16), iv: sipAb.subarray(16, 24) });
  assert.deepEqual(confirmed.receiveLengthKeys, { key1: sipBa.subarray(0, 8), key2: sipBa.subarray(8, 16), iv: sipBa.subarray(16, 24) });
});

function nonce(value: number): Buffer { const bytes = Buffer.alloc(12); bytes.writeBigUInt64LE(BigInt(value), 4); return bytes; }

test('rejects invalid SessionCreated timestamp, padding length, and authentication tag', () => {
  const bobStatic = generateKeyPairSync('x25519');
  const alice = createSessionRequest({ networkId: 2, publishedRouterHash: Buffer.alloc(32, 0x19), publishedIv: Buffer.alloc(16, 0x20), publishedStaticKey: rawPublic(bobStatic.publicKey), message3Part2Length: 512 });
  const stale = makeBobResponse(alice, 1);
  assert.throws(() => processSessionCreated(alice, stale.message, { nowSeconds: 10_000, maxClockSkewSeconds: 2 }), /timestamp/);
  const corrupt = Buffer.from(stale.message); corrupt[40] = corrupt[40]! ^ 1;
  assert.throws(() => processSessionCreated(alice, corrupt, { nowSeconds: 1 }), /Unsupported state|authenticate|auth/i);
  assert.throws(() => processSessionCreated(alice, stale.message.subarray(0, 63)), /size/);
});
