import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { createSessionRequest, processSessionCreated } from '../src/router/transport/ntcp2/handshake.ts';

const protocol = Buffer.from('Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256', 'ascii');
const xPrefix = Buffer.from('302a300506032b656e032100', 'hex');
function rawPublic(key: KeyObject): Buffer { return Buffer.from(key.export({ format: 'der', type: 'spki' }).subarray(-32)); }
function hash(data: Buffer): Buffer { return createHash('sha256').update(data).digest(); }
function mac(key: Buffer, data: Buffer): Buffer { return createHmac('sha256', key).update(data).digest(); }

test('NTCP2 SessionRequest decrypts and authenticates with Noise XK message-one KDF', () => {
  const bob = generateKeyPairSync('x25519'); const bobPublic = rawPublic(bob.publicKey);
  const routerHash = Buffer.alloc(32, 0x21); const iv = Buffer.alloc(16, 0x42); const padding = Buffer.alloc(12, 0x73);
  const result = createSessionRequest({ networkId: 2, publishedRouterHash: routerHash, publishedIv: iv, publishedStaticKey: bobPublic, timestampSeconds: 1_800_000_000, message3Part2Length: 512, padding });
  assert.equal(result.message.length, 64 + padding.length);

  const aes = createDecipheriv('aes-256-cbc', routerHash, iv); aes.setAutoPadding(false);
  const aliceEphemeral = Buffer.concat([aes.update(result.message.subarray(0, 32)), aes.final()]);
  assert.deepEqual(aliceEphemeral, result.ephemeralPublicKey);

  let h = hash(protocol); let ck: ReturnType<typeof mac> = Buffer.from(h);
  h = hash(h); h = hash(Buffer.concat([h, bobPublic])); h = hash(Buffer.concat([h, aliceEphemeral]));
  const dh = diffieHellman({ privateKey: bob.privateKey, publicKey: createPublicKeyFromRaw(aliceEphemeral) });
  const temp = mac(ck, dh); ck = mac(temp, Buffer.from([1])); const key = mac(temp, Buffer.concat([ck, Buffer.from([2])]));
  assert.deepEqual(ck, result.chainingKey);
  const ciphertext = result.message.subarray(32, 64);
  const decipher = createDecipheriv('chacha20-poly1305', key, Buffer.alloc(12), { authTagLength: 16 });
  decipher.setAAD(h, { plaintextLength: 16 }); decipher.setAuthTag(ciphertext.subarray(-16));
  const options = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  assert.equal(options.readUInt8(0), 2);
  assert.equal(options.readUInt8(1), 2);
  assert.equal(options.readUInt16BE(2), padding.length);
  assert.equal(options.readUInt16BE(4), 512);
  assert.equal(options.readUInt32BE(8), 1_800_000_000);
  assert.deepEqual(result.message.subarray(64), padding);
});

function createPublicKeyFromRaw(raw: Buffer) {
  return createPublicKey({ key: Buffer.concat([xPrefix, raw]), format: 'der', type: 'spki' });
}

test('NTCP2 SessionRequest validates router keys, IVs, network ID, and padding bounds', () => {
  const key = Buffer.alloc(32, 1); const base = { networkId: 2, publishedRouterHash: key, publishedIv: Buffer.alloc(16), publishedStaticKey: rawPublic(generateKeyPairSync('x25519').publicKey), message3Part2Length: 128 };
  assert.throws(() => createSessionRequest({ ...base, networkId: 0 }), /networkId/);
  assert.throws(() => createSessionRequest({ ...base, publishedIv: Buffer.alloc(15) }), /IV/);
  assert.throws(() => createSessionRequest({ ...base, publishedStaticKey: Buffer.alloc(31) }), /32 bytes/);
  assert.throws(() => createSessionRequest({ ...base, message3Part2Length: 10 }), /message3Part2Length/);
  assert.throws(() => createSessionRequest({ ...base, padding: Buffer.alloc(881) }), /padding/);
});
