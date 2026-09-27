import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { decodeElligator2, encodeElligator2 } from '../src/router/crypto/elligator2.ts';
import { generateX25519KeyPair } from '../src/router/crypto/x25519.ts';
import { b32AddressFromHash, decodeI2pBase64, encodeI2pBase32, encodeI2pBase64, parseB32Hostname } from '../src/router/util/encoding.ts';

test('I2P base64 uses the documented substitution alphabet and round-trips', () => {
  const value = Buffer.from([0xfb, 0xff, 0xef]);
  const encoded = encodeI2pBase64(value);
  assert.equal(encoded.includes('+'), false);
  assert.equal(encoded.includes('/'), false);
  assert.deepEqual(decodeI2pBase64(encoded), value);
  assert.throws(() => decodeI2pBase64('@@@'), /Invalid/);
});

test('b32 hostnames are 52-character hashes of 32-byte destination identifiers', () => {
  const hash = randomBytes(32);
  const hostname = b32AddressFromHash(hash);
  assert.match(hostname, /^[a-z2-7]{52}\.b32\.i2p$/);
  assert.deepEqual(parseB32Hostname(hostname), hash);
  assert.equal(parseB32Hostname('example.i2p'), undefined);
  assert.equal(encodeI2pBase32(hash).slice(0, 52), hostname.slice(0, 52));
});

test('Elligator2 encode/decode round-trips eligible X25519 public keys', () => {
  let encoded: Buffer | undefined;
  let publicKey: Buffer = Buffer.alloc(32);
  for (let attempt = 0; attempt < 32 && !encoded; attempt++) {
    publicKey = generateX25519KeyPair().publicKey;
    encoded = encodeElligator2(publicKey, { randomize: false });
  }
  assert.ok(encoded);
  assert.deepEqual(decodeElligator2(encoded), publicKey);
  const randomized = encodeElligator2(publicKey, { randomize: true });
  if (randomized) assert.deepEqual(decodeElligator2(randomized), publicKey);
});
