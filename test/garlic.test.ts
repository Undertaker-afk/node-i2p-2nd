import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { unwrapEciesExistingSessionGarlicMessage, wrapEciesExistingSessionGarlicMessage } from '../src/router/tunnel/garlic.ts';

test('existing-session ECIES Garlic Message encodes a local clove and authenticates reply tag', () => {
  const key = randomBytes(32); const tag = randomBytes(8);
  const inner = { type: 26, id: 0x10203040, expiration: 1_900_000_000_000, payload: Buffer.from('reply data') };
  const message = wrapEciesExistingSessionGarlicMessage(inner, key, tag);
  assert.equal(message.type, 11);
  assert.equal(message.id, inner.id);
  assert.equal(message.expiration, inner.expiration);
  assert.equal(message.payload.readUInt32BE(0), message.payload.length - 4);
  assert.deepEqual(message.payload.subarray(4, 12), tag);
  const ciphertext = message.payload.subarray(12);
  const decipher = createDecipheriv('chacha20-poly1305', key, Buffer.alloc(12), { authTagLength: 16 });
  decipher.setAAD(tag, { plaintextLength: ciphertext.length - 16 });
  decipher.setAuthTag(ciphertext.subarray(-16));
  const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  assert.equal(plaintext[0], 11);
  assert.equal(plaintext.readUInt16BE(1), inner.payload.length + 10);
  assert.equal(plaintext[3], 0);
  assert.equal(plaintext[4], 26);
  assert.equal(plaintext.readUInt32BE(5), inner.id);
  assert.equal(plaintext.readUInt32BE(9), Math.floor(inner.expiration / 1000));
  assert.deepEqual(plaintext.subarray(13), inner.payload);
  assert.deepEqual(unwrapEciesExistingSessionGarlicMessage(message, key, tag), inner);
  const corrupted = { ...message, payload: Buffer.from(message.payload) };
  corrupted.payload[12] = corrupted.payload[12]! ^ 1;
  assert.throws(() => unwrapEciesExistingSessionGarlicMessage(corrupted, key, tag));
});

test('existing-session Garlic wrapping rejects invalid session material and oversized clove', () => {
  const message = { type: 26, id: 1, expiration: Date.now() + 60_000, payload: Buffer.from('x') };
  assert.throws(() => wrapEciesExistingSessionGarlicMessage(message, Buffer.alloc(31), Buffer.alloc(8)), /32 bytes/);
  assert.throws(() => wrapEciesExistingSessionGarlicMessage(message, Buffer.alloc(32), Buffer.alloc(7)), /8 bytes/);
  assert.throws(() => wrapEciesExistingSessionGarlicMessage({ ...message, payload: Buffer.alloc(65_526) }, Buffer.alloc(32), Buffer.alloc(8)), /too large/);
});
