import test from 'node:test';
import assert from 'node:assert/strict';
import { createRouterIdentity } from '../src/router/identity.ts';
import { unwrapEciesRouterGarlicMessage, wrapEciesRouterGarlicMessage } from '../src/router/tunnel/garlic.ts';

test('Noise N router Garlic wraps a LOCAL clove with DateTime replay protection', () => {
  const bob = createRouterIdentity();
  const inner = { type: 25, id: 0x55aa00ff, expiration: Date.now() + 60_000, payload: Buffer.from('short-build') };
  const garlic = wrapEciesRouterGarlicMessage(inner, bob.identity.subarray(0, 32));
  assert.equal(garlic.type, 11);
  assert.equal(garlic.payload.readUInt32BE(0), garlic.payload.length - 4);
  const opened = unwrapEciesRouterGarlicMessage(garlic, bob.encryptionPrivateKey, bob.identity.subarray(0, 32));
  assert.equal(opened.cloves.length, 1);
  assert.equal(opened.cloves[0]!.delivery.type, 'local');
  assert.deepEqual(opened.cloves[0]!.message.payload, inner.payload);
  assert.equal(opened.cloves[0]!.message.type, 25);
  assert.equal(opened.cloves[0]!.message.id, inner.id);
  const corrupted = { ...garlic, payload: Buffer.from(garlic.payload) };
  corrupted.payload[20] = corrupted.payload[20]! ^ 1;
  assert.throws(() => unwrapEciesRouterGarlicMessage(corrupted, bob.encryptionPrivateKey, bob.identity.subarray(0, 32)));
});
