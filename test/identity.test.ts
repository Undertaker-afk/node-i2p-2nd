import test from 'node:test';
import assert from 'node:assert/strict';
import { createRouterIdentity } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo, verifyRouterInfoSignature } from '../src/router/protocol/router-info.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';

test('creates X25519/Ed25519 identity and publishes a signed, verifiable RouterInfo', () => {
  const keys = createRouterIdentity();
  assert.equal(keys.identity.length, 391);
  assert.equal(keys.identity[384], 5);
  assert.equal(keys.identity.readUInt16BE(387), 7);
  assert.equal(keys.identity.readUInt16BE(389), 4);
  for (let offset = 64; offset < 352; offset += 32) {
    assert.deepEqual(keys.identity.subarray(32, 64), keys.identity.subarray(offset, offset + 32));
  }
  const encoded = createRouterInfoRecord(keys, Date.now(), [], new Map([['netId', '2'], ['router.version', '0.0.1-test']]));
  const parsed = parseRouterInfo(encoded);
  assert.deepEqual(parsed.identityHash, keys.identityHash);
  assert.equal(verifyRouterInfoSignature(parsed), true);
  const store = new VerifiedRouterInfoStore();
  assert.equal(store.store(parsed), true);
  assert.deepEqual(store.get(keys.identityHash)?.identity, keys.identity);
});

test('RouterInfo creator refuses mismatched signing key', () => {
  const first = createRouterIdentity(); const second = createRouterIdentity();
  assert.throws(() => createRouterInfoRecord({ ...first, signingPrivateKey: second.signingPrivateKey }, Date.now(), [], new Map([['netId', '2']])), /does not match/);
});
