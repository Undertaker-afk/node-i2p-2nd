import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { loadOrCreateRouterIdentity } from '../src/router/identity-store.ts';

test('persists identity safely and reloads stable signing/encryption keys', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i2p-ts-'));
  const state = path.join(root, 'state');
  try {
    const [first, concurrent] = await Promise.all([loadOrCreateRouterIdentity(state), loadOrCreateRouterIdentity(state)]);
    assert.deepEqual(first.identity, concurrent.identity);
    assert.deepEqual(first.identityHash, concurrent.identityHash);
    const file = path.join(state, 'router-identity.json');
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const reloaded = await loadOrCreateRouterIdentity(state);
    assert.deepEqual(reloaded.identity, first.identity);
    assert.deepEqual(reloaded.signingPrivateKey.export({ format: 'der', type: 'pkcs8' }), first.signingPrivateKey.export({ format: 'der', type: 'pkcs8' }));
    assert.equal((await readFile(file, 'utf8')).includes(first.identity.toString('base64')), true);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('identity store rejects broad permissions and mismatched private keys', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i2p-ts-'));
  const state = path.join(root, 'state');
  try {
    await loadOrCreateRouterIdentity(state);
    const file = path.join(state, 'router-identity.json');
    await chmod(file, 0o644);
    await assert.rejects(loadOrCreateRouterIdentity(state), /permissions are too broad/);
    await chmod(file, 0o600);
    const value = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
    value.signingPrivateKey = value.encryptionPrivateKey;
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await assert.rejects(loadOrCreateRouterIdentity(state), /do not match/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
