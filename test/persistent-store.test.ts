import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRouterIdentity } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo } from '../src/router/protocol/router-info.ts';
import { PersistentRouterInfoStore } from '../src/router/netdb/persistent-store.ts';

function newRecord() {
  const keys = createRouterIdentity();
  const encoded = createRouterInfoRecord(keys, Date.now(), [], new Map([['netId', '2']]));
  return { keys, info: parseRouterInfo(encoded) };
}

test('persistent netDb stores verified RouterInfo atomically and reloads it', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i2p-netdb-'));
  const directory = path.join(root, 'netdb');
  try {
    const store = await PersistentRouterInfoStore.open(directory);
    const { keys, info } = newRecord();
    assert.equal(await store.store(info), true);
    assert.equal((await stat(path.join(directory, `${keys.identityHash.toString('hex')}.ri`))).mode & 0o777, 0o600);
    const restored = await PersistentRouterInfoStore.open(directory);
    assert.equal(restored.size, 1);
    assert.deepEqual(restored.get(keys.identityHash)?.identity, keys.identity);
    assert.equal(await restored.store(info), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('persistent netDb bounds disk records and rejects records from another network', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i2p-netdb-'));
  const directory = path.join(root, 'netdb');
  try {
    const store = await PersistentRouterInfoStore.open(directory, { maxRecords: 1 });
    const first = newRecord(); const second = newRecord();
    await store.store(first.info); await store.store(second.info);
    assert.equal((await readdir(directory)).filter(name => name.endsWith('.ri')).length, 1);
    assert.equal(store.size, 1);
    const foreignKeys = createRouterIdentity();
    const foreign = parseRouterInfo(createRouterInfoRecord(foreignKeys, Date.now(), [], new Map([['netId', '5']])));
    await assert.rejects(store.store(foreign), /network ID/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
