import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createDestinationKeys, encodeDestinationBase64, parseDestination } from '../src/router/protocol/destination.ts';
import { createLeaseSet2, parseLeaseSet2, selectX25519Key, verifyLeaseSet2 } from '../src/router/protocol/leaseset.ts';
import { wrapDestExistingSession, unwrapDestExistingSession, unwrapDestNewSession, unwrapDestNewSessionReply, wrapDestNewSession, wrapDestNewSessionReply } from '../src/router/crypto/ecies-dest.ts';
import { createSynAckPacket, createSynPacket, parseStreamingPacket } from '../src/router/streaming.ts';
import { encodeDatabaseLookup, parseDatabaseLookup, encryptDatabaseLookupReply, decryptDatabaseLookupReply } from '../src/router/netdb/messages.ts';
import { encodeDatabaseStoreLeaseSet2, parseDatabaseStore } from '../src/router/netdb/database-store.ts';
import { HostsBook } from '../src/router/netdb/hosts.ts';
import { I2NP_DATA } from '../src/router/streaming.ts';
import { encryptAead } from '../src/router/crypto/x25519.ts';
import { encodeDateTimeBlock, encodeGarlicCloveBlock, encodePaddingBlock } from '../src/router/tunnel/garlic.ts';
import { DestinationSessionManager, type DestinationStream } from '../src/router/destination-session.ts';
import { httpGetOverStream } from '../src/router/http-client.ts';
import { loadOrCreateDestinationKeys } from '../src/router/destination-store.ts';

function clove(destHash: Buffer, payload: Buffer) {
  return {
    delivery: { type: 'destination' as const, hash: destHash },
    message: { type: I2NP_DATA, id: 7, expiration: Date.now() + 60_000, payload },
  };
}

test('Ed25519 destinations and LeaseSet2 round-trip with an X25519 key', () => {
  const keys = createDestinationKeys();
  assert.equal(keys.destination.length, 391);
  assert.equal(keys.destination.readUInt16BE(389), 0);
  assert.equal(parseDestination(keys.destination).signatureType, 7);
  const leases = [{ gatewayHash: randomBytes(32), tunnelId: 99, expiresAtSeconds: Math.floor(Date.now() / 1000) + 600 }];
  const encoded = createLeaseSet2(keys, leases);
  const ls = parseLeaseSet2(encoded);
  assert.equal(verifyLeaseSet2(ls), true);
  assert.deepEqual(selectX25519Key(ls), keys.encryptionPublicKey);
  assert.equal(ls.leases[0]!.tunnelId, 99);
  const store = parseDatabaseStore(encodeDatabaseStoreLeaseSet2(encoded));
  assert.equal(store.kind, 'leaseSet2');
  if (store.kind === 'leaseSet2') assert.deepEqual(store.record.leaseSet.destinationHash, keys.destinationHash);
});

test('ECIES destination New Session / Reply / Existing Session round-trips streaming cloves', () => {
  const alice = createDestinationKeys();
  const bob = createDestinationKeys();
  const syn = createSynPacket(alice);
  const ns = wrapDestNewSession([clove(bob.destinationHash, syn)], bob.encryptionPublicKey, alice.encryptionPublicKey, alice.encryptionPrivateKey);
  const incoming = unwrapDestNewSession(ns.message, bob.encryptionPrivateKey, bob.encryptionPublicKey);
  assert.deepEqual(incoming.aliceStaticPublicKey, alice.encryptionPublicKey);
  assert.equal(incoming.cloves[0]!.message.type, I2NP_DATA);
  parseStreamingPacket(incoming.cloves[0]!.message.payload);
  const synAck = createSynAckPacket(bob, parseStreamingPacket(syn).receiveStreamId, 44);
  const nsr = wrapDestNewSessionReply(incoming, [clove(alice.destinationHash, synAck)], incoming.aliceStaticPublicKey, bob.encryptionPrivateKey);
  const opened = unwrapDestNewSessionReply(nsr.message, ns, alice.encryptionPrivateKey);
  assert.equal(opened.cloves[0]!.message.type, I2NP_DATA);
  const follow = wrapDestExistingSession(opened.session, [clove(bob.destinationHash, Buffer.from('ping'))]);
  const cloves = unwrapDestExistingSession(follow, nsr.session);
  assert.deepEqual(cloves[0]!.message.payload, Buffer.from('ping'));
});

test('DatabaseLookup encodes LeaseSet queries and ECIES encrypted replies', () => {
  const key = randomBytes(32); const from = randomBytes(32); const replyKey = randomBytes(32); const tag = randomBytes(8);
  const payload = encodeDatabaseLookup({
    key, from, kind: 'leaseSet', replyTunnelId: 5, excludedPeers: [], encryptedReply: { key: replyKey, tag },
  });
  const parsed = parseDatabaseLookup(payload);
  assert.equal(parsed.kind, 'leaseSet');
  assert.equal(parsed.replyTunnelId, 5);
  assert.deepEqual(parsed.encryptedReply?.tag, tag);
  const inner = { type: 1, id: 9, expiration: Date.now() + 10_000, payload: randomBytes(8) };
  const encrypted = encryptDatabaseLookupReply(inner, replyKey, tag);
  assert.deepEqual(decryptDatabaseLookupReply(encrypted, replyKey, tag).payload, inner.payload);
});

test('hosts book resolves i2p-projekt aliases and b32 names', () => {
  const book = new HostsBook();
  const dest = book.get('i2p-project.i2p');
  assert.ok(dest);
  assert.deepEqual(book.get('i2p-projekt.i2p'), dest);
  parseDestination(dest!);
  encodeDestinationBase64(dest!);
  const resolved = book.resolve('i2p-projekt.i2p');
  assert.ok(resolved?.destination);
  const imported = book.importHostsTxt('example.i2p=' + encodeDestinationBase64(dest!) + '\n');
  assert.equal(imported, 1);
  assert.ok(book.get('notbob.i2p'));
  assert.ok(book.get('identiguy.i2p'));
  assert.ok(book.get('stats.i2p'));
});

test('encrypted lookup replies accept Garlic cloves as well as raw I2NP', () => {
  const replyKey = randomBytes(32); const tag = randomBytes(8);
  const inner = { type: 1, id: 9, expiration: Date.now() + 10_000, payload: randomBytes(8) };
  const plaintext = Buffer.concat([
    encodeDateTimeBlock(),
    encodeGarlicCloveBlock({ delivery: { type: 'local' }, message: inner }),
    encodePaddingBlock(0),
  ]);
  const body = Buffer.concat([tag, encryptAead(replyKey, Buffer.alloc(12), tag, plaintext)]);
  const decrypted = decryptDatabaseLookupReply(body, replyKey, tag);
  assert.equal(decrypted.type, 1);
  assert.deepEqual(decrypted.payload, inner.payload);
});

test('destination sessions include LeaseSet2 in New Session and carry an HTTP GET', async () => {
  let alice!: DestinationSessionManager;
  const bob = new DestinationSessionManager({
    sendGarlic: async message => { alice.handleGarlic(message); },
  });
  alice = new DestinationSessionManager({
    sendGarlic: async message => { bob.handleGarlic(message); },
  });
  const aliceLease = { gatewayHash: randomBytes(32), tunnelId: 11, expiresAtSeconds: Math.floor(Date.now() / 1000) + 600 };
  alice.createLeaseSet([aliceLease]);
  let inbound: DestinationStream | undefined;
  const seenLease = new Promise<void>(resolve => {
    bob.on('leaseSet', ls => {
      assert.deepEqual(ls.destinationHash, alice.local.destinationHash);
      resolve();
    });
  });
  bob.on('inboundStream', (stream, nsr, remote) => {
    inbound = stream;
    assert.equal(remote.tunnelId, 11);
    assert.deepEqual(remote.gatewayHash, aliceLease.gatewayHash);
    stream.on('data', (_payload: Buffer) => {
      void stream.write(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello')).then(() => stream.close());
    });
    alice.handleGarlic(nsr);
  });
  const stream = await alice.connect({
    gatewayHash: randomBytes(32), tunnelId: 9,
    encryptionPublicKey: bob.local.encryptionPublicKey,
    destination: bob.local.destination, destinationHash: bob.local.destinationHash,
  });
  await seenLease;
  assert.ok(inbound);
  const response = await httpGetOverStream(stream, { host: 'bob.i2p', path: '/hosts.txt' });
  assert.equal(response.status, 200);
  assert.equal(response.body.toString(), 'hello');
});

test('persists destination keys across reloads', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i2p-dest-'));
  const state = path.join(root, 'state');
  try {
    const first = await loadOrCreateDestinationKeys(state);
    const reloaded = await loadOrCreateDestinationKeys(state);
    assert.deepEqual(reloaded.destination, first.destination);
    assert.deepEqual(reloaded.encryptionPublicKey, first.encryptionPublicKey);
    assert.equal((await stat(path.join(state, 'destination.json'))).mode & 0o777, 0o600);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('two streams to the same destination keep independent ratchet sessions; garlic IDs are unique', async () => {
  let alice!: DestinationSessionManager;
  const ids = new Set<number>();
  let sent = 0;
  const bob = new DestinationSessionManager({ sendGarlic: async message => { ids.add(message.id); sent++; alice.handleGarlic(message); } });
  alice = new DestinationSessionManager({ sendGarlic: async message => { ids.add(message.id); sent++; bob.handleGarlic(message); } });
  alice.createLeaseSet([{ gatewayHash: randomBytes(32), tunnelId: 11, expiresAtSeconds: Math.floor(Date.now() / 1000) + 600 }]);
  let served = 0;
  bob.on('inboundStream', (stream, nsr) => {
    const index = ++served;
    stream.on('data', () => { void stream.write(Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n${index}`)).then(() => stream.close()); });
    alice.handleGarlic(nsr);
  });
  const remote = { gatewayHash: randomBytes(32), tunnelId: 9, encryptionPublicKey: bob.local.encryptionPublicKey, destination: bob.local.destination, destinationHash: bob.local.destinationHash };
  const first = await alice.connect(remote);
  const second = await alice.connect(remote);
  // The first stream must still work after a second handshake with the same remote static key.
  const firstResponse = await httpGetOverStream(first, { host: 'bob.i2p', path: '/a', timeoutMs: 5_000 });
  const secondResponse = await httpGetOverStream(second, { host: 'bob.i2p', path: '/b', timeoutMs: 5_000 });
  assert.equal(firstResponse.body.toString(), '1');
  assert.equal(secondResponse.body.toString(), '2');
  assert.equal(ids.size, sent, 'every garlic message gets a fresh I2NP id (gateways drop repeated ids as replays)');
});
