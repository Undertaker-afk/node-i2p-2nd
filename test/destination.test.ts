import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createDestinationKeys, encodeDestinationBase64, parseDestination } from '../src/router/protocol/destination.ts';
import { createLeaseSet2, parseLeaseSet2, selectX25519Key, verifyLeaseSet2 } from '../src/router/protocol/leaseset.ts';
import { wrapDestExistingSession, unwrapDestExistingSession, unwrapDestNewSession, unwrapDestNewSessionReply, wrapDestNewSession, wrapDestNewSessionReply } from '../src/router/crypto/ecies-dest.ts';
import { createSynAckPacket, createSynPacket, parseStreamingPacket } from '../src/router/streaming.ts';
import { encodeDatabaseLookup, parseDatabaseLookup, encryptDatabaseLookupReply, decryptDatabaseLookupReply } from '../src/router/netdb/messages.ts';
import { encodeDatabaseStoreLeaseSet2, parseDatabaseStore } from '../src/router/netdb/database-store.ts';
import { HostsBook } from '../src/router/netdb/hosts.ts';
import { I2NP_DATA } from '../src/router/streaming.ts';

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
});
