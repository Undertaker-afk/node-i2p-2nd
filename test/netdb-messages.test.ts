import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeDatabaseLookup, encodeDatabaseSearchReply, parseDatabaseLookup, parseDatabaseSearchReply } from '../src/router/netdb/messages.ts';

const h = (byte: number) => Buffer.alloc(32, byte);

test('DatabaseLookup encodes and parses a direct RouterInfo lookup', () => {
  const expected = { key: h(1), from: h(2), kind: 'routerInfo' as const, excludedPeers: [h(3), h(4)] };
  const payload = encodeDatabaseLookup(expected);
  assert.equal(payload[64], 8);
  assert.deepEqual(parseDatabaseLookup(payload), expected);
});

test('DatabaseLookup encodes tunnel reply route and exploratory lookup', () => {
  const expected = { key: h(5), from: h(6), kind: 'exploration' as const, replyTunnelId: 0x12345678, excludedPeers: [] };
  const payload = encodeDatabaseLookup(expected);
  assert.equal(payload[64], 13);
  assert.deepEqual(parseDatabaseLookup(payload), expected);
});

test('DatabaseLookup rejects unsupported flags, type, count, and truncation', () => {
  const payload = encodeDatabaseLookup({ key: h(1), from: h(2), kind: 'routerInfo', excludedPeers: [] });
  const encrypted = Buffer.from(payload); encrypted[64] = encrypted[64]! | 2;
  assert.throws(() => parseDatabaseLookup(encrypted), /Encrypted/);
  const unsupported = Buffer.from(payload); unsupported[64] = 0;
  assert.throws(() => parseDatabaseLookup(unsupported), /Unsupported DatabaseLookup type/);
  assert.throws(() => parseDatabaseLookup(payload.subarray(0, 66)), /Truncated/);
  assert.throws(() => encodeDatabaseLookup({ key: h(1), from: h(2), kind: 'routerInfo', excludedPeers: Array(513).fill(h(3)) }), /512/);
});

test('DatabaseSearchReply round-trips and rejects malformed payloads', () => {
  const reply = { key: h(7), peers: [h(8), h(9)], from: h(10) };
  assert.deepEqual(parseDatabaseSearchReply(encodeDatabaseSearchReply(reply)), reply);
  assert.throws(() => parseDatabaseSearchReply(Buffer.alloc(32)), /Truncated/);
  assert.throws(() => encodeDatabaseSearchReply({ key: h(1), peers: Array(256).fill(h(2)), from: h(3) }), /255/);
});
