import test from 'node:test';
import assert from 'node:assert/strict';
import { Ntcp2ReplayCache } from '../src/router/transport/ntcp2/accept.ts';

test('NTCP2 replay cache rejects duplicates, expires entries, and stays bounded', () => {
  const cache = new Ntcp2ReplayCache(2);
  const first = Buffer.alloc(32, 1); const second = Buffer.alloc(32, 2); const third = Buffer.alloc(32, 3);
  assert.equal(cache.remember(first, 1_000, 100), true);
  assert.equal(cache.remember(first, 1_001, 100), false);
  assert.equal(cache.remember(second, 1_002, 100), true);
  assert.equal(cache.remember(third, 1_003, 100), true);
  assert.equal(cache.remember(first, 1_004, 100), true, 'oldest entry is evicted at capacity');
  assert.equal(cache.remember(second, 1_200, 100), true, 'expired entry can be used again');
  assert.throws(() => cache.remember(Buffer.alloc(31), 1_000, 100), /32-byte/);
  assert.throws(() => cache.remember(first, 1_000, 0), /TTL/);
});
