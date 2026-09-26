import test from 'node:test';
import assert from 'node:assert/strict';
import { Ntcp2DataCipher } from '../src/router/transport/ntcp2/data-cipher.ts';
import { decodeI2npBlock, encodeI2npBlock } from '../src/router/transport/ntcp2/blocks.ts';
import type { SipHashKeys } from '../src/router/transport/ntcp2/siphash.ts';

const keys = (base: number): SipHashKeys => ({ key1: Buffer.alloc(8, base), key2: Buffer.alloc(8, base + 1), iv: Buffer.alloc(8, base + 2) });

test('NTCP2 data cipher exchanges authenticated blocks over fragmented TCP input', () => {
  const aliceToBob = Buffer.alloc(32, 0x11); const bobToAlice = Buffer.alloc(32, 0x22);
  const alice = new Ntcp2DataCipher(aliceToBob, bobToAlice, keys(1), keys(4));
  const bob = new Ntcp2DataCipher(bobToAlice, aliceToBob, keys(4), keys(1));
  const block = encodeI2npBlock({ type: 3, id: 0x12345678, expiration: 1_800_000_000_999, payload: Buffer.from('i2np test payload') });
  const first = alice.seal([block]); const second = alice.seal([{ type: 254, data: Buffer.from('pad') }]);
  assert.deepEqual(bob.push(first.subarray(0, 1)), []);
  assert.deepEqual(bob.push(first.subarray(1, 13)), []);
  const result = bob.push(Buffer.concat([first.subarray(13), second]));
  assert.equal(result.length, 2);
  assert.deepEqual(decodeI2npBlock(result[0]![0]!), { type: 3, id: 0x12345678, expiration: 1_800_000_000_000, payload: Buffer.from('i2np test payload') });
  assert.deepEqual(result[1], [{ type: 254, data: Buffer.from('pad') }]);
  const response = bob.seal([{ type: 0, data: Buffer.from('time') }]);
  assert.deepEqual(alice.push(response), [[{ type: 0, data: Buffer.from('time') }]]);
});

test('NTCP2 data cipher detects tag corruption and malformed blocks', () => {
  const a = new Ntcp2DataCipher(Buffer.alloc(32, 1), Buffer.alloc(32, 2), keys(3), keys(6));
  const b = new Ntcp2DataCipher(Buffer.alloc(32, 2), Buffer.alloc(32, 1), keys(6), keys(3));
  const corrupted = a.seal([{ type: 0, data: Buffer.from([1]) }]); corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
  assert.throws(() => b.push(corrupted));
  const sender2 = new Ntcp2DataCipher(Buffer.alloc(32, 1), Buffer.alloc(32, 2), keys(3), keys(6));
  const malformed = sender2.seal([{ type: 3, data: Buffer.from([1, 2]) }]);
  const fresh = new Ntcp2DataCipher(Buffer.alloc(32, 2), Buffer.alloc(32, 1), keys(6), keys(3));
  assert.throws(() => decodeI2npBlock(fresh.push(malformed)[0]![0]!), /9-byte/);
});

test('short NTCP2 I2NP block validates the 9-byte unframed header', () => {
  assert.throws(() => decodeI2npBlock({ type: 3, data: Buffer.alloc(8) }), /9-byte/);
  assert.throws(() => decodeI2npBlock({ type: 4, data: Buffer.alloc(9) }), /Expected/);
});
