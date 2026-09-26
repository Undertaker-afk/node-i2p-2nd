import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { I2npMessage } from '../src/router/protocol/i2np.ts';
import { buildTunnelMessageFragments } from '../src/router/tunnel/fragments.ts';
import { TunnelFragmentReassembler } from '../src/router/tunnel/reassembly.ts';

test('reassembles out-of-order tunnel fragments and preserves delivery routing', () => {
  const message: I2npMessage = { type: 20, id: 0x10203040, expiration: Date.now() + 60_000, payload: randomBytes(8000) };
  const delivery = { type: 'router' as const, identityHash: randomBytes(32) };
  const fragments = buildTunnelMessageFragments(message, delivery);
  const reassembler = new TunnelFragmentReassembler();
  assert.equal(reassembler.add(fragments[0]!), undefined);
  for (let index = fragments.length - 1; index >= 1; index--) {
    const completed = reassembler.add(fragments[index]!);
    if (index !== 1) assert.equal(completed, undefined);
    else {
      assert.ok(completed);
      assert.deepEqual(completed.delivery, delivery);
      assert.deepEqual(completed.message, message);
    }
  }
  assert.equal(reassembler.size, 0);
  assert.equal(reassembler.bufferedBytes, 0);
});

test('fragment reassembler rejects duplicates and clears expired partial messages', () => {
  const message: I2npMessage = { type: 20, id: 55, expiration: Date.now() + 60_000, payload: randomBytes(3000) };
  const fragments = buildTunnelMessageFragments(message, { type: 'local' });
  const duplicate = new TunnelFragmentReassembler();
  duplicate.add(fragments[0]!);
  assert.throws(() => duplicate.add(fragments[0]!), /checksum|Duplicate|initial/);

  const expired = new TunnelFragmentReassembler({ fragmentTimeoutMs: 100 });
  expired.add(fragments[0]!, 1_000);
  assert.equal(expired.size, 0);
  assert.equal(expired.bufferedBytes, 0);
});
