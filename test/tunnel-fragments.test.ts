import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { decodeI2np, type I2npMessage } from '../src/router/protocol/i2np.ts';
import { buildTunnelMessageFragments, parseTunnelMessageFragment } from '../src/router/tunnel/fragments.ts';

test('tunnel message framing round-trips local and router delivery with checksum and padding', () => {
  const message: I2npMessage = { type: 20, id: 44, expiration: 1_900_000_000_000, payload: Buffer.from('tunnel payload') };
  for (const delivery of [{ type: 'local' as const }, { type: 'router' as const, identityHash: randomBytes(32) }]) {
    const [encoded] = buildTunnelMessageFragments(message, delivery, { iv: Buffer.alloc(16, 0x39), random: length => Buffer.alloc(length, 0x7f) });
    assert.ok(encoded);
    const parsed = parseTunnelMessageFragment(encoded);
    assert.deepEqual(parsed.delivery, delivery);
    assert.equal(parsed.lastFragment, true);
    assert.equal(parsed.followOn, false);
    assert.deepEqual(decodeI2np(parsed.data), message);
  }
});

test('tunnel message framing emits linked initial and follow-on fragments', () => {
  const message: I2npMessage = { type: 20, id: 0x12345678, expiration: 1_900_000_000_000, payload: randomBytes(5000) };
  const delivery = { type: 'tunnel' as const, tunnelId: 0x87654321, gatewayHash: randomBytes(32) };
  const encoded = buildTunnelMessageFragments(message, delivery);
  assert.ok(encoded.length > 2);
  const fragments = encoded.map(parseTunnelMessageFragment);
  assert.deepEqual(fragments[0]!.delivery, delivery);
  assert.equal(fragments[0]!.followOn, false);
  assert.equal(fragments[0]!.lastFragment, false);
  assert.equal(fragments[0]!.messageId, message.id);
  for (let index = 1; index < fragments.length; index++) {
    assert.equal(fragments[index]!.followOn, true);
    assert.equal(fragments[index]!.messageId, message.id);
    assert.equal(fragments[index]!.fragmentNumber, index);
    assert.equal(fragments[index]!.lastFragment, index === fragments.length - 1);
  }
  const reassembled = Buffer.concat(fragments.map(fragment => fragment.data));
  assert.deepEqual(decodeI2np(reassembled), message);
});

test('tunnel message parser rejects invalid checksum and delivery instruction flags', () => {
  const message: I2npMessage = { type: 20, id: 1, expiration: Date.now() + 1000, payload: Buffer.from('x') };
  const [frame] = buildTunnelMessageFragments(message, { type: 'local' });
  assert.ok(frame);
  const damaged = Buffer.from(frame); damaged[16] = damaged[16]! ^ 1;
  assert.throws(() => parseTunnelMessageFragment(damaged), /checksum/);
  const badInstruction = Buffer.from(frame);
  const delimiter = badInstruction.indexOf(0, 20);
  badInstruction[delimiter + 1] = 0x60;
  const checksum = createHash('sha256').update(badInstruction.subarray(delimiter + 1)).update(badInstruction.subarray(0, 16)).digest();
  checksum.copy(badInstruction, 16, 0, 4);
  assert.throws(() => parseTunnelMessageFragment(badInstruction), /flags\/type/);
});
