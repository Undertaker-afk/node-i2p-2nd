import test from 'node:test';
import assert from 'node:assert/strict';
import { SipHashLengthCipher, sipHash24 } from '../src/router/transport/ntcp2/siphash.ts';

test('SipHash-2-4 matches published zero- and one-byte vectors', () => {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  assert.equal(sipHash24(key.subarray(0, 8), key.subarray(8), Buffer.alloc(0)).toString('hex'), '310e0edd47db6f72');
  assert.equal(sipHash24(key.subarray(0, 8), key.subarray(8), Buffer.from([0])).toString('hex'), 'fd67dc93c539f874');
});

test('NTCP2 frame lengths obfuscate/deobfuscate with synchronized rolling IV', () => {
  const keys = { key1: Buffer.alloc(8, 1), key2: Buffer.alloc(8, 2), iv: Buffer.alloc(8, 3) };
  const sender = new SipHashLengthCipher(keys); const receiver = new SipHashLengthCipher(keys);
  for (const length of [16, 64, 1500, 65535]) {
    const encrypted = sender.encode(length);
    assert.notEqual(encrypted, length);
    assert.equal(receiver.decode(encrypted), length);
  }
  assert.throws(() => sender.encode(15), /16\.\.65535/);
  const maskSource = new SipHashLengthCipher(keys); const firstEncodedLength = maskSource.encode(16);
  const invalidReceiver = new SipHashLengthCipher(keys);
  assert.throws(() => invalidReceiver.decode(firstEncodedLength ^ 16), /Invalid de-obfuscated/);
});
