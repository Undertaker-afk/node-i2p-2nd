import test from 'node:test';
import assert from 'node:assert/strict';
import { ByteReader, encodeDate, encodeString } from '../src/router/protocol/common.ts';

test('common I2P date and UTF-8 string structures round-trip', () => {
  const date = encodeDate(1_700_000_000_123);
  const string = encodeString('I2P café 🧅');
  const reader = new ByteReader(Buffer.concat([date, string]));
  assert.equal(reader.readDate(), 1_700_000_000_123);
  assert.equal(reader.readString(), 'I2P café 🧅');
  reader.assertEnd();
});

test('common structures reject truncated, trailing, oversized and invalid data', () => {
  assert.throws(() => new ByteReader(Buffer.from([2, 0xaa])).readString(), /Truncated/);
  assert.throws(() => new ByteReader(Buffer.from([2, 0xc3, 0x28])).readString(), /Invalid UTF-8/);
  assert.throws(() => new ByteReader(Buffer.alloc(9), 8), /configured limit/);
  assert.throws(() => encodeString('x'.repeat(256)), /255/);
  assert.throws(() => encodeString('\ud800'), /invalid Unicode/);
  assert.throws(() => encodeDate(-1), /non-negative/);
  const reader = new ByteReader(Buffer.from([1, 2])); reader.readUInt8();
  assert.throws(() => reader.assertEnd(), /trailing/);
});
