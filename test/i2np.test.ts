import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeI2np, decodeShortI2npHeader, encodeI2np, encodeShortI2npHeader, I2NP_HEADER_LENGTH, I2npStreamDecoder } from '../src/router/protocol/i2np.ts';

test('standard I2NP zero-payload checksum matches SHA-256 known value', () => {
  const empty = encodeI2np({ type: 0, id: 0, expiration: 0, payload: Buffer.alloc(0) });
  assert.equal(empty[15], 0xe3);
  assert.deepEqual(decodeI2np(empty).payload, Buffer.alloc(0));
});

test('standard I2NP message encodes and decodes a valid header and payload', () => {
  const expected = { type: 3, id: 0x12345678, expiration: 1_700_000_000_123, payload: Buffer.from('router-data') };
  const encoded = encodeI2np(expected);
  assert.equal(encoded.length, I2NP_HEADER_LENGTH + expected.payload.length);
  assert.equal(encoded.readUInt8(0), expected.type);
  assert.equal(encoded.readUInt32BE(1), expected.id);
  assert.equal(encoded.readBigUInt64BE(5), BigInt(expected.expiration));
  assert.deepEqual(decodeI2np(encoded), expected);
});

test('standard I2NP codec rejects truncation, trailing bytes, and checksum tampering', () => {
  const packet = encodeI2np({ type: 1, id: 9, expiration: 1234, payload: Buffer.from([1, 2, 3]) });
  assert.throws(() => decodeI2np(packet.subarray(0, 15)), /Truncated/);
  assert.throws(() => decodeI2np(Buffer.concat([packet, Buffer.from([0])])), /length/);
  const corrupted = Buffer.from(packet); corrupted[16] = corrupted[16]! ^ 0xff;
  assert.throws(() => decodeI2np(corrupted), /checksum/);
});

test('standard I2NP codec enforces wire field ranges', () => {
  assert.throws(() => encodeI2np({ type: 256, id: 1, expiration: 1, payload: Buffer.alloc(0) }), /type/);
  assert.throws(() => encodeI2np({ type: 1, id: -1, expiration: 1, payload: Buffer.alloc(0) }), /id/);
  assert.throws(() => encodeI2np({ type: 1, id: 1, expiration: 1, payload: Buffer.alloc(0x10000) }), /65535/);
});

test('incremental I2NP decoder accepts split frames and multiple messages per chunk', () => {
  const first = encodeI2np({ type: 1, id: 2, expiration: 9000, payload: Buffer.from('one') });
  const second = encodeI2np({ type: 2, id: 3, expiration: 9001, payload: Buffer.from('two') });
  const decoder = new I2npStreamDecoder();
  assert.deepEqual(decoder.push(first.subarray(0, 7)), []);
  assert.equal(decoder.pendingBytes, 7);
  assert.deepEqual(decoder.push(Buffer.concat([first.subarray(7), second])), [
    { type: 1, id: 2, expiration: 9000, payload: Buffer.from('one') },
    { type: 2, id: 3, expiration: 9001, payload: Buffer.from('two') },
  ]);
  assert.equal(decoder.pendingBytes, 0); decoder.finish();
  assert.throws(() => decoder.push(Buffer.alloc(0)), /already ended/);
});

test('incremental I2NP decoder rejects truncated stream on finish', () => {
  const decoder = new I2npStreamDecoder(); decoder.push(Buffer.from([1, 2, 3]));
  assert.throws(() => decoder.finish(), /Truncated/);
});

test('short I2NP header round-trips and rejects incorrect lengths', () => {
  const expected = { type: 11, id: 0xfedcba98, expirationSeconds: 0x65010203 };
  assert.deepEqual(decodeShortI2npHeader(encodeShortI2npHeader(expected)), expected);
  assert.throws(() => decodeShortI2npHeader(Buffer.alloc(8)), /9 bytes/);
  assert.throws(() => encodeShortI2npHeader({ ...expected, expirationSeconds: -1 }), /expirationSeconds/);
});
