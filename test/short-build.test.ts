import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRouterIdentity } from '../src/router/identity.ts';
import {
  SHORT_BUILD_RECORD_SIZE, SHORT_BUILD_REQUEST_SIZE, SHORT_BUILD_REPLY_SIZE,
  decryptShortBuildRequestRecord, decryptShortTunnelBuildReplyRecord, encodeShortBuildReplyPlaintext,
  encodeShortBuildRequestPlaintext, encodeShortTunnelBuildPayload, encryptShortBuildRequestRecord,
  encryptShortTunnelBuildReply, parseShortBuildReplyPlaintext, parseShortTunnelBuildPayload,
  transformShortBuildReplyCoverRecords,
} from '../src/router/tunnel/short-build.ts';

const rawX25519PublicKey = (identity: Buffer): Buffer => Buffer.from(identity.subarray(0, 32));

test('short-build plaintext validates fields, writes the mapping and pads to the fixed record size', () => {
  const next = randomBytes(32);
  const mapping = Buffer.from([0, 3, 0x61, 0x3d, 0x62]);
  const record = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 1, nextTunnelId: 2, nextIdentityHash: next, flags: 0x80,
    requestTimeMinutes: 123, expirationSeconds: 600, nextMessageId: 3, optionsMapping: mapping,
    random: length => Buffer.alloc(length, 0x5a),
  });
  assert.equal(record.length, SHORT_BUILD_REQUEST_SIZE);
  assert.equal(record.readUInt32BE(0), 1);
  assert.equal(record.readUInt32BE(4), 2);
  assert.deepEqual(record.subarray(8, 40), next);
  assert.equal(record[40], 0x80);
  assert.equal(record.readUInt32BE(44), 123);
  assert.equal(record.readUInt32BE(48), 600);
  assert.equal(record.readUInt32BE(52), 3);
  assert.deepEqual(record.subarray(56, 56 + mapping.length), mapping);
  assert.equal(record.at(-1), 0x5a);
  assert.throws(() => encodeShortBuildRequestPlaintext({ receiveTunnelId: 1, nextTunnelId: 2, nextIdentityHash: next, flags: 0xc0, nextMessageId: 3 }), /flags/);
  assert.throws(() => encodeShortBuildRequestPlaintext({ receiveTunnelId: 0, nextTunnelId: 2, nextIdentityHash: next, flags: 0, nextMessageId: 3 }), /nonzero/);
});

test('ECIES short tunnel request uses Noise N and derives matching transit keys', () => {
  const router = createRouterIdentity();
  const plaintext = randomBytes(SHORT_BUILD_REQUEST_SIZE);
  plaintext.writeUInt32BE(0x12345678, 0);
  plaintext.writeUInt32BE(0x23456789, 4);
  plaintext.fill(0x44, 8, 40);
  plaintext[40] = 0x80;
  plaintext[43] = 0;
  plaintext.writeUInt32BE(Math.floor(Date.now() / 60_000), 44);
  plaintext.writeUInt32BE(600, 48);
  plaintext.writeUInt32BE(0x98765432, 52);

  const encrypted = encryptShortBuildRequestRecord(router.identityHash, rawX25519PublicKey(router.identity), plaintext);
  assert.equal(encrypted.bytes.length, SHORT_BUILD_RECORD_SIZE);
  assert.equal(encrypted.bytes.subarray(0, 16).equals(router.identityHash.subarray(0, 16)), true);
  const decoded = decryptShortBuildRequestRecord(encrypted.bytes, router.identityHash, router.encryptionPrivateKey, rawX25519PublicKey(router.identity));
  assert.deepEqual(decoded.raw, plaintext);
  assert.equal(decoded.receiveTunnelId, 0x12345678);
  assert.equal(decoded.nextTunnelId, 0x23456789);
  assert.equal(decoded.flags, 0x80);
  assert.equal(decoded.expirationSeconds, 600);
  assert.equal(decoded.nextMessageId, 0x98765432);
  assert.equal(decoded.replyKey.length, 32);
  assert.equal(decoded.layerKey.length, 32);
  assert.equal(decoded.ivKey.length, 32);
  assert.equal(decoded.handshakeHash.length, 32);
  assert.deepEqual(encrypted.replyKey, decoded.replyKey);
  assert.deepEqual(encrypted.layerKey, decoded.layerKey);
  assert.deepEqual(encrypted.ivKey, decoded.ivKey);
  assert.deepEqual(encrypted.handshakeHash, decoded.handshakeHash);
});

test('OBEP Noise KDF derives the one-time garlic reply key and tag consistently', () => {
  const router = createRouterIdentity();
  const plaintext = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 77, nextTunnelId: 88, nextIdentityHash: randomBytes(32),
    flags: 0x40, nextMessageId: 99,
  });
  const encrypted = encryptShortBuildRequestRecord(router.identityHash, rawX25519PublicKey(router.identity), plaintext);
  const decrypted = decryptShortBuildRequestRecord(encrypted.bytes, router.identityHash, router.encryptionPrivateKey, rawX25519PublicKey(router.identity));
  assert.ok(encrypted.garlicReplyKey); assert.ok(encrypted.garlicReplyTag);
  assert.ok(decrypted.garlicReplyKey); assert.ok(decrypted.garlicReplyTag);
  assert.equal(encrypted.garlicReplyKey.length, 32);
  assert.equal(encrypted.garlicReplyTag.length, 8);
  assert.deepEqual(encrypted.garlicReplyKey, decrypted.garlicReplyKey);
  assert.deepEqual(encrypted.garlicReplyTag, decrypted.garlicReplyTag);
});

test('ECIES short-build request rejects wrong recipient, malformed size, and tampered ciphertext', () => {
  const router = createRouterIdentity();
  const record = encryptShortBuildRequestRecord(router.identityHash, rawX25519PublicKey(router.identity), randomBytes(SHORT_BUILD_REQUEST_SIZE)).bytes;
  assert.throws(() => decryptShortBuildRequestRecord(record, randomBytes(32), router.encryptionPrivateKey, rawX25519PublicKey(router.identity)), /not addressed/);
  assert.throws(() => decryptShortBuildRequestRecord(record.subarray(1), router.identityHash, router.encryptionPrivateKey, rawX25519PublicKey(router.identity)), /218 bytes/);
  const corrupted = Buffer.from(record); corrupted[217] = corrupted[217]! ^ 0x01;
  assert.throws(() => decryptShortBuildRequestRecord(corrupted, router.identityHash, router.encryptionPrivateKey, rawX25519PublicKey(router.identity)));
});

test('short-build payload encodes bounded records and creates reply cover ciphertext', () => {
  const router = createRouterIdentity();
  const first = encryptShortBuildRequestRecord(router.identityHash, rawX25519PublicKey(router.identity), randomBytes(SHORT_BUILD_REQUEST_SIZE)).bytes;
  const second = randomBytes(SHORT_BUILD_RECORD_SIZE);
  const encoded = encodeShortTunnelBuildPayload([first, second]);
  assert.deepEqual(parseShortTunnelBuildPayload(encoded), [first, second]);
  assert.throws(() => parseShortTunnelBuildPayload(Buffer.from([0])), /count/);
  assert.throws(() => parseShortTunnelBuildPayload(Buffer.concat([encoded, Buffer.from([0])])), /length/);

  const decrypted = decryptShortBuildRequestRecord(first, router.identityHash, router.encryptionPrivateKey, rawX25519PublicKey(router.identity));
  const replyPlaintext = encodeShortBuildReplyPlaintext(30, Buffer.alloc(2), length => Buffer.alloc(length, 0xa5));
  const replies = encryptShortTunnelBuildReply([first, second], 0, replyPlaintext, decrypted.replyKey, decrypted.handshakeHash);
  assert.equal(replies[0]!.length, SHORT_BUILD_RECORD_SIZE);
  assert.equal(replies[1]!.length, SHORT_BUILD_RECORD_SIZE);
  const clearReply = decryptShortTunnelBuildReplyRecord(replies[0]!, 0, decrypted.replyKey, decrypted.handshakeHash);
  assert.deepEqual(clearReply, replyPlaintext);
  assert.deepEqual(parseShortBuildReplyPlaintext(clearReply), { optionsMapping: Buffer.alloc(2), returnCode: 30, raw: replyPlaintext });
  assert.throws(() => decryptShortTunnelBuildReplyRecord(replies[0]!, 1, decrypted.replyKey, decrypted.handshakeHash));
  assert.notDeepEqual(replies[1], second);
  const unwrapped = transformShortBuildReplyCoverRecords(replies, 0, decrypted.replyKey);
  assert.deepEqual(unwrapped[0], replies[0]);
  assert.deepEqual(unwrapped[1], second);
});
