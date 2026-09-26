import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, randomBytes,
  diffieHellman, generateKeyPairSync, hkdfSync, timingSafeEqual, type KeyObject,
} from 'node:crypto';

export const SHORT_BUILD_RECORD_SIZE = 218;
export const SHORT_BUILD_REQUEST_SIZE = 154;
export const SHORT_BUILD_REPLY_SIZE = 202;
export const SHORT_BUILD_MAX_RECORDS = 8;
export const SHORT_BUILD_ENDPOINT_FLAG = 0x40;
export const SHORT_BUILD_GATEWAY_FLAG = 0x80;
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const PROTOCOL_NAME = Buffer.from('Noise_N_25519_ChaChaPoly_SHA256', 'ascii');

export type ShortBuildRecord = {
  ephemeralPublicKey: Buffer; ciphertext: Buffer; bytes: Buffer;
  replyKey: Buffer; layerKey: Buffer; ivKey: Buffer; handshakeHash: Buffer;
  garlicReplyKey: Buffer | undefined; garlicReplyTag: Buffer | undefined;
};
export type ShortBuildRequestFields = {
  receiveTunnelId: number; nextTunnelId: number; nextIdentityHash: Buffer; flags: number;
  layerEncryptionType?: number; requestTimeMinutes?: number; expirationSeconds?: number;
  nextMessageId: number; optionsMapping?: Buffer; random?: (size: number) => Buffer;
};
export type DecryptedShortBuildRequest = {
  receiveTunnelId: number; nextTunnelId: number; nextIdentityHash: Buffer; flags: number;
  layerEncryptionType: number; requestTimeMinutes: number; expirationSeconds: number;
  nextMessageId: number; optionsAndPadding: Buffer; replyKey: Buffer; layerKey: Buffer;
  ivKey: Buffer; handshakeHash: Buffer; chainingKey: Buffer; raw: Buffer;
  garlicReplyKey: Buffer | undefined; garlicReplyTag: Buffer | undefined;
};
export type ShortBuildReply = { optionsMapping: Buffer; returnCode: number; raw: Buffer };

function sha256(...parts: Buffer[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}
function noiseInitialState(recipientStaticPublicKey: Buffer): { h: Buffer; ck: Buffer } {
  if (!Buffer.isBuffer(recipientStaticPublicKey) || recipientStaticPublicKey.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  const paddedName = Buffer.alloc(32);
  PROTOCOL_NAME.copy(paddedName);
  return { h: sha256(sha256(paddedName), recipientStaticPublicKey), ck: paddedName };
}
function mixKey(ck: Buffer, input: Buffer): { ck: Buffer; key: Buffer } {
  const output = Buffer.from(hkdfSync('sha256', input, ck, Buffer.alloc(0), 64));
  return { ck: output.subarray(0, 32), key: output.subarray(32, 64) };
}
function deriveKey(ck: Buffer, label: string): { ck: Buffer; key: Buffer } {
  const output = Buffer.from(hkdfSync('sha256', Buffer.alloc(0), ck, Buffer.from(label, 'ascii'), 64));
  return { ck: output.subarray(0, 32), key: output.subarray(32, 64) };
}
function rawPublicKey(key: KeyObject): Buffer {
  const encoded = key.export({ format: 'der', type: 'spki' });
  return Buffer.from(encoded.subarray(encoded.length - 32));
}
function publicX25519(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
function privateX25519(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error('X25519 private key must be 32 bytes');
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}
function encryptAead(key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function decryptAead(key: Buffer, nonce: Buffer, aad: Buffer, ciphertextAndTag: Buffer): Buffer {
  if (ciphertextAndTag.length < 16) throw new Error('Short build AEAD payload is truncated');
  const ciphertext = ciphertextAndTag.subarray(0, -16);
  const tag = ciphertextAndTag.subarray(-16);
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
function validateMapping(mapping: Buffer, maximumLength: number, label: string): void {
  if (!Buffer.isBuffer(mapping) || mapping.length < 2 || mapping.length > maximumLength || mapping.readUInt16BE(0) !== mapping.length - 2) throw new Error(`${label} must be a valid Mapping`);
}

/** Encrypts one 154-byte short-build request record using Noise_N_25519_ChaChaPoly_SHA256. */
export function encryptShortBuildRequestRecord(recipientIdentityHash: Buffer, recipientStaticPublicKey: Buffer, plaintext: Buffer, ephemeralPrivateKey?: Buffer): ShortBuildRecord {
  if (!Buffer.isBuffer(recipientIdentityHash) || recipientIdentityHash.length !== 32) throw new Error('Recipient identity hash must be 32 bytes');
  if (!Buffer.isBuffer(plaintext) || plaintext.length !== SHORT_BUILD_REQUEST_SIZE) throw new Error('Short-build request plaintext must be 154 bytes');
  const ephemeral = ephemeralPrivateKey ? privateX25519(ephemeralPrivateKey) : generateKeyPairSync('x25519').privateKey;
  const ephemeralPublicKey = rawPublicKey(createPublicKey(ephemeral));
  let { h, ck } = noiseInitialState(recipientStaticPublicKey);
  h = sha256(h, ephemeralPublicKey);
  const shared = diffieHellman({ privateKey: ephemeral, publicKey: publicX25519(recipientStaticPublicKey) });
  const mixed = mixKey(ck, shared);
  ck = mixed.ck;
  const encrypted = encryptAead(mixed.key, Buffer.alloc(12), h, plaintext);
  h = sha256(h, encrypted);
  const reply = deriveKey(mixed.ck, 'SMTunnelReplyKey');
  const layer = deriveKey(reply.ck, 'SMTunnelLayerKey');
  const isEndpoint = Boolean(plaintext[40]! & SHORT_BUILD_ENDPOINT_FLAG);
  const iv = isEndpoint ? deriveKey(layer.ck, 'TunnelLayerIVKey') : { ck: layer.ck, key: layer.ck };
  const garlic = isEndpoint ? deriveKey(iv.ck, 'RGarlicKeyAndTag') : undefined;
  const bytes = Buffer.alloc(SHORT_BUILD_RECORD_SIZE);
  recipientIdentityHash.copy(bytes, 0, 0, 16);
  ephemeralPublicKey.copy(bytes, 16);
  encrypted.copy(bytes, 48);
  const result = {
    ephemeralPublicKey, ciphertext: encrypted, bytes,
    replyKey: Buffer.from(reply.key), layerKey: Buffer.from(layer.key), ivKey: Buffer.from(iv.key), handshakeHash: Buffer.from(h),
    garlicReplyKey: garlic ? Buffer.from(garlic.key) : undefined,
    garlicReplyTag: garlic ? Buffer.from(garlic.ck.subarray(0, 8)) : undefined,
  };
  shared.fill(0); mixed.ck.fill(0); mixed.key.fill(0);
  reply.ck.fill(0); reply.key.fill(0); layer.ck.fill(0); layer.key.fill(0); iv.ck.fill(0); iv.key.fill(0);
  garlic?.ck.fill(0); garlic?.key.fill(0);
  return result;
}

/** Decrypts a local hop's short-build record and derives its reply/layer/IV keys. */
export function decryptShortBuildRequestRecord(record: Buffer, localIdentityHash: Buffer, staticPrivateKey: KeyObject, staticPublicKey: Buffer): DecryptedShortBuildRequest {
  if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Short-build record must be 218 bytes');
  if (!Buffer.isBuffer(localIdentityHash) || localIdentityHash.length !== 32 || !timingSafeEqual(record.subarray(0, 16), localIdentityHash.subarray(0, 16))) throw new Error('Short-build record is not addressed to this router');
  const ephemeralPublicKey = Buffer.from(record.subarray(16, 48));
  let { h, ck } = noiseInitialState(staticPublicKey);
  h = sha256(h, ephemeralPublicKey);
  const shared = diffieHellman({ privateKey: staticPrivateKey, publicKey: publicX25519(ephemeralPublicKey) });
  const mixed = mixKey(ck, shared);
  const encrypted = record.subarray(48);
  const raw = decryptAead(mixed.key, Buffer.alloc(12), h, encrypted);
  h = sha256(h, encrypted);
  if (raw.length !== SHORT_BUILD_REQUEST_SIZE) throw new Error('Short-build plaintext has an invalid length');
  const flags = raw[40]!;
  const reply = deriveKey(mixed.ck, 'SMTunnelReplyKey');
  const layer = deriveKey(reply.ck, 'SMTunnelLayerKey');
  const isEndpoint = Boolean(flags & SHORT_BUILD_ENDPOINT_FLAG);
  const iv = isEndpoint ? deriveKey(layer.ck, 'TunnelLayerIVKey') : { ck: layer.ck, key: layer.ck };
  const garlic = isEndpoint ? deriveKey(iv.ck, 'RGarlicKeyAndTag') : undefined;
  const result: DecryptedShortBuildRequest = {
    receiveTunnelId: raw.readUInt32BE(0), nextTunnelId: raw.readUInt32BE(4),
    nextIdentityHash: Buffer.from(raw.subarray(8, 40)), flags, layerEncryptionType: raw[43]!,
    requestTimeMinutes: raw.readUInt32BE(44), expirationSeconds: raw.readUInt32BE(48),
    nextMessageId: raw.readUInt32BE(52), optionsAndPadding: Buffer.from(raw.subarray(56)),
    replyKey: Buffer.from(reply.key), layerKey: Buffer.from(layer.key), ivKey: Buffer.from(iv.key),
    handshakeHash: Buffer.from(h), chainingKey: Buffer.from(iv.ck), raw: Buffer.from(raw),
    garlicReplyKey: garlic ? Buffer.from(garlic.key) : undefined,
    garlicReplyTag: garlic ? Buffer.from(garlic.ck.subarray(0, 8)) : undefined,
  };
  shared.fill(0); mixed.ck.fill(0); mixed.key.fill(0); raw.fill(0);
  reply.ck.fill(0); reply.key.fill(0); layer.ck.fill(0); layer.key.fill(0); iv.ck.fill(0); iv.key.fill(0);
  garlic?.ck.fill(0); garlic?.key.fill(0);
  return result;
}

/** Encodes and parses short tunnel build payloads. */
export function encodeShortTunnelBuildPayload(records: readonly Buffer[]): Buffer {
  if (records.length < 1 || records.length > SHORT_BUILD_MAX_RECORDS) throw new RangeError('Short Tunnel Build must contain 1..8 records');
  for (const record of records) if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Each Short Tunnel Build record must be 218 bytes');
  return Buffer.concat([Buffer.from([records.length]), ...records]);
}
export function parseShortTunnelBuildPayload(payload: Buffer): Buffer[] {
  if (!Buffer.isBuffer(payload) || payload.length < 1) throw new Error('Short Tunnel Build payload is truncated');
  const count = payload[0]!;
  if (count < 1 || count > SHORT_BUILD_MAX_RECORDS || payload.length !== 1 + count * SHORT_BUILD_RECORD_SIZE) throw new Error('Short Tunnel Build payload count or length is invalid');
  return Array.from({ length: count }, (_, index) => Buffer.from(payload.subarray(1 + index * SHORT_BUILD_RECORD_SIZE, 1 + (index + 1) * SHORT_BUILD_RECORD_SIZE)));
}

/** Encodes the 154-byte short-build plaintext request. */
export function encodeShortBuildRequestPlaintext(fields: ShortBuildRequestFields): Buffer {
  assertUInt32('receiveTunnelId', fields.receiveTunnelId);
  assertUInt32('nextTunnelId', fields.nextTunnelId);
  assertUInt32('nextMessageId', fields.nextMessageId);
  if (fields.receiveTunnelId === 0 || fields.nextTunnelId === 0) throw new RangeError('Tunnel IDs must be nonzero');
  if (!Buffer.isBuffer(fields.nextIdentityHash) || fields.nextIdentityHash.length !== 32) throw new Error('Next identity hash must be 32 bytes');
  if (!Number.isInteger(fields.flags) || fields.flags < 0 || fields.flags > 0xff || (fields.flags & 0x3f) !== 0 || (fields.flags & (SHORT_BUILD_ENDPOINT_FLAG | SHORT_BUILD_GATEWAY_FLAG)) === (SHORT_BUILD_ENDPOINT_FLAG | SHORT_BUILD_GATEWAY_FLAG)) throw new RangeError('Invalid ShortBuildRequestRecord flags');
  const layerEncryptionType = fields.layerEncryptionType ?? 0;
  if (layerEncryptionType !== 0) throw new RangeError('Only AES tunnel layer encryption is supported');
  const requestTimeMinutes = fields.requestTimeMinutes ?? Math.floor(Date.now() / 60_000);
  assertUInt32('requestTimeMinutes', requestTimeMinutes);
  const expirationSeconds = fields.expirationSeconds ?? 600;
  assertUInt32('expirationSeconds', expirationSeconds);
  if (expirationSeconds !== 600) throw new RangeError('Only the standardized 600-second tunnel expiration is supported');
  const optionsMapping = fields.optionsMapping ?? Buffer.alloc(2);
  validateMapping(optionsMapping, 98, 'Tunnel build options');
  const random = fields.random ?? randomBytes;
  const padding = random(SHORT_BUILD_REQUEST_SIZE - 56 - optionsMapping.length);
  if (!Buffer.isBuffer(padding) || padding.length !== SHORT_BUILD_REQUEST_SIZE - 56 - optionsMapping.length) throw new Error('Random source returned the wrong padding length');
  const output = Buffer.alloc(SHORT_BUILD_REQUEST_SIZE);
  output.writeUInt32BE(fields.receiveTunnelId, 0); output.writeUInt32BE(fields.nextTunnelId, 4);
  fields.nextIdentityHash.copy(output, 8); output[40] = fields.flags; output[43] = layerEncryptionType;
  output.writeUInt32BE(requestTimeMinutes, 44); output.writeUInt32BE(expirationSeconds, 48); output.writeUInt32BE(fields.nextMessageId, 52);
  optionsMapping.copy(output, 56); padding.copy(output, 56 + optionsMapping.length);
  return output;
}

/** Encodes the 202-byte plaintext response for a selected Short Tunnel Build hop. */
export function encodeShortBuildReplyPlaintext(returnCode: number, optionsMapping = Buffer.alloc(2), random: (size: number) => Buffer = randomBytes): Buffer {
  if (!Number.isInteger(returnCode) || returnCode < 0 || returnCode > 0xff) throw new RangeError('Tunnel build return code must be a byte');
  validateMapping(optionsMapping, 201, 'Tunnel build reply options');
  const paddingLength = SHORT_BUILD_REPLY_SIZE - optionsMapping.length - 1;
  const padding = random(paddingLength);
  if (!Buffer.isBuffer(padding) || padding.length !== paddingLength) throw new Error('Random source returned the wrong reply padding length');
  const output = Buffer.alloc(SHORT_BUILD_REPLY_SIZE);
  optionsMapping.copy(output, 0); padding.copy(output, optionsMapping.length); output[SHORT_BUILD_REPLY_SIZE - 1] = returnCode;
  return output;
}
export function parseShortBuildReplyPlaintext(plaintext: Buffer): ShortBuildReply {
  if (!Buffer.isBuffer(plaintext) || plaintext.length !== SHORT_BUILD_REPLY_SIZE) throw new Error('Short-build reply plaintext must be 202 bytes');
  const mappingLength = plaintext.readUInt16BE(0);
  if (mappingLength > SHORT_BUILD_REPLY_SIZE - 3 || mappingLength + 2 > SHORT_BUILD_REPLY_SIZE - 1) throw new Error('Short-build reply options exceed limits');
  const optionsMapping = Buffer.from(plaintext.subarray(0, mappingLength + 2));
  validateMapping(optionsMapping, 201, 'Tunnel build reply options');
  return { optionsMapping, returnCode: plaintext[SHORT_BUILD_REPLY_SIZE - 1]!, raw: Buffer.from(plaintext) };
}
function assertUInt32(label: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new RangeError(`${label} must be a uint32`);
}

/** Decrypts a hop's own AEAD-protected 218-byte Short Tunnel Build Reply record. */
export function decryptShortTunnelBuildReplyRecord(record: Buffer, recordIndex: number, replyKey: Buffer, handshakeHash: Buffer): Buffer {
  if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Short-build reply record must be 218 bytes');
  if (!Number.isInteger(recordIndex) || recordIndex < 0 || recordIndex >= SHORT_BUILD_MAX_RECORDS) throw new RangeError('Short-build reply record index is out of range');
  if (!Buffer.isBuffer(replyKey) || replyKey.length !== 32 || !Buffer.isBuffer(handshakeHash) || handshakeHash.length !== 32) throw new Error('Short-build reply keys must be 32 bytes');
  const nonce = Buffer.alloc(12); nonce[4] = recordIndex;
  return decryptAead(replyKey, nonce, handshakeHash, record);
}

/** Writes one hop's AEAD reply into its slot while keeping later unprocessed request records intact. */
export function encryptShortTunnelBuildTransitRequest(records: readonly Buffer[], selectedIndex: number, replyPlaintext: Buffer, replyKey: Buffer, handshakeHash: Buffer): Buffer[] {
  if (records.length < 1 || records.length > SHORT_BUILD_MAX_RECORDS || !Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= records.length) throw new Error('Invalid short-build transit record selection');
  if (!Buffer.isBuffer(replyPlaintext) || replyPlaintext.length !== SHORT_BUILD_REPLY_SIZE) throw new Error('Short-build reply plaintext must be 202 bytes');
  if (!Buffer.isBuffer(replyKey) || replyKey.length !== 32 || !Buffer.isBuffer(handshakeHash) || handshakeHash.length !== 32) throw new Error('Short-build reply keys must be 32 bytes');
  return records.map((record, index) => {
    if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Each Short Tunnel Build record must be 218 bytes');
    if (index !== selectedIndex) return Buffer.from(record);
    const nonce = Buffer.alloc(12); nonce[4] = index;
    return encryptAead(replyKey, nonce, handshakeHash, replyPlaintext);
  });
}

/** Removes/adds the ChaCha20 cover layer for every record except the hop's own AEAD record. */
export function transformShortBuildReplyCoverRecords(records: readonly Buffer[], selectedIndex: number, replyKey: Buffer): Buffer[] {
  if (records.length < 1 || records.length > SHORT_BUILD_MAX_RECORDS || !Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= records.length) throw new Error('Invalid short-build cover record selection');
  if (!Buffer.isBuffer(replyKey) || replyKey.length !== 32) throw new Error('Short-build reply key must be 32 bytes');
  return records.map((record, index) => {
    if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Each Short Tunnel Build record must be 218 bytes');
    if (index === selectedIndex) return Buffer.from(record);
    const nonce = Buffer.alloc(12); nonce[4] = index;
    const chachaIv = Buffer.alloc(16); chachaIv.writeUInt32LE(1, 0); nonce.copy(chachaIv, 4);
    const cipher = createCipheriv('chacha20', replyKey, chachaIv);
    return Buffer.concat([cipher.update(record), cipher.final()]);
  });
}

/** Encrypts a Short Tunnel Build Reply: AEAD for the selected record, ChaCha20 for cover records. */
export function encryptShortTunnelBuildReply(records: readonly Buffer[], selectedIndex: number, replyPlaintext: Buffer, replyKey: Buffer, handshakeHash: Buffer): Buffer[] {
  if (records.length < 1 || records.length > SHORT_BUILD_MAX_RECORDS || !Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= records.length) throw new Error('Invalid short-build reply record selection');
  if (!Buffer.isBuffer(replyPlaintext) || replyPlaintext.length !== SHORT_BUILD_REPLY_SIZE) throw new Error('Short-build reply plaintext must be 202 bytes');
  if (replyKey.length !== 32 || handshakeHash.length !== 32) throw new Error('Short-build reply keys must be 32 bytes');
  return records.map((record, index) => {
    if (!Buffer.isBuffer(record) || record.length !== SHORT_BUILD_RECORD_SIZE) throw new Error('Each Short Tunnel Build record must be 218 bytes');
    const nonce = Buffer.alloc(12); nonce[4] = index;
    if (index === selectedIndex) return encryptAead(replyKey, nonce, handshakeHash, replyPlaintext);
    const chachaIv = Buffer.alloc(16); chachaIv.writeUInt32LE(1, 0); nonce.copy(chachaIv, 4);
    const cipher = createCipheriv('chacha20', replyKey, chachaIv);
    return Buffer.concat([cipher.update(record), cipher.final()]);
  });
}

/** Creates an X25519 static public key from the raw identity encryption key bytes. */
export function x25519PublicKeyFromRaw(raw: Buffer): KeyObject { return publicX25519(raw); }
/** Creates an X25519 static private key from raw 32-byte private material. */
export function x25519PrivateKeyFromRaw(raw: Buffer): KeyObject { return privateX25519(raw); }
/** Extracts the raw 32-byte X25519 public key from a Node.js key object. */
export function x25519RawPublicKey(key: KeyObject): Buffer { return rawPublicKey(key); }
