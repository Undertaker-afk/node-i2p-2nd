import { createPublicKey, randomBytes, type KeyObject } from 'node:crypto';
import type { I2npMessage } from '../protocol/i2np.ts';
import { I2NP_MAX_PAYLOAD } from '../protocol/i2np.ts';
import {
  decryptAead, encryptAead, generateX25519KeyPair, mixKey, rawPublicKey, sha256, x25519SharedSecret,
} from '../crypto/x25519.ts';

export const I2NP_GARLIC = 11;
export const GARLIC_DATETIME_BLOCK = 0;
export const GARLIC_CLOVE_BLOCK = 11;
export const GARLIC_PADDING_BLOCK = 254;
const MAX_GARLIC_CLOVE_PAYLOAD = 0xffff;
const NOISE_N_PROTOCOL = Buffer.from('Noise_N_25519_ChaChaPoly_SHA256', 'ascii');

export type GarlicDelivery =
  | { type: 'local' }
  | { type: 'destination'; hash: Buffer }
  | { type: 'router'; hash: Buffer }
  | { type: 'tunnel'; tunnelId: number; gatewayHash: Buffer };

export type GarlicClove = { delivery: GarlicDelivery; message: I2npMessage };

export function encodeGarlicCloveDelivery(delivery: GarlicDelivery): Buffer {
  if (delivery.type === 'local') return Buffer.from([0]);
  if (delivery.type === 'destination') {
    if (!Buffer.isBuffer(delivery.hash) || delivery.hash.length !== 32) throw new Error('Destination hash must be 32 bytes');
    return Buffer.concat([Buffer.from([0x20]), delivery.hash]);
  }
  if (delivery.type === 'router') {
    if (!Buffer.isBuffer(delivery.hash) || delivery.hash.length !== 32) throw new Error('Router hash must be 32 bytes');
    return Buffer.concat([Buffer.from([0x40]), delivery.hash]);
  }
  if (!Number.isSafeInteger(delivery.tunnelId) || delivery.tunnelId < 1 || delivery.tunnelId > 0xffff_ffff) throw new RangeError('Tunnel ID must be a nonzero uint32');
  if (!Buffer.isBuffer(delivery.gatewayHash) || delivery.gatewayHash.length !== 32) throw new Error('Tunnel gateway hash must be 32 bytes');
  const header = Buffer.allocUnsafe(37);
  header[0] = 0x60;
  header.writeUInt32BE(delivery.tunnelId, 1);
  delivery.gatewayHash.copy(header, 5);
  return header;
}

export function parseGarlicCloveDelivery(bytes: Buffer): { delivery: GarlicDelivery; size: number } {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1) throw new Error('Garlic delivery instructions are truncated');
  const flags = bytes[0]!;
  const kind = (flags >>> 5) & 3;
  if ((flags & 0x1f) !== 0) throw new Error('Unsupported Garlic delivery flags');
  if (kind === 0) return { delivery: { type: 'local' }, size: 1 };
  if (kind === 1) {
    if (bytes.length < 33) throw new Error('Destination delivery hash is truncated');
    return { delivery: { type: 'destination', hash: Buffer.from(bytes.subarray(1, 33)) }, size: 33 };
  }
  if (kind === 2) {
    if (bytes.length < 33) throw new Error('Router delivery hash is truncated');
    return { delivery: { type: 'router', hash: Buffer.from(bytes.subarray(1, 33)) }, size: 33 };
  }
  if (bytes.length < 37) throw new Error('Tunnel delivery instruction is truncated');
  const tunnelId = bytes.readUInt32BE(1);
  if (tunnelId === 0) throw new Error('Tunnel delivery ID must be nonzero');
  return { delivery: { type: 'tunnel', tunnelId, gatewayHash: Buffer.from(bytes.subarray(5, 37)) }, size: 37 };
}

export function encodeGarlicCloveBlock(clove: GarlicClove): Buffer {
  const delivery = encodeGarlicCloveDelivery(clove.delivery);
  const expirationSeconds = Math.floor(clove.message.expiration / 1000);
  if (expirationSeconds < 0 || expirationSeconds > 0xffff_ffff) throw new RangeError('Garlic clove expiration exceeds uint32 seconds');
  if (!Number.isInteger(clove.message.type) || clove.message.type < 0 || clove.message.type > 0xff) throw new RangeError('Garlic clove I2NP type must be a byte');
  if (!Number.isInteger(clove.message.id) || clove.message.id < 0 || clove.message.id > 0xffff_ffff) throw new RangeError('Garlic clove I2NP ID must be a uint32');
  if (!Buffer.isBuffer(clove.message.payload) || clove.message.payload.length > MAX_GARLIC_CLOVE_PAYLOAD - delivery.length - 9) throw new RangeError('Garlic clove I2NP payload is too large');
  const innerLength = delivery.length + 9 + clove.message.payload.length;
  const block = Buffer.allocUnsafe(3 + innerLength);
  block[0] = GARLIC_CLOVE_BLOCK;
  block.writeUInt16BE(innerLength, 1);
  delivery.copy(block, 3);
  const offset = 3 + delivery.length;
  block[offset] = clove.message.type;
  block.writeUInt32BE(clove.message.id >>> 0, offset + 1);
  block.writeUInt32BE(expirationSeconds, offset + 5);
  clove.message.payload.copy(block, offset + 9);
  return block;
}

export function encodeDateTimeBlock(timestampSeconds = Math.floor(Date.now() / 1000)): Buffer {
  if (!Number.isInteger(timestampSeconds) || timestampSeconds < 0 || timestampSeconds > 0xffff_ffff) throw new RangeError('DateTime timestamp must be a uint32');
  const block = Buffer.allocUnsafe(7);
  block[0] = GARLIC_DATETIME_BLOCK;
  block.writeUInt16BE(4, 1);
  block.writeUInt32BE(timestampSeconds, 3);
  return block;
}

export function encodePaddingBlock(size = randomBytes(1)[0]! & 0x0f): Buffer {
  if (!Number.isInteger(size) || size < 0 || size > 255) throw new RangeError('Garlic padding size is out of range');
  const block = Buffer.alloc(3 + size);
  block[0] = GARLIC_PADDING_BLOCK;
  block.writeUInt16BE(size, 1);
  if (size) randomBytes(size).copy(block, 3);
  return block;
}

export function parseGarlicPayloadBlocks(plaintext: Buffer): { datetime?: number; cloves: GarlicClove[] } {
  if (!Buffer.isBuffer(plaintext) || plaintext.length < 7) throw new Error('Garlic payload is truncated');
  const cloves: GarlicClove[] = [];
  let offset = 0;
  let datetime: number | undefined;
  while (offset < plaintext.length) {
    if (offset + 3 > plaintext.length) throw new Error('Truncated Garlic payload block');
    const type = plaintext[offset]!;
    const size = plaintext.readUInt16BE(offset + 1);
    if (offset + 3 + size > plaintext.length) throw new Error('Garlic payload block length exceeds buffer');
    const data = plaintext.subarray(offset + 3, offset + 3 + size);
    if (type === GARLIC_DATETIME_BLOCK) {
      if (size !== 4) throw new Error('DateTime block must contain a 4-byte timestamp');
      datetime = data.readUInt32BE(0);
    } else if (type === GARLIC_CLOVE_BLOCK) {
      cloves.push(parseGarlicCloveBody(data));
    } else if (type === GARLIC_PADDING_BLOCK) {
      if (offset + 3 + size !== plaintext.length) throw new Error('Garlic padding must be the final payload block');
    } else if (type !== 5) {
      throw new Error(`Unsupported Garlic payload block type ${type}`);
    }
    offset += 3 + size;
  }
  return datetime === undefined ? { cloves } : { datetime, cloves };
}

function parseGarlicCloveBody(data: Buffer): GarlicClove {
  const parsed = parseGarlicCloveDelivery(data);
  const headerOffset = parsed.size;
  if (data.length < headerOffset + 9) throw new Error('Garlic clove I2NP header is truncated');
  const expiration = data.readUInt32BE(headerOffset + 5) * 1000;
  if (expiration <= 0) throw new Error('Garlic clove expiration is invalid');
  return {
    delivery: parsed.delivery,
    message: {
      type: data[headerOffset]!,
      id: data.readUInt32BE(headerOffset + 1),
      expiration,
      payload: Buffer.from(data.subarray(headerOffset + 9)),
    },
  };
}

function encodeLocalClovePlaintext(message: I2npMessage, messageId: number, expirationSeconds: number): Buffer {
  return encodeGarlicCloveBlock({
    delivery: { type: 'local' },
    message: { type: message.type, id: messageId, expiration: expirationSeconds * 1000, payload: message.payload },
  });
}

/** Wraps one I2NP message as an ECIES-router Garlic Message using a one-time existing-session key/tag. */
export function wrapEciesExistingSessionGarlicMessage(
  message: I2npMessage,
  key: Buffer,
  replyTag: Buffer,
  options: { messageId?: number; expiration?: number } = {},
): I2npMessage {
  validateSessionMaterial(key, replyTag);
  const expiration = options.expiration ?? message.expiration;
  const messageId = options.messageId ?? message.id;
  validateMessageMeta(message, messageId, expiration);
  const expirationSeconds = Math.floor(expiration / 1000);
  const plaintext = encodeLocalClovePlaintext(message, messageId, expirationSeconds);
  let ciphertext: Buffer;
  try { ciphertext = encryptAead(key, Buffer.alloc(12), replyTag, plaintext); }
  finally { plaintext.fill(0); }
  return encodeGarlicEnvelope(ciphertext, replyTag, messageId, expiration);
}

/** Authenticates and parses the single LOCAL clove used by short-build replies. */
export function unwrapEciesExistingSessionGarlicMessage(message: I2npMessage, key: Buffer, expectedReplyTag: Buffer): I2npMessage {
  validateSessionMaterial(key, expectedReplyTag);
  const body = decodeGarlicBody(message);
  if (body.length < 8 + 16) throw new Error('Garlic Message payload is truncated');
  const tag = body.subarray(0, 8);
  if (!tag.equals(expectedReplyTag)) throw new Error('Garlic reply tag mismatch');
  const plaintext = decryptAead(key, Buffer.alloc(12), tag, body.subarray(8));
  try {
    const parsed = parseGarlicPayloadBlocks(plaintext);
    if (parsed.cloves.length !== 1 || parsed.cloves[0]!.delivery.type !== 'local') throw new Error('Short-build reply Garlic Clove must use LOCAL delivery');
    return parsed.cloves[0]!.message;
  } finally { plaintext.fill(0); }
}

function noiseNState(recipientStaticPublicKey: Buffer): { h: Buffer; ck: Buffer } {
  if (!Buffer.isBuffer(recipientStaticPublicKey) || recipientStaticPublicKey.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  const paddedName = Buffer.alloc(32);
  NOISE_N_PROTOCOL.copy(paddedName);
  return { h: sha256(sha256(paddedName), recipientStaticPublicKey), ck: Buffer.from(paddedName) };
}

/**
 * Wraps one I2NP message as a Noise_N new-session Garlic Message to an ECIES router.
 * Used to hide inbound ShortTunnelBuild messages from the paired outbound endpoint.
 */
export function wrapEciesRouterGarlicMessage(
  message: I2npMessage,
  recipientStaticPublicKey: Buffer,
  options: { messageId?: number; expiration?: number; timestampSeconds?: number; ephemeralPrivateKey?: KeyObject } = {},
): I2npMessage {
  const expiration = options.expiration ?? message.expiration;
  const messageId = options.messageId ?? message.id;
  validateMessageMeta(message, messageId, expiration);
  const ephemeral = options.ephemeralPrivateKey
    ? { privateKey: options.ephemeralPrivateKey, publicKey: rawPublicKey(createPublicKey(options.ephemeralPrivateKey)) }
    : generateX25519KeyPair();
  const ephemeralPublicKey = ephemeral.publicKey;
  let { h, ck } = noiseNState(recipientStaticPublicKey);
  h = sha256(h, ephemeralPublicKey);
  const shared = x25519SharedSecret(ephemeral.privateKey, recipientStaticPublicKey);
  const mixed = mixKey(ck, shared);
  const plaintext = Buffer.concat([
    encodeDateTimeBlock(options.timestampSeconds ?? Math.floor(Date.now() / 1000)),
    encodeLocalClovePlaintext(message, messageId, Math.floor(expiration / 1000)),
    encodePaddingBlock(),
  ]);
  let ciphertext: Buffer;
  try { ciphertext = encryptAead(mixed.key, Buffer.alloc(12), h, plaintext); }
  finally { plaintext.fill(0); shared.fill(0); mixed.ck.fill(0); mixed.key.fill(0); }
  const body = Buffer.concat([ephemeralPublicKey, ciphertext]);
  return encodeGarlicEnvelope(body, undefined, messageId, expiration);
}

/** Decrypts a Noise_N Garlic Message addressed to this router's X25519 static key. */
export function unwrapEciesRouterGarlicMessage(
  message: I2npMessage,
  staticPrivateKey: KeyObject,
  staticPublicKey: Buffer,
  options: { nowSeconds?: number; maxClockSkewSeconds?: number } = {},
): { datetime: number; cloves: GarlicClove[]; ephemeralPublicKey: Buffer } {
  const body = decodeGarlicBody(message);
  if (body.length < 32 + 16 + 7) throw new Error('Router Garlic Message is truncated');
  const ephemeralPublicKey = Buffer.from(body.subarray(0, 32));
  let { h, ck } = noiseNState(staticPublicKey);
  h = sha256(h, ephemeralPublicKey);
  const shared = x25519SharedSecret(staticPrivateKey, ephemeralPublicKey);
  const mixed = mixKey(ck, shared);
  let plaintext: Buffer;
  try { plaintext = decryptAead(mixed.key, Buffer.alloc(12), h, body.subarray(32)); }
  finally { shared.fill(0); mixed.ck.fill(0); mixed.key.fill(0); }
  try {
    const parsed = parseGarlicPayloadBlocks(plaintext);
    if (parsed.datetime === undefined) throw new Error('Router Garlic Message is missing a DateTime block');
    const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    const skew = options.maxClockSkewSeconds ?? 120;
    if (Math.abs(nowSeconds - parsed.datetime) > skew) throw new Error('Router Garlic DateTime is outside accepted clock skew');
    if (parsed.cloves.length < 1) throw new Error('Router Garlic Message contains no cloves');
    return { datetime: parsed.datetime, cloves: parsed.cloves, ephemeralPublicKey };
  } finally { plaintext.fill(0); }
}

function encodeGarlicEnvelope(body: Buffer, prefix: Buffer | undefined, messageId: number, expiration: number): I2npMessage {
  const content = prefix ? Buffer.concat([prefix, body]) : body;
  if (4 + content.length > I2NP_MAX_PAYLOAD) throw new RangeError('Garlic Message exceeds I2NP payload size');
  const payload = Buffer.allocUnsafe(4 + content.length);
  payload.writeUInt32BE(content.length, 0);
  content.copy(payload, 4);
  return { type: I2NP_GARLIC, id: messageId >>> 0, expiration, payload };
}

function decodeGarlicBody(message: I2npMessage): Buffer {
  if (message.type !== I2NP_GARLIC) throw new Error('Expected an I2NP Garlic Message');
  const payload = message.payload;
  if (!Buffer.isBuffer(payload) || payload.length < 4) throw new Error('Garlic Message payload is truncated');
  const bodyLength = payload.readUInt32BE(0);
  if (bodyLength !== payload.length - 4) throw new Error('Garlic Message length mismatch');
  return payload.subarray(4);
}

function validateSessionMaterial(key: Buffer, replyTag: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Garlic reply key must be 32 bytes');
  if (!Buffer.isBuffer(replyTag) || replyTag.length !== 8) throw new Error('Garlic reply tag must be 8 bytes');
}

function validateMessageMeta(message: I2npMessage, messageId: number, expiration: number): void {
  if (!Number.isSafeInteger(expiration) || expiration < 0) throw new RangeError('Garlic expiration must be a non-negative safe integer');
  if (!Number.isInteger(messageId) || messageId < 0 || messageId > 0xffff_ffff) throw new RangeError('Garlic message ID must be a uint32');
  if (Math.floor(expiration / 1000) > 0xffff_ffff) throw new RangeError('Garlic inner expiration exceeds uint32 seconds');
  if (!Number.isInteger(message.type) || message.type < 0 || message.type > 0xff) throw new RangeError('Garlic inner I2NP type must be a byte');
  if (!Buffer.isBuffer(message.payload) || message.payload.length > MAX_GARLIC_CLOVE_PAYLOAD - 10) throw new RangeError('Garlic clove I2NP payload is too large');
}
