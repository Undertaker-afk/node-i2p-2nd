import { createCipheriv, createDecipheriv } from 'node:crypto';
import type { I2npMessage } from '../protocol/i2np.ts';
import { I2NP_MAX_PAYLOAD } from '../protocol/i2np.ts';

const I2NP_GARLIC = 11;
const GARLIC_CLOVE_BLOCK = 11;
const MAX_GARLIC_CLOVE_PAYLOAD = 0xffff;

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
  if (!Number.isSafeInteger(expiration) || expiration < 0) throw new RangeError('Garlic expiration must be a non-negative safe integer');
  if (!Number.isInteger(messageId) || messageId < 0 || messageId > 0xffff_ffff) throw new RangeError('Garlic message ID must be a uint32');
  const expirationSeconds = Math.floor(expiration / 1000);
  if (expirationSeconds > 0xffff_ffff) throw new RangeError('Garlic inner expiration exceeds uint32 seconds');
  if (!Number.isInteger(message.type) || message.type < 0 || message.type > 0xff) throw new RangeError('Garlic inner I2NP type must be a byte');
  if (!Buffer.isBuffer(message.payload) || message.payload.length > MAX_GARLIC_CLOVE_PAYLOAD - 10) throw new RangeError('Garlic clove I2NP payload is too large');

  const cloveSize = 10 + message.payload.length;
  const plaintext = Buffer.allocUnsafe(3 + cloveSize);
  plaintext[0] = GARLIC_CLOVE_BLOCK;
  plaintext.writeUInt16BE(cloveSize, 1);
  plaintext[3] = 0; // LOCAL delivery
  plaintext[4] = message.type;
  plaintext.writeUInt32BE(messageId >>> 0, 5);
  plaintext.writeUInt32BE(expirationSeconds, 9);
  message.payload.copy(plaintext, 13);

  let ciphertext: Buffer;
  try {
    const cipher = createCipheriv('chacha20-poly1305', key, Buffer.alloc(12), { authTagLength: 16 });
    cipher.setAAD(replyTag, { plaintextLength: plaintext.length });
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  } finally { plaintext.fill(0); }
  const bodyLength = replyTag.length + ciphertext.length;
  if (4 + bodyLength > I2NP_MAX_PAYLOAD) throw new RangeError('Garlic Message exceeds I2NP payload size');
  const payload = Buffer.allocUnsafe(4 + bodyLength);
  payload.writeUInt32BE(bodyLength, 0);
  replyTag.copy(payload, 4);
  ciphertext.copy(payload, 12);
  return { type: I2NP_GARLIC, id: messageId >>> 0, expiration, payload };
}

/** Authenticates and parses the single LOCAL clove used by short-build replies. */
export function unwrapEciesExistingSessionGarlicMessage(message: I2npMessage, key: Buffer, expectedReplyTag: Buffer): I2npMessage {
  validateSessionMaterial(key, expectedReplyTag);
  if (message.type !== I2NP_GARLIC) throw new Error('Expected an I2NP Garlic Message');
  const payload = message.payload;
  if (!Buffer.isBuffer(payload) || payload.length < 4 + 8 + 16 + 3 + 10) throw new Error('Garlic Message payload is truncated');
  const bodyLength = payload.readUInt32BE(0);
  if (bodyLength !== payload.length - 4) throw new Error('Garlic Message length mismatch');
  const tag = payload.subarray(4, 12);
  if (!tag.equals(expectedReplyTag)) throw new Error('Garlic reply tag mismatch');
  const ciphertext = payload.subarray(12);
  if (ciphertext.length < 16) throw new Error('Garlic Message ciphertext is truncated');
  const decipher = createDecipheriv('chacha20-poly1305', key, Buffer.alloc(12), { authTagLength: 16 });
  decipher.setAAD(tag, { plaintextLength: ciphertext.length - 16 });
  decipher.setAuthTag(ciphertext.subarray(-16));
  const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  try {
    if (plaintext.length < 13 || plaintext[0] !== GARLIC_CLOVE_BLOCK) throw new Error('Unsupported Garlic payload block');
    const cloveSize = plaintext.readUInt16BE(1);
    if (cloveSize !== plaintext.length - 3 || cloveSize < 10) throw new Error('Garlic Clove block size mismatch');
    if (plaintext[3] !== 0) throw new Error('Short-build reply Garlic Clove must use LOCAL delivery');
    const expiration = plaintext.readUInt32BE(9) * 1000;
    if (expiration <= 0) throw new Error('Garlic Clove expiration is invalid');
    return {
      type: plaintext[4]!, id: plaintext.readUInt32BE(5), expiration,
      payload: Buffer.from(plaintext.subarray(13)),
    };
  } finally { plaintext.fill(0); }
}

function validateSessionMaterial(key: Buffer, replyTag: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Garlic reply key must be 32 bytes');
  if (!Buffer.isBuffer(replyTag) || replyTag.length !== 8) throw new Error('Garlic reply tag must be 8 bytes');
}
