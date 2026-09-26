import { createCipheriv, createDecipheriv } from 'node:crypto';

export const TUNNEL_MESSAGE_SIZE = 1024;
export const TUNNEL_IV_SIZE = 16;
export const TUNNEL_DATA_SIZE = TUNNEL_MESSAGE_SIZE - TUNNEL_IV_SIZE;

function validateKey(name: string, key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error(`${name} must be a 32-byte AES-256 key`);
}
function aesEcbEncrypt(block: Buffer, key: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

/**
 * Applies the AES tunnel participant transformation to one 1024-byte tunnel message.
 * Participants encrypt the data layer and double-encrypt the IV before forwarding.
 */
export function processTunnelDataLayer(message: Buffer, layerKey: Buffer, ivKey: Buffer): Buffer {
  if (!Buffer.isBuffer(message) || message.length !== TUNNEL_MESSAGE_SIZE) throw new Error('Tunnel message must be exactly 1024 bytes');
  validateKey('Tunnel layer key', layerKey);
  validateKey('Tunnel IV key', ivKey);
  const incomingIv = message.subarray(0, TUNNEL_IV_SIZE);
  const currentIv = aesEcbEncrypt(incomingIv, ivKey);
  const cipher = createCipheriv('aes-256-cbc', layerKey, currentIv);
  cipher.setAutoPadding(false);
  const encryptedLayer = Buffer.concat([cipher.update(message.subarray(TUNNEL_IV_SIZE)), cipher.final()]);
  const nextIv = aesEcbEncrypt(currentIv, ivKey);
  const output = Buffer.allocUnsafe(TUNNEL_MESSAGE_SIZE);
  nextIv.copy(output, 0);
  encryptedLayer.copy(output, TUNNEL_IV_SIZE);
  return output;
}

/** Unwraps one AES layer at an outbound gateway using the inverse participant transform. */
export function removeTunnelDataLayer(message: Buffer, layerKey: Buffer, ivKey: Buffer): Buffer {
  if (!Buffer.isBuffer(message) || message.length !== TUNNEL_MESSAGE_SIZE) throw new Error('Tunnel message must be exactly 1024 bytes');
  validateKey('Tunnel layer key', layerKey);
  validateKey('Tunnel IV key', ivKey);
  const outgoingIv = message.subarray(0, TUNNEL_IV_SIZE);
  const priorIv = createDecipheriv('aes-256-ecb', ivKey, null);
  priorIv.setAutoPadding(false);
  const currentIv = Buffer.concat([priorIv.update(outgoingIv), priorIv.final()]);
  const priorIvCipher = createDecipheriv('aes-256-ecb', ivKey, null);
  priorIvCipher.setAutoPadding(false);
  const originalIv = Buffer.concat([priorIvCipher.update(currentIv), priorIvCipher.final()]);
  const decipher = createDecipheriv('aes-256-cbc', layerKey, currentIv);
  decipher.setAutoPadding(false);
  const ciphertext = decipher.update(message.subarray(TUNNEL_IV_SIZE));
  const data = Buffer.concat([ciphertext, decipher.final()]);
  const output = Buffer.allocUnsafe(TUNNEL_MESSAGE_SIZE);
  originalIv.copy(output, 0);
  data.copy(output, TUNNEL_IV_SIZE);
  data.fill(0);
  return output;
}

/**
 * Preprocesses an outbound tunnel gateway message by applying inverse hop transforms
 * from the final endpoint back to the first hop. Each remote router then applies its
 * normal participant transform, revealing the original message at the OBEP.
 */
export function preprocessOutboundTunnelMessage(
  message: Buffer,
  layerKeys: readonly { layerKey: Buffer; ivKey: Buffer }[],
): Buffer {
  if (!Array.isArray(layerKeys) || layerKeys.length < 1 || layerKeys.length > 8) throw new RangeError('Outbound tunnel requires 1..8 layer-key pairs');
  let output: Buffer<ArrayBufferLike> = Buffer.from(message);
  try {
    for (let index = layerKeys.length - 1; index >= 0; index--) {
      const keys = layerKeys[index]!;
      const unwrapped = removeTunnelDataLayer(output, keys.layerKey, keys.ivKey);
      output.fill(0); output = unwrapped;
    }
    return output;
  } catch (error) { output.fill(0); throw error; }
}
