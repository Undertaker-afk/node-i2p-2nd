import { decodeI2np, encodeI2np, type I2npMessage } from '../protocol/i2np.ts';
import { TUNNEL_MESSAGE_SIZE } from './data.ts';

export type TunnelDataPayload = { tunnelId: number; message: Buffer };
export type TunnelGatewayPayload = { tunnelId: number; message: I2npMessage };

function validateTunnelId(tunnelId: number): void {
  if (!Number.isSafeInteger(tunnelId) || tunnelId < 1 || tunnelId > 0xffff_ffff) throw new RangeError('Tunnel ID must be a nonzero uint32');
}

/** Decodes the I2NP TunnelData payload: tunnel ID followed by one fixed 1024-byte tunnel message. */
export function decodeTunnelDataPayload(payload: Buffer): TunnelDataPayload {
  if (!Buffer.isBuffer(payload) || payload.length !== 4 + TUNNEL_MESSAGE_SIZE) throw new Error('TunnelData payload must contain a 4-byte ID and 1024-byte message');
  const tunnelId = payload.readUInt32BE(0);
  validateTunnelId(tunnelId);
  return { tunnelId, message: Buffer.from(payload.subarray(4)) };
}

export function encodeTunnelDataPayload(tunnelId: number, message: Buffer): Buffer {
  validateTunnelId(tunnelId);
  if (!Buffer.isBuffer(message) || message.length !== TUNNEL_MESSAGE_SIZE) throw new Error('Tunnel message must be exactly 1024 bytes');
  const output = Buffer.allocUnsafe(4 + TUNNEL_MESSAGE_SIZE);
  output.writeUInt32BE(tunnelId, 0);
  message.copy(output, 4);
  return output;
}

/** Decodes I2NP TunnelGateway: tunnel ID, 2-byte encapsulated-message length, and full I2NP packet. */
export function decodeTunnelGatewayPayload(payload: Buffer): TunnelGatewayPayload {
  if (!Buffer.isBuffer(payload) || payload.length < 4 + 2 + 16) throw new Error('TunnelGateway payload is truncated');
  const tunnelId = payload.readUInt32BE(0);
  validateTunnelId(tunnelId);
  const length = payload.readUInt16BE(4);
  if (length !== payload.length - 6) throw new Error('TunnelGateway encapsulated-message length mismatch');
  return { tunnelId, message: decodeI2np(payload.subarray(6)) };
}

export function encodeTunnelGatewayPayload(tunnelId: number, message: I2npMessage): Buffer {
  validateTunnelId(tunnelId);
  const encoded = encodeI2np(message);
  if (encoded.length > 0xffff) throw new RangeError('Encapsulated I2NP message exceeds TunnelGateway uint16 size');
  const output = Buffer.allocUnsafe(6 + encoded.length);
  output.writeUInt32BE(tunnelId, 0);
  output.writeUInt16BE(encoded.length, 4);
  encoded.copy(output, 6);
  return output;
}
