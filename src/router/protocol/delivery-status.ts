import type { I2npMessage } from './i2np.ts';

/** I2NP DeliveryStatus (type 10). Also used for tunnel testing as of API 0.9.68. */
export const I2NP_DELIVERY_STATUS = 10;
export const DELIVERY_STATUS_LENGTH = 12;

export type DeliveryStatus = {
  messageId: number;
  timestamp: number;
};

function assertMessageId(messageId: number): void {
  if (!Number.isInteger(messageId) || messageId < 0 || messageId > 0xffff_ffff) throw new RangeError('DeliveryStatus message ID must be a uint32');
}

function assertTimestamp(timestamp: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new RangeError('DeliveryStatus timestamp must be a non-negative safe integer');
}

/** Encodes the 12-byte DeliveryStatus payload: 4-byte message ID + 8-byte Date. */
export function encodeDeliveryStatus(status: DeliveryStatus): Buffer {
  assertMessageId(status.messageId);
  assertTimestamp(status.timestamp);
  const payload = Buffer.allocUnsafe(DELIVERY_STATUS_LENGTH);
  payload.writeUInt32BE(status.messageId >>> 0, 0);
  payload.writeBigUInt64BE(BigInt(status.timestamp), 4);
  return payload;
}

export function parseDeliveryStatus(payload: Buffer): DeliveryStatus {
  if (!Buffer.isBuffer(payload) || payload.length !== DELIVERY_STATUS_LENGTH) throw new Error('DeliveryStatus payload must be exactly 12 bytes');
  const timestampBig = payload.readBigUInt64BE(4);
  if (timestampBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('DeliveryStatus timestamp exceeds safe integer range');
  return { messageId: payload.readUInt32BE(0), timestamp: Number(timestampBig) };
}

export function createDeliveryStatusMessage(status: DeliveryStatus, options: { id?: number; expiration?: number } = {}): I2npMessage {
  const id = options.id ?? status.messageId;
  assertMessageId(id);
  const expiration = options.expiration ?? Date.now() + 60_000;
  assertTimestamp(expiration);
  return { type: I2NP_DELIVERY_STATUS, id: id >>> 0, expiration, payload: encodeDeliveryStatus(status) };
}
