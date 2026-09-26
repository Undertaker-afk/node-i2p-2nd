import type { I2npMessage } from '../../protocol/i2np.ts';
import { ByteReader } from '../../protocol/common.ts';

export type Ntcp2Block = { type: number; data: Buffer };
export const MAX_NTCP2_BLOCK_DATA = 65_516;

export function encodeNtcp2Block(block: Ntcp2Block): Buffer {
  if (!Number.isInteger(block.type) || block.type < 0 || block.type > 255) throw new RangeError('NTCP2 block type must be uint8');
  if (!Buffer.isBuffer(block.data) || block.data.length > MAX_NTCP2_BLOCK_DATA) throw new RangeError('NTCP2 block data exceeds 65516 bytes');
  const header = Buffer.allocUnsafe(3); header.writeUInt8(block.type, 0); header.writeUInt16BE(block.data.length, 1);
  return Buffer.concat([header, block.data]);
}

export function decodeNtcp2Blocks(plaintext: Buffer): Ntcp2Block[] {
  const reader = new ByteReader(plaintext, 65_519); const blocks: Ntcp2Block[] = [];
  while (reader.remaining) {
    if (reader.remaining < 3) throw new Error('Truncated NTCP2 block header');
    const type = reader.readUInt8(); const length = reader.readUInt16();
    blocks.push({ type, data: Buffer.from(reader.readBytes(length)) });
  }
  return blocks;
}

/** I2NP blocks carry type, message ID, and expiration seconds, followed by raw I2NP payload. */
export function encodeI2npBlock(message: I2npMessage): Ntcp2Block {
  if (!Number.isSafeInteger(message.expiration) || message.expiration < 0) throw new RangeError('I2NP expiration must be non-negative');
  const seconds = Math.floor(message.expiration / 1000);
  if (seconds > 0xffff_ffff) throw new RangeError('I2NP expiration is outside NTCP2 short-header range');
  if (!Number.isInteger(message.type) || message.type < 0 || message.type > 255 || !Number.isInteger(message.id) || message.id < 0 || message.id > 0xffff_ffff) throw new RangeError('Invalid I2NP type or ID');
  const header = Buffer.allocUnsafe(9); header[0] = message.type; header.writeUInt32BE(message.id, 1); header.writeUInt32BE(seconds, 5);
  return { type: 3, data: Buffer.concat([header, message.payload]) };
}

export function decodeI2npBlock(block: Ntcp2Block): I2npMessage {
  if (block.type !== 3) throw new Error(`Expected NTCP2 I2NP block type 3, got ${block.type}`);
  if (block.data.length < 9) throw new Error('NTCP2 I2NP block is shorter than its 9-byte header');
  const expiration = block.data.readUInt32BE(5) * 1000;
  return { type: block.data.readUInt8(0), id: block.data.readUInt32BE(1), expiration, payload: Buffer.from(block.data.subarray(9)) };
}
