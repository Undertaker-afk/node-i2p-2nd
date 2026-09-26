import { createCipheriv, createDecipheriv } from 'node:crypto';
import { encodeNtcp2Block, decodeNtcp2Blocks, type Ntcp2Block } from './blocks.ts';
import { SipHashLengthCipher, type SipHashKeys } from './siphash.ts';

const MAX_FRAME_PLAINTEXT = 65_519;
const MAX_NONCE = 0xffff_ffff_ffff_fffen;
function nonce(counter: bigint): Buffer { const value = Buffer.alloc(12); value.writeBigUInt64LE(counter, 4); return value; }
function encodeBlocks(blocks: readonly Ntcp2Block[]): Buffer {
  const chunks = blocks.map(encodeNtcp2Block);
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  if (total > MAX_FRAME_PLAINTEXT) throw new RangeError('NTCP2 frame plaintext exceeds 65519 bytes');
  return Buffer.concat(chunks, total);
}

/** NTCP2 authenticated data-phase codec with independent directional AEAD and length states. */
export class Ntcp2DataCipher {
  private readonly sendLength: SipHashLengthCipher;
  private readonly receiveLength: SipHashLengthCipher;
  private sendNonce = 0n;
  private receiveNonce = 0n;
  private incoming = Buffer.alloc(0);
  private expectedIncomingLength: number | undefined;
  private destroyed = false;
  private readonly sendKey: Buffer;
  private readonly receiveKey: Buffer;

  constructor(sendKey: Buffer, receiveKey: Buffer, sendLengthKeys: SipHashKeys, receiveLengthKeys: SipHashKeys) {
    if (sendKey.length !== 32 || receiveKey.length !== 32) throw new Error('NTCP2 data keys must be 32 bytes');
    this.sendKey = Buffer.from(sendKey); this.receiveKey = Buffer.from(receiveKey);
    this.sendLength = new SipHashLengthCipher(sendLengthKeys);
    this.receiveLength = new SipHashLengthCipher(receiveLengthKeys);
  }

  seal(blocks: readonly Ntcp2Block[]): Buffer {
    if (this.destroyed) throw new Error('NTCP2 data cipher is destroyed');
    if (this.sendNonce > MAX_NONCE) throw new Error('NTCP2 send nonce exhausted; reconnect required');
    const plaintext = encodeBlocks(blocks);
    const cipher = createCipheriv('chacha20-poly1305', this.sendKey, nonce(this.sendNonce), { authTagLength: 16 });
    cipher.setAAD(Buffer.alloc(0), { plaintextLength: plaintext.length });
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    const prefix = Buffer.allocUnsafe(2); prefix.writeUInt16BE(this.sendLength.encode(encrypted.length));
    this.sendNonce++;
    return Buffer.concat([prefix, encrypted]);
  }

  /** Accepts arbitrary TCP fragments; yields decoded blocks for each complete authenticated frame. */
  push(chunk: Buffer): Ntcp2Block[][] {
    if (this.destroyed) throw new Error('NTCP2 data cipher is destroyed');
    if (!Buffer.isBuffer(chunk)) throw new TypeError('NTCP2 input chunk must be a Buffer');
    const frames: Ntcp2Block[][] = []; let offset = 0;
    while (offset < chunk.length || (this.expectedIncomingLength !== undefined && this.incoming.length === this.expectedIncomingLength + 2)) {
      if (this.expectedIncomingLength === undefined) {
        const count = Math.min(2 - this.incoming.length, chunk.length - offset);
        if (count > 0) { this.incoming = Buffer.concat([this.incoming, chunk.subarray(offset, offset + count)]); offset += count; }
        if (this.incoming.length < 2) break;
        this.expectedIncomingLength = this.receiveLength.decode(this.incoming.readUInt16BE(0));
      }
      const totalLength = this.expectedIncomingLength + 2;
      const count = Math.min(totalLength - this.incoming.length, chunk.length - offset);
      if (count > 0) { this.incoming = Buffer.concat([this.incoming, chunk.subarray(offset, offset + count)]); offset += count; }
      if (this.incoming.length < totalLength) break;
      if (this.receiveNonce > MAX_NONCE) throw new Error('NTCP2 receive nonce exhausted; reconnect required');
      const frame = this.incoming.subarray(2);
      const decipher = createDecipheriv('chacha20-poly1305', this.receiveKey, nonce(this.receiveNonce), { authTagLength: 16 });
      decipher.setAAD(Buffer.alloc(0), { plaintextLength: frame.length - 16 });
      decipher.setAuthTag(frame.subarray(-16));
      const plaintext = Buffer.concat([decipher.update(frame.subarray(0, -16)), decipher.final()]);
      frames.push(decodeNtcp2Blocks(plaintext)); this.receiveNonce++;
      this.incoming = Buffer.alloc(0); this.expectedIncomingLength = undefined;
    }
    return frames;
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true; this.sendKey.fill(0); this.receiveKey.fill(0); this.incoming.fill(0);
    this.sendLength.destroy(); this.receiveLength.destroy(); this.incoming = Buffer.alloc(0); this.expectedIncomingLength = undefined;
  }
}
