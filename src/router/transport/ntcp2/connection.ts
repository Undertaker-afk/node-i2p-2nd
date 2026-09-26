import { EventEmitter } from 'node:events';
import type { Duplex } from 'node:stream';
import { decodeI2npBlock, encodeI2npBlock, encodeNtcp2Block, type Ntcp2Block } from './blocks.ts';
import { Ntcp2DataCipher } from './data-cipher.ts';
import type { I2npMessage } from '../../protocol/i2np.ts';

const DEFAULT_MAX_PENDING_BYTES = 4 * 1024 * 1024;

/** Established NTCP2 data-phase connection; handshake construction is provided separately. */
export class Ntcp2Connection extends EventEmitter {
  private closed = false;
  private pendingBytes = 0;
  private sendChain: Promise<void> = Promise.resolve();
  private readonly socket: Duplex;
  private readonly cipher: Ntcp2DataCipher;
  private readonly maxPendingBytes: number;
  readonly remoteIdentityHash: Buffer | undefined;
  constructor(socket: Duplex, cipher: Ntcp2DataCipher, maxPendingBytes = DEFAULT_MAX_PENDING_BYTES, remoteIdentityHash?: Buffer) {
    super();
    this.socket = socket; this.cipher = cipher; this.maxPendingBytes = maxPendingBytes;
    if (remoteIdentityHash !== undefined && (!Buffer.isBuffer(remoteIdentityHash) || remoteIdentityHash.length !== 32)) throw new Error('remoteIdentityHash must be 32 bytes');
    this.remoteIdentityHash = remoteIdentityHash ? Buffer.from(remoteIdentityHash) : undefined;
    if (!Number.isSafeInteger(maxPendingBytes) || maxPendingBytes < 18) throw new RangeError('maxPendingBytes must be at least one minimum NTCP2 frame');
    socket.on('data', chunk => this.onData(Buffer.from(chunk)));
    socket.once('error', error => { this.emit('transportError', error); this.finish(); });
    socket.once('end', () => { this.emit('end'); this.finish(); });
    socket.once('close', () => this.finish());
    socket.resume();
  }

  private onData(chunk: Buffer): void {
    if (this.closed) return;
    try {
      for (const frame of this.cipher.push(chunk)) {
        for (const block of frame) {
          if (block.type === 3) this.emit('i2np', decodeI2npBlock(block));
          else if (block.type === 4) {
            this.emit('termination', block.data);
            this.socket.end(); this.finish(); return;
          } else this.emit('block', block);
        }
      }
    } catch (error) { this.emit('protocolError', error); this.socket.destroy(error instanceof Error ? error : undefined); this.finish(); }
  }

  sendI2np(message: I2npMessage): Promise<void> { return this.sendBlocks([encodeI2npBlock(message)]); }

  sendBlocks(blocks: readonly Ntcp2Block[]): Promise<void> {
    if (this.closed) return Promise.reject(new Error('NTCP2 connection is closed'));
    const estimated = blocks.reduce((sum, block) => sum + encodeNtcp2Block(block).length, 0) + 18;
    if (this.pendingBytes + estimated > this.maxPendingBytes) return Promise.reject(new Error('NTCP2 outbound queue limit exceeded'));
    const frame = this.cipher.seal(blocks);
    this.pendingBytes += frame.length;
    const send = this.sendChain.then(() => new Promise<void>((resolve, reject) => {
      if (this.closed) { reject(new Error('NTCP2 connection is closed')); return; }
      this.socket.write(frame, error => error ? reject(error) : resolve());
    }));
    this.sendChain = send.catch(error => { this.emit('sendError', error); this.socket.destroy(error instanceof Error ? error : undefined); this.finish(); });
    return send.finally(() => { this.pendingBytes -= frame.length; });
  }

  close(): void { if (this.closed) return; this.socket.end(); this.finish(); }
  private finish(): void { if (this.closed) return; this.closed = true; this.cipher.destroy(); this.emit('close'); }
  get isClosed(): boolean { return this.closed; }
  get queuedBytes(): number { return this.pendingBytes; }
}
