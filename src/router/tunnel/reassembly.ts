import { decodeI2np, type I2npMessage } from '../protocol/i2np.ts';
import { parseTunnelMessageFragment, type TunnelDelivery } from './fragments.ts';

type PendingMessage = {
  delivery: TunnelDelivery;
  parts: Map<number, Buffer>;
  lastPart?: number;
  bytes: number;
  expiresAt: number;
};
export type ReassembledTunnelMessage = { delivery: TunnelDelivery; message: I2npMessage };

const DEFAULT_MAX_PENDING_MESSAGES = 256;
const DEFAULT_MAX_PENDING_BYTES = 8 * 1024 * 1024;
const DEFAULT_FRAGMENT_TIMEOUT_MS = 60_000;

/** Bounded I2P tunnel fragment reassembler; returns only checksum-validated complete I2NP messages. */
export class TunnelFragmentReassembler {
  private readonly pending = new Map<number, PendingMessage>();
  private pendingBytes = 0;
  readonly maxPendingMessages: number;
  readonly maxPendingBytes: number;
  readonly fragmentTimeoutMs: number;

  constructor(options: { maxPendingMessages?: number; maxPendingBytes?: number; fragmentTimeoutMs?: number } = {}) {
    this.maxPendingMessages = options.maxPendingMessages ?? DEFAULT_MAX_PENDING_MESSAGES;
    this.maxPendingBytes = options.maxPendingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.fragmentTimeoutMs = options.fragmentTimeoutMs ?? DEFAULT_FRAGMENT_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.maxPendingMessages) || this.maxPendingMessages < 1 || this.maxPendingMessages > 100_000) throw new RangeError('maxPendingMessages must be 1..100000');
    if (!Number.isSafeInteger(this.maxPendingBytes) || this.maxPendingBytes < 1024 || this.maxPendingBytes > 256 * 1024 * 1024) throw new RangeError('maxPendingBytes is out of range');
    if (!Number.isSafeInteger(this.fragmentTimeoutMs) || this.fragmentTimeoutMs < 100 || this.fragmentTimeoutMs > 600_000) throw new RangeError('fragmentTimeoutMs must be 100..600000');
  }

  get size(): number { this.expire(Date.now()); return this.pending.size; }
  get bufferedBytes(): number { this.expire(Date.now()); return this.pendingBytes; }

  add(message: Buffer, now = Date.now()): ReassembledTunnelMessage | undefined {
    if (!Number.isSafeInteger(now) || now < 0) throw new RangeError('now must be a non-negative safe integer');
    this.expire(now);
    const fragment = parseTunnelMessageFragment(message);
    if (!fragment.followOn) {
      if (fragment.lastFragment) {
        const decoded = decodeI2np(fragment.data);
        if (decoded.expiration <= now) throw new Error('Tunnel-delivered I2NP message has expired');
        return { delivery: fragment.delivery, message: decoded };
      }
      if (fragment.messageId === undefined || fragment.data.length < 1) throw new Error('Initial fragmented tunnel message lacks a message ID or data');
      const key = fragment.messageId >>> 0;
      if (this.pending.has(key)) throw new Error('Duplicate initial tunnel fragment message ID');
      if (this.pending.size >= this.maxPendingMessages || fragment.data.length > this.maxPendingBytes - this.pendingBytes) throw new Error('Tunnel fragment reassembly capacity exceeded');
      this.pending.set(key, {
        delivery: fragment.delivery, parts: new Map([[0, Buffer.from(fragment.data)]]),
        bytes: fragment.data.length, expiresAt: now + this.fragmentTimeoutMs,
      });
      this.pendingBytes += fragment.data.length;
      return undefined;
    }
    const key = fragment.messageId! >>> 0;
    const state = this.pending.get(key);
    if (!state) return undefined;
    if (state.parts.has(fragment.fragmentNumber)) { this.delete(key); throw new Error('Duplicate tunnel fragment'); }
    if (state.bytes + fragment.data.length > this.maxPendingBytes - (this.pendingBytes - state.bytes)) { this.delete(key); throw new Error('Tunnel fragment reassembly byte limit exceeded'); }
    if (state.lastPart !== undefined && fragment.fragmentNumber > state.lastPart) { this.delete(key); throw new Error('Tunnel fragment follows the declared final fragment'); }
    if (fragment.lastFragment) {
      if (state.lastPart !== undefined && state.lastPart !== fragment.fragmentNumber) { this.delete(key); throw new Error('Conflicting final tunnel fragment numbers'); }
      state.lastPart = fragment.fragmentNumber;
    }
    state.parts.set(fragment.fragmentNumber, Buffer.from(fragment.data));
    state.bytes += fragment.data.length;
    this.pendingBytes += fragment.data.length;
    if (state.lastPart === undefined) return undefined;
    for (let number = 0; number <= state.lastPart; number++) if (!state.parts.has(number)) return undefined;
    const complete = Buffer.concat(Array.from({ length: state.lastPart + 1 }, (_, number) => state.parts.get(number)!));
    this.delete(key);
    try {
      const decoded = decodeI2np(complete);
      if (decoded.id !== key) throw new Error('Reassembled I2NP message ID does not match fragment ID');
      if (decoded.expiration <= now) throw new Error('Tunnel-delivered I2NP message has expired');
      return { delivery: state.delivery, message: decoded };
    } finally { complete.fill(0); }
  }

  clear(): void { this.pending.clear(); this.pendingBytes = 0; }

  private delete(key: number): void {
    const state = this.pending.get(key);
    if (!state) return;
    for (const part of state.parts.values()) part.fill(0);
    this.pendingBytes -= state.bytes;
    this.pending.delete(key);
  }
  private expire(now: number): void {
    for (const [key, state] of this.pending) if (state.expiresAt <= now) this.delete(key);
  }
}
