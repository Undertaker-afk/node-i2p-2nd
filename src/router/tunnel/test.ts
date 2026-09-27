import { EventEmitter } from 'node:events';
import { randomInt } from 'node:crypto';
import type { I2npMessage } from '../protocol/i2np.ts';
import {
  createDeliveryStatusMessage, I2NP_DELIVERY_STATUS, parseDeliveryStatus,
} from '../protocol/delivery-status.ts';
import type { BuiltInboundTunnel, BuiltOutboundTunnel } from './builder.ts';

export type TunnelTestResult = {
  messageId: number;
  rttMs: number;
  timestamp: number;
};

type PendingTest = {
  sentAt: number;
  resolve: (result: TunnelTestResult) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

/**
 * Correlates DeliveryStatus (type 10) echoes used to test an outbound/inbound tunnel pair.
 * The originator sends the message through the outbound tunnel with TUNNEL delivery to the
 * inbound gateway; the inbound tunnel delivers it locally.
 */
export class TunnelTester extends EventEmitter {
  private readonly pending = new Map<number, PendingTest>();

  get size(): number { return this.pending.size; }

  create(messageId = randomInt(1, 0x1_0000_0000), timestamp = Date.now()): I2npMessage {
    if (this.pending.has(messageId)) throw new Error('A tunnel test with this message ID is already outstanding');
    return createDeliveryStatusMessage({ messageId, timestamp }, { id: messageId, expiration: timestamp + 60_000 });
  }

  wait(messageId: number, timeoutMs = 8_000): Promise<TunnelTestResult> {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new RangeError('timeoutMs must be 1..120000');
    if (this.pending.has(messageId)) throw new Error('A tunnel test with this message ID is already outstanding');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(messageId);
        reject(new Error('Tunnel test timed out'));
      }, timeoutMs);
      this.pending.set(messageId, { sentAt: Date.now(), resolve, reject, timer });
    });
  }

  /** Returns true when the message completed a pending test. */
  handle(message: I2npMessage): boolean {
    if (message.type !== I2NP_DELIVERY_STATUS) return false;
    let status;
    try { status = parseDeliveryStatus(message.payload); }
    catch { return false; }
    const pending = this.pending.get(status.messageId);
    if (!pending) return false;
    this.pending.delete(status.messageId);
    clearTimeout(pending.timer);
    const result: TunnelTestResult = {
      messageId: status.messageId,
      rttMs: Math.max(0, Date.now() - pending.sentAt),
      timestamp: status.timestamp,
    };
    pending.resolve(result);
    this.emit('result', result);
    return true;
  }

  stop(): void {
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Tunnel tester stopped'));
      this.pending.delete(id);
    }
  }
}

export type TunnelPair = { outbound: BuiltOutboundTunnel; inbound: BuiltInboundTunnel };
