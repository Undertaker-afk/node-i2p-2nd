import type { EventEmitter } from 'node:events';
import type { I2npMessage } from '../protocol/i2np.ts';

export type TransportName = 'NTCP2' | 'SSU2';

/**
 * Transport-neutral view of an established router-to-router session.
 * Both NTCP2 (TCP) and SSU2 (UDP) sessions emit `i2np` for every received
 * I2NP message and `close` once the session is gone.
 */
export interface PeerConnection extends EventEmitter {
  readonly transport: TransportName;
  readonly remoteIdentityHash: Buffer | undefined;
  readonly isClosed: boolean;
  sendI2np(message: I2npMessage): Promise<void>;
  close(): void;
}

export function isPeerConnection(value: unknown): value is PeerConnection {
  return typeof value === 'object' && value !== null
    && typeof (value as PeerConnection).sendI2np === 'function'
    && typeof (value as PeerConnection).close === 'function';
}
