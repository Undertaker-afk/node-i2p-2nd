import { EventEmitter } from 'node:events';
import { randomBytes, randomInt } from 'node:crypto';
import type { DestinationKeys } from './protocol/destination.ts';
import { createDestinationKeys, parseDestination } from './protocol/destination.ts';
import { createLeaseSet2, selectX25519Key, type Lease2, type LeaseSet2 } from './protocol/leaseset.ts';
import {
  unwrapDestExistingSession, unwrapDestNewSession, unwrapDestNewSessionReply, wrapDestExistingSession,
  wrapDestNewSession, wrapDestNewSessionReply, type EstablishedDestSession, type NewSessionResult,
} from './crypto/ecies-dest.ts';
import { I2NP_DATA, createDataPacket, createSynAckPacket, createSynPacket, parseStreamingPacket } from './streaming.ts';
import type { GarlicClove } from './tunnel/garlic.ts';
import type { I2npMessage } from './protocol/i2np.ts';
import { decodeGarlicBody } from './crypto/ecies-dest.ts';

export type RemoteLease = { gatewayHash: Buffer; tunnelId: number; encryptionPublicKey: Buffer; destination: Buffer; destinationHash: Buffer };

type PendingConnect = {
  pending: NewSessionResult;
  local: DestinationKeys;
  remote: RemoteLease;
  receiveStreamId: number;
  resolve: (stream: DestinationStream) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

export class DestinationStream extends EventEmitter {
  sendStreamId: number;
  receiveStreamId: number;
  private sequence = 1;
  private readonly session: EstablishedDestSession;
  private readonly local: DestinationKeys;
  private readonly remoteHash: Buffer;
  private readonly sendGarlic: (message: I2npMessage, remote: RemoteLease) => Promise<void>;
  private readonly remote: RemoteLease;
  private closed = false;

  constructor(options: {
    session: EstablishedDestSession; local: DestinationKeys; remote: RemoteLease;
    sendStreamId: number; receiveStreamId: number;
    sendGarlic: (message: I2npMessage, remote: RemoteLease) => Promise<void>;
  }) {
    super();
    this.session = options.session; this.local = options.local; this.remote = options.remote;
    this.remoteHash = options.remote.destinationHash;
    this.sendStreamId = options.sendStreamId; this.receiveStreamId = options.receiveStreamId;
    this.sendGarlic = options.sendGarlic;
  }

  async write(payload: Buffer): Promise<void> {
    if (this.closed) throw new Error('Stream is closed');
    const packet = createDataPacket(this.sendStreamId, this.receiveStreamId, this.sequence++, this.sequence - 2, payload);
    await this.sendGarlic(wrapDestExistingSession(this.session, [dataClove(this.remoteHash, packet)]), this.remote);
  }

  handleIncoming(payload: Buffer): void {
    const packet = parseStreamingPacket(payload);
    if (packet.payload.length) this.emit('data', packet.payload);
    if (packet.flags & 2) { this.closed = true; this.emit('close'); }
  }
}

function dataClove(destHash: Buffer, streaming: Buffer): GarlicClove {
  return {
    delivery: { type: 'destination', hash: destHash },
    message: { type: I2NP_DATA, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: streaming },
  };
}

/** End-to-end ECIES sessions and streaming for one local destination. */
export class DestinationSessionManager extends EventEmitter {
  readonly local: DestinationKeys;
  private readonly sessions = new Map<string, EstablishedDestSession>();
  private readonly pendingNs = new Map<string, PendingConnect>();
  private readonly streams = new Set<DestinationStream>();
  private readonly sendGarlic: (message: I2npMessage, remote: RemoteLease) => Promise<void>;

  constructor(options: { local?: DestinationKeys; sendGarlic: (message: I2npMessage, remote: RemoteLease) => Promise<void> }) {
    super();
    this.local = options.local ?? createDestinationKeys();
    this.sendGarlic = options.sendGarlic;
  }

  createLeaseSet(leases: readonly Lease2[]): Buffer {
    return createLeaseSet2(this.local, leases);
  }

  async connect(remote: RemoteLease, timeoutMs = 30_000): Promise<DestinationStream> {
    const receiveStreamId = randomInt(1, 0x1_0000_0000);
    const syn = createSynPacket(this.local, receiveStreamId);
    const pending = wrapDestNewSession(
      [dataClove(remote.destinationHash, syn)],
      remote.encryptionPublicKey,
      this.local.encryptionPublicKey,
      this.local.encryptionPrivateKey,
    );
    await this.sendGarlic(pending.message, remote);
    return new Promise<DestinationStream>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingNs.delete(keyOf(pending));
        reject(new Error('Destination handshake timed out'));
      }, timeoutMs);
      this.pendingNs.set(keyOf(pending), { pending, local: this.local, remote, receiveStreamId, resolve, reject, timer });
    });
  }

  handleGarlic(message: I2npMessage): boolean {
    try {
      const body = decodeGarlicBody(message);
      if (body.length >= 8) {
        for (const [hex, pending] of this.pendingNs) {
          if (!pending.pending.nsrTags.has(body.subarray(0, 8).toString('hex'))) continue;
          const opened = unwrapDestNewSessionReply(message, pending.pending, this.local.encryptionPrivateKey);
          this.sessions.set(pending.remote.encryptionPublicKey.toString('hex'), opened.session);
          const synAck = opened.cloves.find(clove => clove.message.type === I2NP_DATA);
          let sendStreamId = randomInt(1, 0x1_0000_0000);
          if (synAck) {
            const packet = parseStreamingPacket(synAck.message.payload);
            sendStreamId = packet.receiveStreamId || sendStreamId;
          }
          const stream = new DestinationStream({
            session: opened.session, local: this.local, remote: pending.remote,
            sendStreamId, receiveStreamId: pending.receiveStreamId, sendGarlic: this.sendGarlic,
          });
          this.streams.add(stream);
          clearTimeout(pending.timer);
          this.pendingNs.delete(hex);
          pending.resolve(stream);
          return true;
        }
        for (const session of this.sessions.values()) {
          if (!session.receiveTags.has(body.subarray(0, 8).toString('hex'))) continue;
          const cloves = unwrapDestExistingSession(message, session);
          this.dispatchCloves(cloves);
          return true;
        }
      }
      const incoming = unwrapDestNewSession(message, this.local.encryptionPrivateKey, this.local.encryptionPublicKey);
      const remote: RemoteLease = {
        gatewayHash: Buffer.alloc(32), tunnelId: 1, encryptionPublicKey: incoming.aliceStaticPublicKey,
        destination: Buffer.alloc(0), destinationHash: Buffer.alloc(32),
      };
      const syn = incoming.cloves.find(clove => clove.message.type === I2NP_DATA);
      const receiveStreamId = randomInt(1, 0x1_0000_0000);
      let sendStreamId = 0;
      if (syn) {
        const packet = parseStreamingPacket(syn.message.payload);
        sendStreamId = packet.receiveStreamId;
        if (packet.from) remote.destination = packet.from;
        if (packet.from) remote.destinationHash = parseDestination(packet.from).destinationHash;
      }
      const reply = wrapDestNewSessionReply(incoming, [dataClove(remote.destinationHash, createSynAckPacket(this.local, sendStreamId, receiveStreamId))], incoming.aliceStaticPublicKey, this.local.encryptionPrivateKey);
      this.sessions.set(incoming.aliceStaticPublicKey.toString('hex'), reply.session);
      const stream = new DestinationStream({
        session: reply.session, local: this.local, remote, sendStreamId, receiveStreamId, sendGarlic: this.sendGarlic,
      });
      this.streams.add(stream);
      this.emit('inboundStream', stream, reply.message, remote);
      return true;
    } catch {
      return false;
    }
  }

  private dispatchCloves(cloves: GarlicClove[]): void {
    for (const clove of cloves) {
      if (clove.message.type !== I2NP_DATA) continue;
      for (const stream of this.streams) {
        try { stream.handleIncoming(clove.message.payload); }
        catch { /* not this stream */ }
      }
      this.emit('dataMessage', clove.message);
    }
  }
}

function keyOf(pending: NewSessionResult): string {
  return randomBytes(8).toString('hex') + pending.bobStaticPublicKey.toString('hex');
}

export function leaseSetToRemote(ls: LeaseSet2): RemoteLease {
  const lease = ls.leases[0];
  if (!lease) throw new Error('LeaseSet2 has no leases');
  return {
    gatewayHash: Buffer.from(lease.gatewayHash),
    tunnelId: lease.tunnelId,
    encryptionPublicKey: selectX25519Key(ls),
    destination: Buffer.from(ls.destination),
    destinationHash: Buffer.from(ls.destinationHash),
  };
}
