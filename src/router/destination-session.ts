import { EventEmitter } from 'node:events';
import { randomBytes, randomInt } from 'node:crypto';
import type { DestinationKeys } from './protocol/destination.ts';
import { createDestinationKeys, parseDestination } from './protocol/destination.ts';
import { createLeaseSet2, parseLeaseSet2, selectX25519Key, type Lease2, type LeaseSet2 } from './protocol/leaseset.ts';
import {
  unwrapDestExistingSession, unwrapDestNewSession, unwrapDestNewSessionReply, wrapDestExistingSession,
  wrapDestNewSession, wrapDestNewSessionReply, type EstablishedDestSession, type NewSessionResult,
} from './crypto/ecies-dest.ts';
import {
  I2NP_DATA, STREAM_CLOSE, STREAM_MAX_PACKET_SIZE, STREAM_RESET, STREAM_SYN,
  createAckPacket, createClosePacket, createDataPacket, createResetPacket, createSynAckPacket, createSynPacket, parseStreamingPacket,
  type StreamingPacket,
} from './streaming.ts';
import type { GarlicClove } from './tunnel/garlic.ts';
import type { I2npMessage } from './protocol/i2np.ts';
import { decodeGarlicBody } from './crypto/ecies-dest.ts';
import { encodeDatabaseStoreLeaseSet2, parseDatabaseStore } from './netdb/database-store.ts';

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
  private nextSendSeq = 1;
  private nextRecvSeq = 1;
  private readonly session: EstablishedDestSession;
  private readonly local: DestinationKeys;
  private readonly remoteHash: Buffer;
  private readonly sendGarlic: (message: I2npMessage, remote: RemoteLease) => Promise<void>;
  private readonly remote: RemoteLease;
  private closed = false;
  private finished = false;
  private readonly queued: Buffer[] = [];
  private readonly unacked = new Map<number, { packet: Buffer; sentAt: number; tries: number }>();
  private readonly reorder = new Map<number, StreamingPacket>();
  private readonly window = 32;
  private readonly rtoMs = 1_500;
  private retransmitTimer: NodeJS.Timeout | undefined;
  private waitingForWindow: Array<() => void> = [];

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
    this.on('newListener', event => { if (event === 'data') queueMicrotask(() => this.flushQueue()); });
    this.retransmitTimer = setInterval(() => void this.retransmitExpired(), this.rtoMs);
    this.retransmitTimer.unref();
  }

  get isClosed(): boolean { return this.closed; }

  async write(payload: Buffer): Promise<void> {
    if (this.closed) throw new Error('Stream is closed');
    if (!Buffer.isBuffer(payload)) throw new TypeError('payload must be a Buffer');
    if (payload.length === 0) return;
    for (let offset = 0; offset < payload.length; offset += STREAM_MAX_PACKET_SIZE) {
      await this.waitForWindow();
      if (this.closed) throw new Error('Stream is closed');
      const chunk = Buffer.from(payload.subarray(offset, offset + STREAM_MAX_PACKET_SIZE));
      const seq = this.nextSendSeq++;
      const packet = createDataPacket(this.sendStreamId, this.receiveStreamId, seq, this.nextRecvSeq - 1, chunk);
      this.unacked.set(seq, { packet, sentAt: Date.now(), tries: 1 });
      await this.sendPacket(packet);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      const seq = this.nextSendSeq++;
      const packet = createClosePacket(this.local, this.sendStreamId, this.receiveStreamId, seq, this.nextRecvSeq - 1);
      this.unacked.set(seq, { packet, sentAt: Date.now(), tries: 1 });
      await this.sendPacket(packet);
    } finally {
      this.finishClose();
    }
  }

  async reset(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.sendPacket(createResetPacket(this.sendStreamId, this.receiveStreamId, this.nextSendSeq, this.nextRecvSeq - 1));
    } finally {
      this.emit('error', new Error('Stream reset'));
      this.finishClose();
    }
  }

  handleIncoming(payload: Buffer): boolean {
    const packet = parseStreamingPacket(payload);
    if (this.receiveStreamId !== 0 && packet.sendStreamId !== 0 && packet.sendStreamId !== this.receiveStreamId) return false;
    this.applyAck(packet.ackThrough, packet.nacks);
    if (packet.flags & STREAM_RESET) {
      this.closed = true;
      this.emit('error', new Error('Peer reset the stream'));
      this.finishClose();
      return true;
    }
    const hasData = packet.payload.length > 0 || (packet.flags & (STREAM_CLOSE | STREAM_SYN)) !== 0;
    if (hasData) this.receivePacket(packet);
    return true;
  }

  private receivePacket(packet: StreamingPacket): void {
    if (packet.sequenceNum < this.nextRecvSeq) {
      this.sendAck();
      return;
    }
    if (packet.sequenceNum > this.nextRecvSeq) {
      if (this.reorder.size < 256) this.reorder.set(packet.sequenceNum, packet);
      this.sendAck();
      return;
    }
    this.deliver(packet);
    while (this.reorder.has(this.nextRecvSeq)) {
      const next = this.reorder.get(this.nextRecvSeq)!;
      this.reorder.delete(this.nextRecvSeq);
      this.deliver(next);
    }
    this.sendAck();
  }

  private deliver(packet: StreamingPacket): void {
    this.nextRecvSeq = packet.sequenceNum + 1;
    if (packet.payload.length) {
      if (this.listenerCount('data') > 0) this.emit('data', packet.payload);
      else this.queued.push(packet.payload);
    }
    if (packet.flags & STREAM_CLOSE) {
      this.closed = true;
      this.finishClose();
    }
  }

  private applyAck(ackThrough: number, nacks: readonly number[]): void {
    for (const seq of [...this.unacked.keys()]) {
      if (seq <= ackThrough && !nacks.includes(seq)) this.unacked.delete(seq);
    }
    for (const seq of nacks) {
      const entry = this.unacked.get(seq);
      if (entry) void this.sendPacket(entry.packet);
    }
    const waiters = this.waitingForWindow;
    this.waitingForWindow = [];
    for (const resume of waiters) resume();
  }

  private sendAck(): void {
    if (this.closed) return;
    const nacks: number[] = [];
    const highest = Math.max(this.nextRecvSeq - 1, ...this.reorder.keys(), 0);
    for (let seq = this.nextRecvSeq; seq <= highest && nacks.length < 8; seq++) {
      if (!this.reorder.has(seq)) nacks.push(seq);
    }
    const packet = createAckPacket(this.sendStreamId, this.receiveStreamId, Math.max(0, this.nextSendSeq - 1), this.nextRecvSeq - 1, nacks);
    void this.sendPacket(packet).catch(() => undefined);
  }

  private async waitForWindow(): Promise<void> {
    while (this.unacked.size >= this.window && !this.closed) {
      await new Promise<void>(resolve => this.waitingForWindow.push(resolve));
    }
  }

  private async retransmitExpired(): Promise<void> {
    if (this.closed) return;
    const now = Date.now();
    for (const [seq, entry] of this.unacked) {
      if (now - entry.sentAt < this.rtoMs) continue;
      if (entry.tries >= 8) {
        this.closed = true;
        this.emit('error', new Error(`Stream packet ${seq} timed out`));
        this.finishClose();
        return;
      }
      entry.tries++;
      entry.sentAt = now;
      await this.sendPacket(entry.packet).catch(() => undefined);
    }
  }

  private async sendPacket(packet: Buffer): Promise<void> {
    await this.sendGarlic(wrapDestExistingSession(this.session, [dataClove(this.remoteHash, packet)]), this.remote);
  }

  private finishClose(): void {
    if (this.finished) return;
    this.finished = true;
    this.closed = true;
    if (this.retransmitTimer) clearInterval(this.retransmitTimer);
    this.retransmitTimer = undefined;
    this.unacked.clear();
    this.reorder.clear();
    const waiters = this.waitingForWindow;
    this.waitingForWindow = [];
    for (const resume of waiters) resume();
    this.emit('close');
  }

  private flushQueue(): void {
    if (this.listenerCount('data') === 0) return;
    for (const chunk of this.queued) this.emit('data', chunk);
    this.queued.length = 0;
  }
}

function dataClove(destHash: Buffer, streaming: Buffer): GarlicClove {
  return {
    delivery: { type: 'destination', hash: destHash },
    message: { type: I2NP_DATA, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: streaming },
  };
}

function leaseSetClove(leaseSetBytes: Buffer): GarlicClove {
  return {
    delivery: { type: 'local' },
    message: { type: 1, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: encodeDatabaseStoreLeaseSet2(leaseSetBytes) },
  };
}

/** End-to-end ECIES sessions and streaming for one local destination. */
export class DestinationSessionManager extends EventEmitter {
  readonly local: DestinationKeys;
  private localLeaseSet: Buffer | undefined;
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
    const now = Math.floor(Date.now() / 1000);
    const maxExp = Math.max(...leases.map(lease => lease.expiresAtSeconds));
    const expiresOffsetSeconds = Math.min(0xffff, Math.max(60, maxExp - now + 10));
    const encoded = createLeaseSet2(this.local, leases, { expiresOffsetSeconds });
    this.localLeaseSet = encoded;
    return encoded;
  }

  setLocalLeaseSet(leaseSetBytes: Buffer): void {
    parseLeaseSet2(leaseSetBytes);
    this.localLeaseSet = Buffer.from(leaseSetBytes);
  }

  getLocalLeaseSet(): Buffer | undefined {
    return this.localLeaseSet ? Buffer.from(this.localLeaseSet) : undefined;
  }

  async connect(remote: RemoteLease, timeoutMs = 30_000): Promise<DestinationStream> {
    const receiveStreamId = randomInt(1, 0x1_0000_0000);
    const syn = createSynPacket(this.local, receiveStreamId);
    const cloves: GarlicClove[] = [];
    if (this.localLeaseSet) cloves.push(leaseSetClove(this.localLeaseSet));
    cloves.push(dataClove(remote.destinationHash, syn));
    const pending = wrapDestNewSession(
      cloves,
      remote.encryptionPublicKey,
      this.local.encryptionPublicKey,
      this.local.encryptionPrivateKey,
    );
    const pendingId = [...pending.nsrTags.keys()][0] ?? randomBytes(8).toString('hex');
    return new Promise<DestinationStream>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingNs.delete(pendingId);
        reject(new Error('Destination handshake timed out'));
      }, timeoutMs);
      this.pendingNs.set(pendingId, { pending, local: this.local, remote, receiveStreamId, resolve, reject, timer });
      void this.sendGarlic(pending.message, remote).catch(error => {
        clearTimeout(timer);
        this.pendingNs.delete(pendingId);
        reject(error instanceof Error ? error : new Error(String(error)));
      });
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
          this.ingestCloves(opened.cloves);
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
      const remote = remoteFromIncoming(incoming.aliceStaticPublicKey, incoming.cloves);
      this.ingestCloves(incoming.cloves);
      const syn = incoming.cloves.find(clove => clove.message.type === I2NP_DATA);
      const receiveStreamId = randomInt(1, 0x1_0000_0000);
      let sendStreamId = 0;
      if (syn) {
        const packet = parseStreamingPacket(syn.message.payload);
        sendStreamId = packet.receiveStreamId;
        if (packet.from && remote.destination.length === 0) {
          remote.destination = packet.from;
          remote.destinationHash = parseDestination(packet.from).destinationHash;
        }
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

  private ingestCloves(cloves: GarlicClove[]): void {
    for (const clove of cloves) {
      if (clove.message.type !== 1) continue;
      try {
        const parsed = parseDatabaseStore(clove.message.payload);
        if (parsed.kind === 'leaseSet2') this.emit('leaseSet', parsed.record.leaseSet);
      } catch { /* not a LeaseSet2 clove */ }
    }
  }

  async sendDatagram(remote: RemoteLease, payload: Buffer): Promise<void> {
    const session = this.sessions.get(remote.encryptionPublicKey.toString('hex'));
    const clove = dataClove(remote.destinationHash, payload);
    if (session) {
      await this.sendGarlic(wrapDestExistingSession(session, [clove]), remote);
      return;
    }
    const pending = wrapDestNewSession(
      this.localLeaseSet ? [leaseSetClove(this.localLeaseSet), clove] : [clove],
      remote.encryptionPublicKey,
      this.local.encryptionPublicKey,
      this.local.encryptionPrivateKey,
    );
    await this.sendGarlic(pending.message, remote);
  }

  private dispatchCloves(cloves: GarlicClove[]): void {
    this.ingestCloves(cloves);
    for (const clove of cloves) {
      if (clove.message.type !== I2NP_DATA) continue;
      let matched = false;
      for (const stream of this.streams) {
        try { if (stream.handleIncoming(clove.message.payload)) { matched = true; break; } }
        catch { /* not a streaming packet for this stream */ }
      }
      if (!matched) this.emit('datagram', clove.message.payload);
      this.emit('dataMessage', clove.message);
    }
  }
}

function remoteFromIncoming(aliceStaticPublicKey: Buffer, cloves: GarlicClove[]): RemoteLease {
  const remote: RemoteLease = {
    gatewayHash: Buffer.alloc(32), tunnelId: 1, encryptionPublicKey: aliceStaticPublicKey,
    destination: Buffer.alloc(0), destinationHash: Buffer.alloc(32),
  };
  for (const clove of cloves) {
    if (clove.message.type !== 1) continue;
    try {
      const parsed = parseDatabaseStore(clove.message.payload);
      if (parsed.kind !== 'leaseSet2') continue;
      const fromLs = leaseSetToRemote(parsed.record.leaseSet);
      remote.gatewayHash = fromLs.gatewayHash;
      remote.tunnelId = fromLs.tunnelId;
      remote.destination = fromLs.destination;
      remote.destinationHash = fromLs.destinationHash;
    } catch { /* ignore malformed DatabaseStore cloves */ }
  }
  return remote;
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
