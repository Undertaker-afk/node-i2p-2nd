import { EventEmitter } from 'node:events';
import { gunzipSync } from 'node:zlib';
import type { I2npMessage } from '../../protocol/i2np.ts';
import type { PeerConnection } from '../peer-connection.ts';
import {
  ackedPacketNumbers, buildAckBlock, blocksSize, dateTimeBlock, decodeAckBlock, decodeBlocks, decodeI2npBlockData, encodeAckBlock,
  encodeBlocks, fragmentI2np, isAckEliciting, newTokenBlock, padBlocks, parseAddressBlock, parseNewToken, parseTermination, terminationBlock,
  BLK_ACK, BLK_ADDRESS, BLK_DATETIME, BLK_FIRST_FRAGMENT, BLK_FOLLOW_ON_FRAGMENT, BLK_I2NP, BLK_NEW_TOKEN, BLK_PADDING, BLK_PATH_CHALLENGE,
  BLK_PATH_RESPONSE, BLK_ROUTER_INFO, BLK_TERMINATION, TERMINATION_IDLE, TERMINATION_NORMAL, TERMINATION_RECEIVED, TERMINATION_TIMEOUT, type Ssu2Block,
} from './blocks.ts';
import { decryptDataPacket, encryptDataPacket, type DirectionKeys } from './handshake.ts';

const HEADER_AND_MAC = 16 + 16;
const ACK_RESERVE = 3 + 5 + 2 * 8;
const MAX_RETRANSMITS = 6;
const RECEIVE_WINDOW = 1024;
const MAX_REASSEMBLY = 64;
const REASSEMBLY_TIMEOUT_MS = 30_000;
const DEDUP_TTL_MS = 120_000;
const MAX_INFLIGHT = 256;

export type Ssu2SessionOptions = {
  role: 'alice' | 'bob';
  remoteHost: string;
  remotePort: number;
  localConnId: Buffer;
  remoteConnId: Buffer;
  ownIntroKey: Buffer;
  remoteIntroKey: Buffer;
  send: DirectionKeys;
  receive: DirectionKeys;
  remoteIdentityHash: Buffer;
  /** Max UDP payload (MTU minus IP/UDP headers). */
  maxPacketSize: number;
  sendPacket: (packet: Buffer) => void;
  /** Alice retains Session Confirmed until Bob's first data packet (spec option 2). */
  sessionConfirmedPackets?: Buffer[];
  keepaliveMs?: number;
  idleTimeoutMs?: number;
};

type InflightPacket = { blocks: Ssu2Block[]; sentAt: number; attempts: number; firstSentAt: number };
type Reassembly = { type: number; id: number; expiration: number; parts: Map<number, Buffer>; last?: number; createdAt: number; bytes: number };

/** Established SSU2 data-phase session. Implements the same PeerConnection surface as Ntcp2Connection. */
export class Ssu2Session extends EventEmitter implements PeerConnection {
  readonly transport = 'SSU2' as const;
  readonly role: 'alice' | 'bob';
  readonly remoteIdentityHash: Buffer;
  readonly localConnId: Buffer;
  readonly remoteConnId: Buffer;
  remoteHost: string;
  remotePort: number;
  private readonly options: Ssu2SessionOptions;
  private closed = false;
  private nextPacketNumber: number;
  private readonly inflight = new Map<number, InflightPacket>();
  private readonly queue: Ssu2Block[] = [];
  private flushScheduled = false;
  private readonly received = new Set<number>();
  private highestReceived = -1;
  private ackPending = false;
  private ackTimer: NodeJS.Timeout | undefined;
  private readonly retransmitTimer: NodeJS.Timeout;
  private readonly keepaliveTimer: NodeJS.Timeout;
  private confirmedTimer: NodeJS.Timeout | undefined;
  private confirmedAttempts = 0;
  private sessionConfirmedPackets: Buffer[] | undefined;
  private readonly reassembly = new Map<number, Reassembly>();
  private readonly seenMessageIds = new Map<number, number>();
  private lastSendAt = Date.now();
  private lastReceiveAt = Date.now();
  private srtt = 0;
  private rttvar = 0;
  private rto = 1_000;
  /** Count of valid data packets received (for Termination blocks). */
  private validReceived = 0n;
  private established = false;

  constructor(options: Ssu2SessionOptions) {
    super();
    this.options = options;
    this.role = options.role;
    this.remoteIdentityHash = Buffer.from(options.remoteIdentityHash);
    this.localConnId = Buffer.from(options.localConnId);
    this.remoteConnId = Buffer.from(options.remoteConnId);
    this.remoteHost = options.remoteHost; this.remotePort = options.remotePort;
    // Session Confirmed is Alice's packet 0, so Alice's data starts at 1; Bob starts at 0.
    this.nextPacketNumber = options.role === 'alice' ? 1 : 0;
    if (options.role === 'bob') { this.received.add(0); this.highestReceived = 0; this.established = true; }
    this.sessionConfirmedPackets = options.sessionConfirmedPackets;
    this.retransmitTimer = setInterval(() => this.onRetransmitTick(), 100);
    this.retransmitTimer.unref();
    this.keepaliveTimer = setInterval(() => this.onKeepaliveTick(), Math.max(1_000, Math.floor((options.keepaliveMs ?? 15_000) / 2)));
    this.keepaliveTimer.unref();
    if (this.sessionConfirmedPackets) this.scheduleConfirmedRetransmit();
  }

  get isClosed(): boolean { return this.closed; }
  get inflightPackets(): number { return this.inflight.size; }
  get isEstablished(): boolean { return this.established; }
  get endpointKey(): string { return `${this.remoteHost}:${this.remotePort}`; }
  private get maxPayload(): number { return this.options.maxPacketSize - HEADER_AND_MAC; }
  private get maxBlockSize(): number { return this.maxPayload - ACK_RESERVE - 8; }

  sendI2np(message: I2npMessage): Promise<void> {
    if (this.closed) return Promise.reject(new Error('SSU2 session is closed'));
    if (this.inflight.size >= MAX_INFLIGHT && this.queue.length > MAX_INFLIGHT) return Promise.reject(new Error('SSU2 outbound queue limit exceeded'));
    let blocks: Ssu2Block[];
    try { blocks = fragmentI2np(message, this.maxBlockSize); } catch (error) { return Promise.reject(error); }
    this.queue.push(...blocks);
    this.scheduleFlush();
    return Promise.resolve();
  }

  /** Queues arbitrary blocks (e.g. New Token, Path Challenge). */
  sendBlocks(blocks: readonly Ssu2Block[]): void {
    if (this.closed) return;
    this.queue.push(...blocks);
    this.scheduleFlush();
  }

  /** Sends a New Token block for Alice's next connection (Bob only). */
  sendNewToken(token: Buffer, expiresMs: number): void { this.sendBlocks([newTokenBlock(token, expiresMs)]); }

  /** Immediately sends an ACK-only packet (used to ACK Session Confirmed / packet 0). */
  sendAckNow(): void { this.ackPending = true; this.flushAck(); }

  /** Alice: re-sends retained Session Confirmed packets (e.g. Bob retransmitted Session Created). */
  resendSessionConfirmed(): void {
    if (!this.sessionConfirmedPackets || this.closed) return;
    for (const packet of this.sessionConfirmedPackets) this.options.sendPacket(packet);
  }

  get awaitingSessionConfirmedAck(): boolean { return this.sessionConfirmedPackets !== undefined; }

  private scheduleConfirmedRetransmit(): void {
    const delays = [1_250, 2_500, 5_000];
    const delay = delays[this.confirmedAttempts];
    if (delay === undefined) {
      if (!this.established) { this.emit('handshakeTimeout'); this.terminate(TERMINATION_TIMEOUT); }
      return;
    }
    this.confirmedTimer = setTimeout(() => {
      if (this.closed || !this.sessionConfirmedPackets) return;
      this.confirmedAttempts++;
      this.resendSessionConfirmed();
      this.scheduleConfirmedRetransmit();
    }, delay);
    this.confirmedTimer.unref();
  }

  /** Handles a packet whose destination connection ID is ours. Returns false if it did not authenticate. */
  handlePacket(packet: Buffer): boolean {
    if (this.closed) return false;
    let opened: ReturnType<typeof decryptDataPacket>;
    try {
      opened = decryptDataPacket(packet, { ownIntroKey: this.options.ownIntroKey, receive: this.options.receive });
    } catch {
      // Bob: a retransmitted Session Confirmed means our ACK of packet 0 was lost.
      if (this.role === 'bob' && this.validReceived === 0n) this.sendAckNow();
      return false;
    }
    const packetNumber = opened.header.packetNumber;
    if (this.received.has(packetNumber) || (this.highestReceived - packetNumber) > RECEIVE_WINDOW) {
      this.ackPending = true; this.scheduleAck(0);
      return true; // duplicate or too old: re-ACK, do not reprocess
    }
    let blocks: Ssu2Block[];
    try { blocks = decodeBlocks(opened.payload); } catch (error) { this.emit('protocolError', error); return true; }
    this.received.add(packetNumber);
    if (packetNumber > this.highestReceived) this.highestReceived = packetNumber;
    this.pruneReceived();
    this.validReceived++;
    this.lastReceiveAt = Date.now();
    if (!this.established || this.sessionConfirmedPackets) {
      this.established = true;
      this.sessionConfirmedPackets = undefined;
      if (this.confirmedTimer) clearTimeout(this.confirmedTimer);
      this.emit('established');
    }
    for (const block of blocks) {
      try { this.handleBlock(block); } catch (error) { this.emit('protocolError', error); }
      if (this.closed) return true;
    }
    if (isAckEliciting(blocks)) {
      this.ackPending = true;
      this.scheduleAck((opened.header.flag & 1) ? 0 : 20);
    }
    return true;
  }

  private handleBlock(block: Ssu2Block): void {
    switch (block.type) {
      case BLK_I2NP: this.deliver(decodeI2npBlockData(block.data)); break;
      case BLK_FIRST_FRAGMENT: this.onFirstFragment(block.data); break;
      case BLK_FOLLOW_ON_FRAGMENT: this.onFollowOnFragment(block.data); break;
      case BLK_ACK: this.onAck(block); break;
      case BLK_TERMINATION: {
        const { reason } = parseTermination(block);
        this.emit('termination', reason);
        if (reason !== TERMINATION_RECEIVED) this.sendRaw([terminationBlock(TERMINATION_RECEIVED, this.validReceived)]);
        this.finish();
        break;
      }
      case BLK_NEW_TOKEN: this.emit('newToken', parseNewToken(block)); break;
      case BLK_ADDRESS: { const address = parseAddressBlock(block); if (address) this.emit('observedAddress', address); break; }
      case BLK_PATH_CHALLENGE: this.sendBlocks([{ type: BLK_PATH_RESPONSE, data: block.data }]); break;
      case BLK_ROUTER_INFO: {
        if (block.data.length < 2) break;
        const body = block.data.subarray(2);
        this.emit('routerInfo', (block.data[0]! & 2) ? gunzipSync(body, { maxOutputLength: 64 * 1024 }) : Buffer.from(body));
        break;
      }
      case BLK_DATETIME: case BLK_PADDING: case BLK_PATH_RESPONSE: break;
      default: this.emit('block', block); break; // relay, peer test, congestion: not implemented, ignored per spec
    }
  }

  private deliver(message: I2npMessage): void {
    const now = Date.now();
    if (this.seenMessageIds.has(message.id)) return;
    this.seenMessageIds.set(message.id, now);
    if (this.seenMessageIds.size > 4096) {
      for (const [id, at] of this.seenMessageIds) { if (now - at > DEDUP_TTL_MS || this.seenMessageIds.size > 4096) this.seenMessageIds.delete(id); else break; }
    }
    this.emit('i2np', message);
  }

  private reassemblyFor(id: number): Reassembly {
    let entry = this.reassembly.get(id);
    if (!entry) {
      if (this.reassembly.size >= MAX_REASSEMBLY) {
        const oldest = this.reassembly.keys().next().value;
        if (oldest !== undefined) this.reassembly.delete(oldest);
      }
      entry = { type: -1, id, expiration: 0, parts: new Map(), createdAt: Date.now(), bytes: 0 };
      this.reassembly.set(id, entry);
    }
    return entry;
  }

  private onFirstFragment(data: Buffer): void {
    if (data.length < 10) throw new Error('SSU2 First Fragment too short');
    const id = data.readUInt32BE(1);
    if (this.seenMessageIds.has(id)) return;
    const entry = this.reassemblyFor(id);
    entry.type = data[0]!; entry.expiration = data.readUInt32BE(5) * 1000;
    if (!entry.parts.has(0)) { entry.parts.set(0, Buffer.from(data.subarray(9))); entry.bytes += data.length - 9; }
    this.tryComplete(entry);
  }

  private onFollowOnFragment(data: Buffer): void {
    if (data.length < 6) throw new Error('SSU2 Follow-on Fragment too short');
    const fragment = data[0]! >> 1; const isLast = (data[0]! & 1) === 1; const id = data.readUInt32BE(1);
    if (fragment === 0) throw new Error('SSU2 Follow-on fragment number 0 is invalid');
    if (this.seenMessageIds.has(id)) return;
    const entry = this.reassemblyFor(id);
    if (!entry.parts.has(fragment)) { entry.parts.set(fragment, Buffer.from(data.subarray(5))); entry.bytes += data.length - 5; }
    if (isLast) entry.last = fragment;
    if (entry.bytes > 64 * 1024) { this.reassembly.delete(id); throw new Error('SSU2 reassembled I2NP message too large'); }
    this.tryComplete(entry);
  }

  private tryComplete(entry: Reassembly): void {
    if (entry.type < 0 || entry.last === undefined) return;
    for (let index = 0; index <= entry.last; index++) if (!entry.parts.has(index)) return;
    this.reassembly.delete(entry.id);
    const parts: Buffer[] = [];
    for (let index = 0; index <= entry.last; index++) parts.push(entry.parts.get(index)!);
    this.deliver({ type: entry.type, id: entry.id, expiration: entry.expiration, payload: Buffer.concat(parts) });
  }

  private onAck(block: Ssu2Block): void {
    const now = Date.now();
    for (const packetNumber of ackedPacketNumbers(decodeAckBlock(block))) {
      if (packetNumber === 0 && this.sessionConfirmedPackets) {
        this.sessionConfirmedPackets = undefined;
        if (this.confirmedTimer) clearTimeout(this.confirmedTimer);
      }
      const entry = this.inflight.get(packetNumber);
      if (!entry) continue;
      this.inflight.delete(packetNumber);
      if (entry.attempts === 1) this.updateRtt(now - entry.sentAt);
    }
    if (this.queue.length) this.scheduleFlush();
  }

  private updateRtt(sample: number): void {
    if (this.srtt === 0) { this.srtt = sample; this.rttvar = sample / 2; }
    else { this.rttvar = 0.75 * this.rttvar + 0.25 * Math.abs(this.srtt - sample); this.srtt = 0.875 * this.srtt + 0.125 * sample; }
    this.rto = Math.min(5_000, Math.max(200, Math.round(this.srtt + 4 * this.rttvar)));
  }

  get roundTripMs(): number { return this.srtt; }

  private pruneReceived(): void {
    if (this.received.size <= RECEIVE_WINDOW) return;
    const floor = this.highestReceived - RECEIVE_WINDOW;
    for (const packetNumber of this.received) if (packetNumber < floor) this.received.delete(packetNumber);
  }

  private scheduleAck(delayMs: number): void {
    if (this.closed) return;
    if (delayMs === 0) { this.flushAck(); return; }
    if (this.ackTimer) return;
    this.ackTimer = setTimeout(() => { this.ackTimer = undefined; this.flushAck(); }, delayMs);
    this.ackTimer.unref();
  }

  private flushAck(): void {
    if (this.ackTimer) { clearTimeout(this.ackTimer); this.ackTimer = undefined; }
    if (!this.ackPending || this.closed) return;
    if (this.queue.length) { this.flush(); return; } // piggyback
    this.sendRaw([]);
  }

  private currentAckBlock(): Ssu2Block | undefined {
    if (this.highestReceived < 0) return undefined;
    const recent = [...this.received].filter(packetNumber => packetNumber > this.highestReceived - 512);
    const ack = buildAckBlock(recent, 8);
    return ack ? encodeAckBlock(ack) : undefined;
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    queueMicrotask(() => { this.flushScheduled = false; this.flush(); });
  }

  private flush(): void {
    if (this.closed) return;
    while (this.queue.length && this.inflight.size < MAX_INFLIGHT) {
      const packetBlocks: Ssu2Block[] = [];
      let size = 0;
      const budget = this.maxPayload - ACK_RESERVE - 8;
      while (this.queue.length && size + 3 + this.queue[0]!.data.length <= budget) {
        const block = this.queue.shift()!;
        packetBlocks.push(block); size += 3 + block.data.length;
      }
      if (!packetBlocks.length) { // oversize single block (should not happen after fragmentation)
        this.emit('protocolError', new Error('SSU2 block exceeds packet budget; dropped'));
        this.queue.shift();
        continue;
      }
      this.sendRaw(packetBlocks, true);
    }
  }

  /** Encrypts and sends one packet with the given blocks plus an ACK block if one is due. */
  private sendRaw(blocks: Ssu2Block[], track = false): number {
    const packetNumber = this.nextPacketNumber++;
    if (packetNumber > 0xffff_ffff) { this.terminate(TERMINATION_NORMAL); return packetNumber; }
    const withAck: Ssu2Block[] = [];
    const ack = this.currentAckBlock();
    if (ack) withAck.push(ack);
    this.ackPending = false;
    if (this.ackTimer) { clearTimeout(this.ackTimer); this.ackTimer = undefined; }
    // Termination must be last except padding.
    const ordered = [...withAck, ...blocks];
    const payload = encodeBlocks(padBlocks(ordered, 8, this.maxPayload, blocksSize(ordered) < 64 ? 16 : 0));
    const packet = encryptDataPacket({
      destConnId: this.remoteConnId, packetNumber, payload, send: this.options.send, remoteIntroKey: this.options.remoteIntroKey,
    });
    const now = Date.now();
    if (track) this.inflight.set(packetNumber, { blocks, sentAt: now, attempts: 1, firstSentAt: now });
    this.lastSendAt = now;
    this.options.sendPacket(packet);
    return packetNumber;
  }

  private onRetransmitTick(): void {
    if (this.closed) return;
    const now = Date.now();
    for (const [packetNumber, entry] of this.inflight) {
      const timeout = this.rto * 2 ** (entry.attempts - 1);
      if (now - entry.sentAt < timeout) continue;
      this.inflight.delete(packetNumber);
      if (entry.attempts >= MAX_RETRANSMITS) {
        this.emit('messageDropped', entry.blocks);
        continue;
      }
      // Retransmit the same blocks under a new packet number (SSU2 never reuses packet numbers).
      const next = this.sendRaw(entry.blocks, false);
      this.inflight.set(next, { blocks: entry.blocks, sentAt: now, attempts: entry.attempts + 1, firstSentAt: entry.firstSentAt });
    }
    for (const [id, entry] of this.reassembly) if (now - entry.createdAt > REASSEMBLY_TIMEOUT_MS) this.reassembly.delete(id);
    if (this.queue.length && this.inflight.size < MAX_INFLIGHT) this.scheduleFlush();
  }

  private onKeepaliveTick(): void {
    if (this.closed) return;
    const now = Date.now();
    const idleTimeout = this.options.idleTimeoutMs ?? 180_000;
    if (now - this.lastReceiveAt > idleTimeout) { this.emit('idleTimeout'); this.terminate(TERMINATION_IDLE); return; }
    // Keep NAT bindings alive and let the peer know we are here.
    if (now - this.lastSendAt >= (this.options.keepaliveMs ?? 15_000)) this.sendRaw([dateTimeBlock(now)]);
  }

  /** Sends a Termination block and closes. */
  terminate(reason = TERMINATION_NORMAL): void {
    if (this.closed) return;
    try { this.sendRaw([terminationBlock(reason, this.validReceived)]); } catch { /* socket may be gone */ }
    this.finish();
  }

  close(): void { this.terminate(TERMINATION_NORMAL); }

  private finish(): void {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.retransmitTimer); clearInterval(this.keepaliveTimer);
    if (this.ackTimer) clearTimeout(this.ackTimer);
    if (this.confirmedTimer) clearTimeout(this.confirmedTimer);
    this.inflight.clear(); this.queue.length = 0; this.reassembly.clear();
    this.options.send.key.fill(0); this.options.receive.key.fill(0);
    this.emit('close');
  }
}
