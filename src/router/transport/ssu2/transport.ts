import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import type { RouterIdentityKeys } from '../../identity.ts';
import { parseRouterInfo, verifyRouterInfoSignature, type RouterInfo } from '../../protocol/router-info.ts';
import { findSsu2AddressByStaticKey, findSsu2Endpoint, type Ssu2Endpoint } from './address.ts';
import {
  addressBlock, parseAddressBlock, parseDateTime, parseNewToken, parseTermination, routerInfoBlock, terminationBlock,
  BLK_ADDRESS, BLK_DATETIME, BLK_NEW_TOKEN, BLK_ROUTER_INFO, BLK_TERMINATION, TERMINATION_CLOCK_SKEW,
  type Ssu2Block,
} from './blocks.ts';
import {
  createRetry, createSessionConfirmed, createSessionCreated, createSessionRequest, createTokenRequest, looksLikeRetry,
  looksLikeSessionCreated, openSessionConfirmedHeader, openSessionRequestHeader, parseRetry, parseTokenRequest, peekDestConnId,
  peekHeaderBytes8to16, processSessionConfirmed, processSessionCreated, processSessionRequest, randomConnId,
  type AliceSsu2State, type BobSsu2State,
} from './handshake.ts';
import { SSU2_MIN_PACKET, SSU2_SESSION_REQUEST, SSU2_TOKEN_REQUEST, SSU2_VERSION } from './header.ts';
import { Ssu2Session } from './session.ts';

const IPV4_UDP_OVERHEAD = 28;
const MAX_UDP_PACKET = 1500 - IPV4_UDP_OVERHEAD;
const TOKEN_LIFETIME_MS = 60 * 60 * 1000;
const RETRY_TOKEN_LIFETIME_MS = 2 * 60 * 1000;

export type Ssu2TransportOptions = {
  identity: RouterIdentityKeys;
  routerInfo: Buffer;
  introKey: Buffer;
  host?: string;
  port: number;
  networkId?: number;
  /** Total handshake timeout (default 15 s as recommended by the spec). */
  timeoutMs?: number;
  maxClockSkewSeconds?: number;
  /** Local MTU; packets are min(local, remote) - 28 bytes. */
  mtu?: number;
  maxSessions?: number;
  maxPendingHandshakes?: number;
  keepaliveMs?: number;
  /** Test hook: return false to drop a datagram. */
  packetFilter?: (direction: 'in' | 'out', packet: Buffer, host: string, port: number) => boolean;
};

type OutboundHandshake = {
  endpoint: Ssu2Endpoint;
  key: string;
  remoteInfo: RouterInfo;
  srcConnId: Buffer;
  destConnId: Buffer;
  stage: 'token' | 'request';
  packet: Buffer;
  alice?: AliceSsu2State;
  retries: number;
  attempts: number;
  timer?: NodeJS.Timeout;
  deadline: NodeJS.Timeout;
  resolve: (session: Ssu2Session) => void;
  reject: (error: Error) => void;
};

type InboundHandshake = {
  host: string;
  port: number;
  localConnId: Buffer;
  remoteConnId: Buffer;
  bob: BobSsu2State;
  packet: Buffer;
  fragments: Map<number, Buffer>;
  header0?: Buffer;
  total?: number;
  attempts: number;
  timer?: NodeJS.Timeout;
  deadline: NodeJS.Timeout;
};

function endpointKey(host: string, port: number): string { return `${host}:${port}`; }

/**
 * SSU2 over UDP: TokenRequest/Retry, Noise XK handshake with header protection, and data phase.
 * Relay, Peer Test, and connection migration are not implemented; this router only dials
 * published IPv4 SSU2 addresses and accepts inbound sessions on its bound UDP port.
 */
export class Ssu2Transport extends EventEmitter {
  private readonly config: Required<Pick<Ssu2TransportOptions, 'networkId' | 'timeoutMs' | 'maxClockSkewSeconds' | 'mtu' | 'maxSessions' | 'maxPendingHandshakes'>> & Ssu2TransportOptions;
  private socket: dgram.Socket | undefined;
  private routerInfo: Buffer;
  private readonly staticPublicKey: Buffer;
  private readonly sessions = new Map<string, Ssu2Session>();
  private readonly pendingOutbound = new Map<string, OutboundHandshake>();
  private readonly pendingInbound = new Map<string, InboundHandshake>();
  private readonly incomingTokens = new Map<string, { token: Buffer; expires: number }>();
  private readonly outgoingTokens = new Map<string, { token: Buffer; expires: number }>();
  private readonly replay = new Map<string, number>();
  private housekeeping: NodeJS.Timeout | undefined;
  private stopping = false;
  /** Last external address reported by a peer (Address block in Retry / Session Created). */
  observedAddress: { host: string; port: number } | undefined;

  constructor(options: Ssu2TransportOptions) {
    super();
    if (!Buffer.isBuffer(options.introKey) || options.introKey.length !== 32) throw new Error('SSU2 intro key must be 32 bytes');
    if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) throw new RangeError('SSU2 port must be 0..65535');
    this.config = {
      networkId: 2, timeoutMs: 15_000, maxClockSkewSeconds: 120, mtu: 1500, maxSessions: 512, maxPendingHandshakes: 128,
      ...options,
    };
    if (this.config.mtu < 1280 || this.config.mtu > 1500) throw new RangeError('SSU2 MTU must be 1280..1500');
    this.routerInfo = Buffer.from(options.routerInfo);
    this.staticPublicKey = Buffer.from(options.identity.identity.subarray(0, 32));
    const local = parseRouterInfo(this.routerInfo);
    if (!findSsu2AddressByStaticKey(local, this.staticPublicKey)) throw new Error('Local RouterInfo lacks an SSU2 address with this router\'s static key and intro key');
  }

  get introKey(): Buffer { return this.config.introKey; }
  get listening(): boolean { return this.socket !== undefined; }
  get activeSessions(): number { return this.sessions.size; }
  get pendingHandshakes(): number { return this.pendingInbound.size + this.pendingOutbound.size; }
  get address(): AddressInfo | null {
    try { return this.socket ? this.socket.address() : null; } catch { return null; }
  }

  updateRouterInfo(routerInfo: Buffer): void {
    const info = parseRouterInfo(routerInfo);
    if (!verifyRouterInfoSignature(info) || !info.identity.equals(this.config.identity.identity)) throw new Error('Updated RouterInfo does not match SSU2 identity');
    const keys = findSsu2AddressByStaticKey(info, this.staticPublicKey);
    if (!keys || !keys.introKey.equals(this.config.introKey)) throw new Error('Updated RouterInfo does not retain the SSU2 static and intro keys');
    this.routerInfo = Buffer.from(routerInfo);
  }

  async start(): Promise<AddressInfo> {
    if (this.socket) throw new Error('SSU2 transport already started');
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: false });
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind({ address: this.config.host ?? '0.0.0.0', port: this.config.port }, () => { socket.removeListener('error', reject); resolve(); });
    });
    socket.on('error', error => this.emit('transportError', error));
    socket.on('message', (packet, rinfo) => {
      try { this.onDatagram(packet, rinfo.address, rinfo.port); }
      catch (error) { this.emit('packetError', error); }
    });
    this.socket = socket; this.stopping = false;
    this.housekeeping = setInterval(() => this.cleanup(), 30_000); this.housekeeping.unref();
    const address = socket.address();
    this.emit('listening', address);
    return address;
  }

  async stop(): Promise<void> {
    if (!this.socket) return;
    this.stopping = true;
    for (const pending of this.pendingOutbound.values()) this.failOutbound(pending, new Error('SSU2 transport stopped'));
    for (const pending of this.pendingInbound.values()) this.dropInbound(pending);
    for (const session of [...this.sessions.values()]) session.terminate(3);
    this.sessions.clear();
    if (this.housekeeping) clearInterval(this.housekeeping);
    const socket = this.socket; this.socket = undefined;
    await new Promise<void>(resolve => socket.close(() => resolve()));
    this.emit('close');
  }

  private send(packet: Buffer, host: string, port: number): void {
    if (!this.socket) return;
    if (this.config.packetFilter && !this.config.packetFilter('out', packet, host, port)) return;
    this.socket.send(packet, port, host, error => { if (error) this.emit('transportError', error); });
  }

  // -------------------------------------------------------------------------
  // Alice: outbound dial
  // -------------------------------------------------------------------------

  /** Dials the SSU2 address in a verified RouterInfo and completes the XK handshake. */
  connect(remoteRouterInfoBytes: Buffer): Promise<Ssu2Session> {
    if (!this.socket || this.stopping) return Promise.reject(new Error('SSU2 transport is not running'));
    let remoteInfo: RouterInfo;
    try {
      remoteInfo = parseRouterInfo(remoteRouterInfoBytes);
      if (!verifyRouterInfoSignature(remoteInfo)) throw new Error('Remote RouterInfo signature is invalid');
      if (remoteInfo.options.get('netId') !== String(this.config.networkId)) throw new Error('Remote RouterInfo belongs to another network');
    } catch (error) { return Promise.reject(error); }
    const endpoint = findSsu2Endpoint(remoteInfo);
    if (!endpoint) return Promise.reject(new Error('RouterInfo contains no usable IPv4 SSU2 address'));
    const key = endpointKey(endpoint.host, endpoint.port);
    if (this.pendingOutbound.has(key)) return Promise.reject(new Error(`SSU2 handshake to ${key} already in progress`));
    if (this.sessions.size + this.pendingHandshakes >= this.config.maxSessions) return Promise.reject(new Error('SSU2 session limit reached'));
    return new Promise<Ssu2Session>((resolve, reject) => {
      const srcConnId = randomConnId(); let destConnId = randomConnId();
      while (destConnId.equals(srcConnId)) destConnId = randomConnId();
      const pending: OutboundHandshake = {
        endpoint, key, remoteInfo, srcConnId, destConnId, stage: 'token', packet: Buffer.alloc(0), retries: 0, attempts: 0,
        deadline: setTimeout(() => this.failOutbound(pending, new Error(`SSU2 handshake with ${key} timed out (stage ${pending.stage})`)), this.config.timeoutMs),
        resolve, reject,
      };
      pending.deadline.unref();
      this.pendingOutbound.set(key, pending);
      const token = this.outgoingTokens.get(key);
      if (token && token.expires > Date.now()) {
        this.outgoingTokens.delete(key); // tokens are single-use
        this.sendSessionRequest(pending, token.token);
      } else {
        pending.packet = createTokenRequest({ destConnId, srcConnId, netId: this.config.networkId, introKey: endpoint.introKey });
        this.transmitOutbound(pending, [3_000, 6_000]);
      }
    });
  }

  private sendSessionRequest(pending: OutboundHandshake, token: Buffer): void {
    const { packet, state } = createSessionRequest({
      destConnId: pending.destConnId, srcConnId: pending.srcConnId, netId: this.config.networkId, token,
      bobStaticKey: pending.endpoint.staticKey, bobIntroKey: pending.endpoint.introKey,
    });
    pending.stage = 'request'; pending.alice = state; pending.packet = packet; pending.attempts = 0;
    this.transmitOutbound(pending, [1_250, 2_500, 5_000]);
  }

  private transmitOutbound(pending: OutboundHandshake, delays: number[]): void {
    if (pending.timer) clearTimeout(pending.timer);
    this.send(pending.packet, pending.endpoint.host, pending.endpoint.port);
    const delay = delays[pending.attempts];
    if (delay === undefined) return;
    pending.timer = setTimeout(() => {
      if (this.pendingOutbound.get(pending.key) !== pending) return;
      pending.attempts++;
      this.transmitOutbound(pending, delays);
    }, delay);
    pending.timer.unref();
  }

  private failOutbound(pending: OutboundHandshake, error: Error): void {
    if (this.pendingOutbound.get(pending.key) === pending) this.pendingOutbound.delete(pending.key);
    if (pending.timer) clearTimeout(pending.timer);
    clearTimeout(pending.deadline);
    pending.reject(error);
  }

  private onOutboundPacket(pending: OutboundHandshake, packet: Buffer): boolean {
    const netId = this.config.networkId;
    if (looksLikeRetry(packet, pending.endpoint.introKey, netId)) {
      let retry: ReturnType<typeof parseRetry>;
      try { retry = parseRetry(packet, pending.endpoint.introKey); } catch { return false; }
      if (!retry.header.destConnId.equals(pending.srcConnId)) return false;
      this.noteBlocks(retry.blocks);
      const termination = retry.blocks.find(block => block.type === BLK_TERMINATION);
      if (retry.token.every(byte => byte === 0)) {
        const reason = termination ? parseTermination(termination).reason : -1;
        this.failOutbound(pending, new Error(`SSU2 Retry from ${pending.key} rejected the connection (termination reason ${reason})`));
        return true;
      }
      if (++pending.retries > 3) { this.failOutbound(pending, new Error(`SSU2 peer ${pending.key} sent too many Retry messages`)); return true; }
      this.sendSessionRequest(pending, retry.token);
      return true;
    }
    if (pending.stage !== 'request' || !pending.alice || !looksLikeSessionCreated(packet, pending.alice)) return false;
    let created: ReturnType<typeof processSessionCreated>;
    try { created = processSessionCreated(packet, pending.alice); } catch (error) { this.emit('handshakeError', error); return false; }
    this.noteBlocks(created.blocks);
    for (const block of created.blocks) {
      if (block.type === BLK_NEW_TOKEN) {
        const token = parseNewToken(block);
        this.outgoingTokens.set(pending.key, { token: token.token, expires: Math.min(token.expiresMs, Date.now() + TOKEN_LIFETIME_MS) });
      }
    }
    const maxPacketSize = Math.min(this.config.mtu, pending.endpoint.mtu) - IPV4_UDP_OVERHEAD;
    let riBlock = routerInfoBlock(this.routerInfo, false);
    if (3 + riBlock.data.length + 48 + 32 + 16 > maxPacketSize) riBlock = routerInfoBlock(gzipSync(this.routerInfo, { level: 9 }), true);
    const confirmed = createSessionConfirmed(created.noise, {
      destConnId: pending.destConnId, bobIntroKey: pending.endpoint.introKey, bobEphemeralKey: created.bobEphemeralKey,
      staticPrivateKey: this.config.identity.encryptionPrivateKey, staticPublicKey: this.staticPublicKey,
      payloadBlocks: [riBlock], maxPacketSize,
    });
    this.pendingOutbound.delete(pending.key);
    if (pending.timer) clearTimeout(pending.timer);
    clearTimeout(pending.deadline);
    const session = new Ssu2Session({
      role: 'alice', remoteHost: pending.endpoint.host, remotePort: pending.endpoint.port,
      localConnId: pending.srcConnId, remoteConnId: pending.destConnId,
      ownIntroKey: this.config.introKey, remoteIntroKey: pending.endpoint.introKey,
      send: confirmed.keys.ab, receive: confirmed.keys.ba, remoteIdentityHash: pending.remoteInfo.identityHash,
      maxPacketSize, sendPacket: bytes => this.send(bytes, session.remoteHost, session.remotePort),
      sessionConfirmedPackets: confirmed.packets,
      ...(this.config.keepaliveMs === undefined ? {} : { keepaliveMs: this.config.keepaliveMs }),
    });
    this.registerSession(session);
    for (const bytes of confirmed.packets) this.send(bytes, pending.endpoint.host, pending.endpoint.port);
    pending.resolve(session);
    return true;
  }

  private noteBlocks(blocks: Ssu2Block[]): void {
    for (const block of blocks) {
      if (block.type === BLK_ADDRESS) {
        const address = parseAddressBlock(block);
        if (address) { this.observedAddress = address; this.emit('observedAddress', address); }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Dispatch
  // -------------------------------------------------------------------------

  private onDatagram(packet: Buffer, host: string, port: number): void {
    if (packet.length < SSU2_MIN_PACKET || packet.length > MAX_UDP_PACKET + 28) return;
    if (this.config.packetFilter && !this.config.packetFilter('in', packet, host, port)) return;
    const key = endpointKey(host, port);
    const outbound = this.pendingOutbound.get(key);
    if (outbound && this.onOutboundPacket(outbound, packet)) return;
    const connId = peekDestConnId(packet, this.config.introKey).toString('hex');
    const session = this.sessions.get(connId);
    if (session) {
      if (session.handlePacket(packet) && (session.remoteHost !== host || session.remotePort !== port)) {
        // Path validation / migration is not implemented; follow the authenticated source.
        session.remoteHost = host; session.remotePort = port;
      }
      return;
    }
    const inbound = this.pendingInbound.get(connId);
    if (inbound) { this.onSessionConfirmed(inbound, packet, host, port); return; }
    const peek = peekHeaderBytes8to16(packet, this.config.introKey);
    if (peek.version === SSU2_VERSION && peek.netId === this.config.networkId) {
      if (peek.type === SSU2_TOKEN_REQUEST) { this.onTokenRequest(packet, host, port); return; }
      if (peek.type === SSU2_SESSION_REQUEST) { this.onSessionRequest(packet, host, port); return; }
    }
    // Possibly a retransmitted Session Created because our Session Confirmed was lost.
    for (const candidate of this.sessions.values()) {
      if (candidate.role === 'alice' && candidate.awaitingSessionConfirmedAck && candidate.remoteHost === host && candidate.remotePort === port) {
        candidate.resendSessionConfirmed();
        return;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Bob: Token Request, Session Request, Session Confirmed
  // -------------------------------------------------------------------------

  private clockSkewed(blocks: Ssu2Block[]): boolean {
    const dateTime = blocks.find(block => block.type === BLK_DATETIME);
    if (!dateTime) return true;
    return Math.abs(parseDateTime(dateTime) - Date.now()) > this.config.maxClockSkewSeconds * 1000;
  }

  private issueToken(host: string, port: number): Buffer {
    let token = randomBytes(8);
    while (token.every(byte => byte === 0)) token = randomBytes(8);
    this.incomingTokens.set(endpointKey(host, port), { token, expires: Date.now() + RETRY_TOKEN_LIFETIME_MS });
    return token;
  }

  private sendRetry(host: string, port: number, destConnId: Buffer, srcConnId: Buffer, reject?: number): void {
    const token = reject === undefined ? this.issueToken(host, port) : Buffer.alloc(8);
    const blocks: Ssu2Block[] = [];
    const address = addressBlock(host, port);
    if (address) blocks.push(address);
    if (reject !== undefined) blocks.push(terminationBlock(reject));
    this.send(createRetry({ destConnId, srcConnId, netId: this.config.networkId, introKey: this.config.introKey, token, blocks }), host, port);
  }

  private onTokenRequest(packet: Buffer, host: string, port: number): void {
    let opened: ReturnType<typeof parseTokenRequest>;
    try { opened = parseTokenRequest(packet, this.config.introKey); } catch { return; } // drop silently on AEAD failure
    const { header } = opened;
    if (header.srcConnId.equals(header.destConnId)) return;
    if (this.clockSkewed(opened.blocks)) { this.sendRetry(host, port, header.srcConnId, header.destConnId, TERMINATION_CLOCK_SKEW); return; }
    this.sendRetry(host, port, header.srcConnId, header.destConnId);
  }

  private onSessionRequest(packet: Buffer, host: string, port: number): void {
    let opened: ReturnType<typeof openSessionRequestHeader>;
    try { opened = openSessionRequestHeader(packet, this.config.introKey); } catch { return; }
    const { header } = opened;
    if (header.srcConnId.equals(header.destConnId)) return;
    const key = endpointKey(host, port);
    const expected = this.incomingTokens.get(key);
    if (!expected || expected.expires < Date.now() || !expected.token.equals(header.token)) {
      this.sendRetry(host, port, header.srcConnId, header.destConnId);
      return;
    }
    if (this.pendingInbound.size >= this.config.maxPendingHandshakes || this.sessions.size >= this.config.maxSessions) return;
    const replayKey = opened.ephemeralKey.toString('hex');
    if (this.replay.has(replayKey)) return;
    let request: ReturnType<typeof processSessionRequest>;
    try {
      request = processSessionRequest(packet, {
        staticPrivateKey: this.config.identity.encryptionPrivateKey, staticPublicKey: this.staticPublicKey, introKey: this.config.introKey,
      });
    } catch (error) { this.emit('handshakeError', error); return; }
    this.replay.set(replayKey, Date.now() + 4 * this.config.maxClockSkewSeconds * 1000);
    if (this.clockSkewed(request.blocks)) { this.sendRetry(host, port, header.srcConnId, header.destConnId, TERMINATION_CLOCK_SKEW); return; }
    this.incomingTokens.delete(key); // single use
    const blocks: Ssu2Block[] = [];
    const address = addressBlock(host, port);
    if (address) blocks.push(address);
    const created = createSessionCreated(request.noise, {
      destConnId: header.srcConnId, srcConnId: header.destConnId, netId: this.config.networkId,
      bobIntroKey: this.config.introKey, aliceEphemeralKey: request.ephemeralKey, blocks,
    });
    const localKey = header.destConnId.toString('hex');
    const existing = this.pendingInbound.get(localKey);
    if (existing) this.dropInbound(existing);
    const pending: InboundHandshake = {
      host, port, localConnId: Buffer.from(header.destConnId), remoteConnId: Buffer.from(header.srcConnId), bob: created.state,
      packet: created.packet, fragments: new Map(), attempts: 0,
      deadline: setTimeout(() => this.dropInbound(pending), 12_000),
    };
    pending.deadline.unref();
    this.pendingInbound.set(localKey, pending);
    this.transmitInbound(pending);
  }

  private transmitInbound(pending: InboundHandshake): void {
    this.send(pending.packet, pending.host, pending.port);
    const delay = [1_000, 2_000, 4_000][pending.attempts];
    if (delay === undefined) return;
    pending.timer = setTimeout(() => {
      if (this.pendingInbound.get(pending.localConnId.toString('hex')) !== pending) return;
      pending.attempts++;
      this.transmitInbound(pending);
    }, delay);
    pending.timer.unref();
  }

  private dropInbound(pending: InboundHandshake): void {
    const key = pending.localConnId.toString('hex');
    if (this.pendingInbound.get(key) === pending) this.pendingInbound.delete(key);
    if (pending.timer) clearTimeout(pending.timer);
    clearTimeout(pending.deadline);
  }

  private onSessionConfirmed(pending: InboundHandshake, packet: Buffer, host: string, port: number): void {
    let fragment: ReturnType<typeof openSessionConfirmedHeader>;
    try { fragment = openSessionConfirmedHeader(packet, this.config.introKey, pending.bob.confirmedHeaderKey); } catch { return; }
    if (pending.total !== undefined && pending.total !== fragment.total) return;
    pending.total = fragment.total;
    if (fragment.fragment === 0) pending.header0 = fragment.headerBytes;
    pending.fragments.set(fragment.fragment, Buffer.from(packet.subarray(16)));
    if (!pending.header0 || pending.fragments.size < fragment.total) return;
    const parts: Buffer[] = [];
    for (let index = 0; index < fragment.total; index++) {
      const part = pending.fragments.get(index);
      if (!part) return;
      parts.push(part);
    }
    let confirmed: ReturnType<typeof processSessionConfirmed>;
    try { confirmed = processSessionConfirmed(pending.header0, Buffer.concat(parts), pending.bob); }
    catch (error) { this.emit('handshakeError', error); this.dropInbound(pending); return; }
    this.dropInbound(pending);
    try {
      const riBlock = confirmed.blocks[0];
      if (!riBlock || riBlock.type !== BLK_ROUTER_INFO || riBlock.data.length < 2) throw new Error('Session Confirmed must start with a RouterInfo block');
      const riBytes = (riBlock.data[0]! & 2) ? gunzipSync(riBlock.data.subarray(2), { maxOutputLength: 64 * 1024 }) : Buffer.from(riBlock.data.subarray(2));
      const info = parseRouterInfo(riBytes);
      if (!verifyRouterInfoSignature(info)) throw new Error('Session Confirmed RouterInfo signature is invalid');
      if (info.options.get('netId') !== String(this.config.networkId)) throw new Error('Session Confirmed RouterInfo is for another network');
      const keys = findSsu2AddressByStaticKey(info, confirmed.aliceStaticKey);
      if (!keys) throw new Error('Session Confirmed RouterInfo lacks an SSU2 address matching the proven static key');
      const session = new Ssu2Session({
        role: 'bob', remoteHost: host, remotePort: port, localConnId: pending.localConnId, remoteConnId: pending.remoteConnId,
        ownIntroKey: this.config.introKey, remoteIntroKey: keys.introKey, send: confirmed.keys.ba, receive: confirmed.keys.ab,
        remoteIdentityHash: info.identityHash, maxPacketSize: this.config.mtu - IPV4_UDP_OVERHEAD,
        sendPacket: bytes => this.send(bytes, session.remoteHost, session.remotePort),
        ...(this.config.keepaliveMs === undefined ? {} : { keepaliveMs: this.config.keepaliveMs }),
      });
      this.registerSession(session);
      session.sendAckNow(); // ACK packet 0 (Session Confirmed)
      session.sendNewToken(this.issueToken(host, port), Date.now() + TOKEN_LIFETIME_MS);
      const token = this.incomingTokens.get(endpointKey(host, port));
      if (token) token.expires = Date.now() + TOKEN_LIFETIME_MS;
      this.emit('routerInfo', riBytes, info);
      this.emit('connection', session);
    } catch (error) {
      // Spec: drop without responding on most Session Confirmed errors.
      this.emit('handshakeError', error);
    }
  }

  private registerSession(session: Ssu2Session): void {
    const key = session.localConnId.toString('hex');
    this.sessions.set(key, session);
    session.on('newToken', ({ token, expiresMs }: { token: Buffer; expiresMs: number }) => {
      this.outgoingTokens.set(session.endpointKey, { token, expires: Math.min(expiresMs, Date.now() + TOKEN_LIFETIME_MS) });
    });
    session.on('observedAddress', address => { this.observedAddress = address; this.emit('observedAddress', address); });
    session.once('close', () => { if (this.sessions.get(key) === session) this.sessions.delete(key); });
    this.emit('session', session);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.replay) if (value < now) this.replay.delete(key);
    for (const [key, value] of this.incomingTokens) if (value.expires < now) this.incomingTokens.delete(key);
    for (const [key, value] of this.outgoingTokens) if (value.expires < now) this.outgoingTokens.delete(key);
  }

  /** Exposed for diagnostics/tests. */
  hasOutgoingToken(host: string, port: number): boolean { return this.outgoingTokens.has(endpointKey(host, port)); }
}

