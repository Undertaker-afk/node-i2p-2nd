import { EventEmitter } from 'node:events';
import type net from 'node:net';
import { randomInt } from 'node:crypto';
import type { RouterIdentityKeys } from './identity.ts';
import type { I2npMessage } from './protocol/i2np.ts';
import { VerifiedRouterInfoStore } from './netdb/store.ts';
import { PeerNetDbService } from './netdb/peer-service.ts';
import { reseedRouterInfoStore, type ReseedOptions } from './netdb/reseed.ts';
import { createRouterInfoRecord, parseRouterInfo } from './protocol/router-info.ts';
import { acceptNtcp2 } from './transport/ntcp2/accept.ts';
import { connectNtcp2 } from './transport/ntcp2/connect.ts';
import { Ntcp2Connection } from './transport/ntcp2/connection.ts';
import { Ntcp2Listener } from './transport/ntcp2/listener.ts';
import type { Ntcp2ConnectOptions } from './transport/ntcp2/connect.ts';
import { TransitTunnelService } from './tunnel/transit.ts';
import { ShortTunnelBuildCreator, type BuiltOutboundTunnel, type ShortBuildReplyTunnel } from './tunnel/builder.ts';
import { encodeTunnelGatewayPayload, encodeTunnelDataPayload } from './tunnel/messages.ts';
import { buildTunnelMessageFragments, type TunnelDelivery } from './tunnel/fragments.ts';
import { preprocessOutboundTunnelMessage } from './tunnel/data.ts';

export type NativeRouterNodeOptions = {
  identity: RouterIdentityKeys;
  routerInfo: Buffer;
  netDb: VerifiedRouterInfoStore;
  host: string;
  port: number;
  publishedIv: Buffer;
  networkId?: number;
  timeoutMs?: number;
  maxClockSkewSeconds?: number;
  maxInboundConnections?: number;
  maxOutboundConnections?: number;
  targetOutboundPeers?: number;
  autoBootstrap?: boolean;
  routerInfoRefreshMs?: number;
  maxTransitTunnels?: number;
  maxConcurrentTunnelBuilds?: number;
  acceptTransitTunnels?: boolean;
};

/** Small direct-peer node that composes NTCP2, verified RouterInfo storage, and I2NP netDb handling. */
export class NativeRouterNode extends EventEmitter {
  static async createFromReseed(options: NativeRouterNodeOptions, reseedOptions: ReseedOptions = {}): Promise<NativeRouterNode> {
    if (options.netDb.size < (reseedOptions.minRouterInfos ?? 10)) await reseedRouterInfoStore(options.netDb, reseedOptions);
    return new NativeRouterNode(options);
  }

  readonly identity: RouterIdentityKeys;
  routerInfo: Buffer;
  readonly netDb: VerifiedRouterInfoStore;
  readonly netDbProtocol: PeerNetDbService;
  readonly transitTunnels: TransitTunnelService;
  readonly shortTunnelBuilds: ShortTunnelBuildCreator;
  readonly listener: Ntcp2Listener;
  private readonly connectOptions: Ntcp2ConnectOptions;
  private readonly maxOutboundConnections: number;
  private readonly targetOutboundPeers: number;
  private readonly autoBootstrap: boolean;
  private readonly routerInfoRefreshMs: number;
  private refreshTimer: NodeJS.Timeout | undefined;
  private bootstrapping: Promise<number> | undefined;
  private readonly pendingInfoLookups = new Map<string, NodeJS.Timeout>();
  private readonly peers = new Map<string, Ntcp2Connection>();
  private readonly connecting = new Map<string, Promise<Ntcp2Connection>>();
  private started = false;
  private stopping = false;

  constructor(options: NativeRouterNodeOptions) {
    super();
    const localInfo = parseRouterInfo(options.routerInfo);
    if (!localInfo.identity.equals(options.identity.identity)) throw new Error('Local RouterInfo does not match router identity');
    if (localInfo.options.get('netId') !== String(options.networkId ?? 2) || options.netDb.expectedNetId !== String(options.networkId ?? 2)) throw new Error('Router node network IDs do not match');
    this.identity = options.identity; this.routerInfo = Buffer.from(options.routerInfo); this.netDb = options.netDb;
    this.netDbProtocol = new PeerNetDbService({ identityHash: options.identity.identityHash, routerInfo: options.routerInfo, store: options.netDb });
    this.transitTunnels = new TransitTunnelService({
      identity: options.identity,
      connectPeer: identityHash => this.connectPeer(identityHash),
      ...(options.maxTransitTunnels === undefined ? {} : { maxTunnels: options.maxTransitTunnels }),
      ...(options.acceptTransitTunnels === undefined ? {} : { allowTransit: options.acceptTransitTunnels }),
    });
    this.shortTunnelBuilds = new ShortTunnelBuildCreator({
      identity: options.identity, transitTunnels: this.transitTunnels,
      connectPeer: identityHash => this.connectPeer(identityHash),
      ...(options.maxConcurrentTunnelBuilds === undefined ? {} : { maxConcurrentBuilds: options.maxConcurrentTunnelBuilds }),
    });
    this.netDbProtocol.on('message', (connection, message) => {
      void this.transitTunnels.handleMessage(connection as Ntcp2Connection, message).catch(error => this.emit('tunnelError', error));
    });
    this.transitTunnels.on('tunnelError', error => this.emit('tunnelError', error));
    this.transitTunnels.on('localMessage', message => this.emit('tunnelMessage', message));
    this.transitTunnels.on('outboundBuildReply', message => this.emit('outboundBuildReply', message));
    this.transitTunnels.on('routerDelivery', (delivery, message) => {
      if (delivery.identityHash.equals(this.identity.identityHash)) { this.emit('tunnelMessage', message); return; }
      void this.connectPeer(delivery.identityHash).then(connection => connection.sendI2np(message)).catch(error => this.emit('tunnelError', error));
    });
    this.transitTunnels.on('tunnelDelivery', (delivery, message) => {
      void this.connectPeer(delivery.gatewayHash).then(connection => connection.sendI2np({
        type: 19, id: randomInt(1, 0x1_0000_0000), expiration: message.expiration,
        payload: encodeTunnelGatewayPayload(delivery.tunnelId, message),
      })).catch(error => this.emit('tunnelError', error));
    });
    this.listener = new Ntcp2Listener({
      identity: options.identity, routerInfo: options.routerInfo, publishedIv: options.publishedIv,
      host: options.host, port: options.port,
      ...(options.networkId === undefined ? {} : { networkId: options.networkId }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.maxClockSkewSeconds === undefined ? {} : { maxClockSkewSeconds: options.maxClockSkewSeconds }),
      ...(options.maxInboundConnections === undefined ? {} : { maxConnections: options.maxInboundConnections }),
    });
    this.connectOptions = {
      ...(options.networkId === undefined ? {} : { networkId: options.networkId }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.maxClockSkewSeconds === undefined ? {} : { maxClockSkewSeconds: options.maxClockSkewSeconds }),
    };
    this.maxOutboundConnections = options.maxOutboundConnections ?? 256;
    this.targetOutboundPeers = options.targetOutboundPeers ?? 8;
    this.autoBootstrap = options.autoBootstrap ?? true;
    this.routerInfoRefreshMs = options.routerInfoRefreshMs ?? 30 * 60 * 1000;
    if (!Number.isSafeInteger(this.maxOutboundConnections) || this.maxOutboundConnections < 1 || this.maxOutboundConnections > 100_000) throw new RangeError('maxOutboundConnections must be between 1 and 100000');
    if (!Number.isSafeInteger(this.targetOutboundPeers) || this.targetOutboundPeers < 0 || this.targetOutboundPeers > this.maxOutboundConnections) throw new RangeError('targetOutboundPeers must be between 0 and maxOutboundConnections');
    if (!Number.isSafeInteger(this.routerInfoRefreshMs) || (this.routerInfoRefreshMs !== 0 && (this.routerInfoRefreshMs < 60_000 || this.routerInfoRefreshMs > 86_400_000))) throw new RangeError('routerInfoRefreshMs must be 0 or 60000..86400000 ms');
    this.listener.on('connection', connection => this.onInbound(connection));
    this.listener.on('handshakeError', error => this.emit('transportError', error));
    this.listener.on('listenerError', error => this.emit('transportError', error));
    this.netDbProtocol.on('messageError', (error, message) => this.emit('netDbError', error, message));
    this.netDbProtocol.on('routerInfo', (info, inserted) => {
      const lookupKey = info.identityHash.toString('hex'); const lookupTimer = this.pendingInfoLookups.get(lookupKey);
      if (lookupTimer) clearTimeout(lookupTimer);
      this.pendingInfoLookups.delete(lookupKey);
      this.emit('routerInfo', info, inserted);
      if (inserted && this.autoBootstrap && this.isRunning && this.peers.size < this.targetOutboundPeers) void this.bootstrap().catch(error => this.emit('bootstrapError', error));
    });
    this.netDbProtocol.on('searchReply', (reply, connection) => {
      this.emit('searchReply', reply, connection);
      if (!(connection instanceof Ntcp2Connection)) return;
      for (const peer of reply.peers as Buffer[]) {
        const key = peer.toString('hex');
        if (this.netDb.get(peer) || this.pendingInfoLookups.has(key)) continue;
        const timer = setTimeout(() => this.pendingInfoLookups.delete(key), this.connectOptions.timeoutMs ?? 15_000);
        timer.unref(); this.pendingInfoLookups.set(key, timer);
        void this.netDbProtocol.requestRouterInfo(connection, peer).catch(error => {
          clearTimeout(timer); this.pendingInfoLookups.delete(key); this.emit('netDbError', error);
        });
      }
    });
  }

  get isRunning(): boolean { return this.started && !this.stopping; }
  get activeOutboundConnections(): number { return this.peers.size; }
  get pendingOutboundConnections(): number { return this.connecting.size; }

  async start(): Promise<net.AddressInfo> {
    if (this.started) throw new Error('Router node is already running');
    this.stopping = false;
    const address = await this.listener.start();
    this.started = true;
    if (this.routerInfoRefreshMs > 0) {
      this.refreshTimer = setInterval(() => {
        try { this.refreshRouterInfo(); }
        catch (error) { this.emit('routerInfoError', error); }
      }, this.routerInfoRefreshMs);
      this.refreshTimer.unref();
    }
    this.emit('started', address);
    if (this.autoBootstrap && this.targetOutboundPeers > 0) queueMicrotask(() => { void this.bootstrap().catch(error => this.emit('bootstrapError', error)); });
    return address;
  }

  async connectPeer(identityHash: Buffer): Promise<Ntcp2Connection> {
    if (!this.isRunning) throw new Error('Router node is not running');
    if (!Buffer.isBuffer(identityHash) || identityHash.length !== 32) throw new Error('Peer identity hash must be 32 bytes');
    if (identityHash.equals(this.identity.identityHash)) throw new Error('Cannot connect to self');
    const key = identityHash.toString('hex');
    const existing = this.peers.get(key);
    if (existing && !existing.isClosed) return existing;
    const pending = this.connecting.get(key);
    if (pending) return pending;
    if (this.peers.size + this.connecting.size >= this.maxOutboundConnections) throw new Error('Outbound peer connection limit reached');
    const info = this.netDb.get(identityHash);
    if (!info) throw new Error('Peer RouterInfo is not in the verified netDb');
    const encodedInfo = Buffer.concat([info.signedData, info.signature]);
    const operation = connectNtcp2(encodedInfo, this.identity, this.routerInfo, this.connectOptions).then(connection => {
      if (this.stopping) { connection.close(); throw new Error('Router node stopped while peer connection was opening'); }
      this.peers.set(key, connection); this.netDbProtocol.attach(connection);
      connection.once('close', () => this.peers.delete(key));
      void this.netDbProtocol.announceLocalRouterInfo(connection).catch(error => this.emit('netDbError', error));
      this.emit('peer', identityHash, connection, 'outbound');
      return connection;
    }).finally(() => this.connecting.delete(key));
    this.connecting.set(key, operation);
    return operation;
  }

  refreshRouterInfo(): void {
    if (!this.isRunning) throw new Error('Router node is not running');
    const current = parseRouterInfo(this.routerInfo);
    const refreshed = createRouterInfoRecord(this.identity, Date.now(), current.addresses, current.options);
    this.listener.updateRouterInfo(refreshed);
    this.routerInfo = Buffer.from(refreshed);
    this.netDbProtocol.updateLocalRouterInfo(refreshed);
    for (const connection of this.peers.values()) void this.netDbProtocol.announceLocalRouterInfo(connection).catch(error => this.emit('netDbError', error));
    this.emit('routerInfoRefreshed', this.routerInfo);
  }

  bootstrap(): Promise<number> {
    if (!this.isRunning) return Promise.reject(new Error('Router node is not running'));
    if (this.bootstrapping) return this.bootstrapping;
    const operation = this.bootstrapPeers().finally(() => { this.bootstrapping = undefined; });
    this.bootstrapping = operation;
    return operation;
  }

  /** Selects distinct, fresh ECIES routers with a direct NTCP2 address from the verified netDb. */
  selectOutboundTunnelPath(hopCount: number, excludedIdentityHashes: readonly Buffer[] = []): Buffer[] {
    if (!Number.isSafeInteger(hopCount) || hopCount < 1 || hopCount > 8) throw new RangeError('Outbound path length must be 1..8');
    const excluded = new Set<string>([this.identity.identityHash.toString('hex')]);
    for (const hash of excludedIdentityHashes) {
      if (!Buffer.isBuffer(hash) || hash.length !== 32) throw new Error('Excluded router identity hash must be 32 bytes');
      excluded.add(hash.toString('hex'));
    }
    const now = Date.now();
    const candidates = this.netDb.all().filter(info => {
      if (excluded.has(info.identityHash.toString('hex'))) return false;
      if (info.signatureType !== 7 || info.identity.length !== 391 || info.identity[384] !== 5 || info.identity.readUInt16BE(389) !== 4) return false;
      const age = now - info.published;
      if (age > 24 * 60 * 60 * 1000 || age < -15 * 60 * 1000) return false;
      return info.addresses.some(address => {
        if (!['NTCP2', 'NTCP'].includes(address.transport) || (address.expiration !== 0 && address.expiration <= now)) return false;
        const options = address.options;
        const port = Number(options.get('port'));
        return Boolean(options.get('host')) && Boolean(options.get('s')) && Boolean(options.get('i'))
          && options.get('v')?.split(',').includes('2') === true && Number.isInteger(port) && port >= 1 && port <= 65535;
      });
    });
    for (let index = candidates.length - 1; index > 0; index--) {
      const other = randomInt(index + 1);
      [candidates[index], candidates[other]] = [candidates[other]!, candidates[index]!];
    }
    if (candidates.length < hopCount) throw new Error(`Only ${candidates.length} eligible NTCP2 routers are available; ${hopCount} are required`);
    return candidates.slice(0, hopCount).map(info => Buffer.from(info.identityHash));
  }

  /** Builds a short outbound tunnel using only fresh, signature-verified ECIES RouterInfos in the netDb. */
  async buildOutboundTunnel(pathIdentityHashes: readonly Buffer[], replyTunnel: ShortBuildReplyTunnel): Promise<BuiltOutboundTunnel> {
    if (!this.isRunning) throw new Error('Router node is not running');
    if (!Array.isArray(pathIdentityHashes) || pathIdentityHashes.length < 1 || pathIdentityHashes.length > 8) throw new RangeError('Outbound path must contain 1..8 RouterInfo hashes');
    const hops = pathIdentityHashes.map(identityHash => {
      const info = this.netDb.get(identityHash);
      if (!info) throw new Error(`Verified RouterInfo is not in netDb for ${identityHash.toString('hex')}`);
      if (info.signatureType !== 7 || info.identity.length !== 391 || info.identity[384] !== 5 || info.identity.readUInt16BE(389) !== 4) throw new Error('Short tunnels require Ed25519/X25519 RouterInfos');
      const infoAge = Date.now() - info.published;
      if (infoAge > 24 * 60 * 60 * 1000 || infoAge < -15 * 60 * 1000) throw new Error('Tunnel path contains a stale or future-dated RouterInfo');
      return { identityHash: Buffer.from(info.identityHash), encryptionPublicKey: Buffer.from(info.identity.subarray(0, 32)) };
    });
    return this.shortTunnelBuilds.buildOutbound(hops, replyTunnel);
  }

  /** Selects a path from the verified netDb and builds its outbound tunnel. */
  async buildOutboundTunnelFromNetDb(hopCount: number, replyTunnel: ShortBuildReplyTunnel, excludedIdentityHashes: readonly Buffer[] = []): Promise<BuiltOutboundTunnel> {
    return this.buildOutboundTunnel(this.selectOutboundTunnelPath(hopCount, excludedIdentityHashes), replyTunnel);
  }

  /** Sends one I2NP message through an outbound tunnel returned by buildOutboundTunnel(). */
  async sendThroughOutboundTunnel(tunnel: BuiltOutboundTunnel, message: I2npMessage, delivery: TunnelDelivery): Promise<void> {
    if (!this.isRunning) throw new Error('Router node is not running');
    if (!tunnel || !Array.isArray(tunnel.hops) || tunnel.hops.length < 1 || tunnel.hops.length > 8) throw new Error('Outbound tunnel state is invalid');
    if (tunnel.expiresAt <= Date.now() || message.expiration <= Date.now()) throw new Error('Outbound tunnel or I2NP message has expired');
    const first = tunnel.hops[0]!;
    if (!first.identityHash.equals(tunnel.gatewayIdentityHash) || first.receiveTunnelId !== tunnel.gatewayTunnelId) throw new Error('Outbound tunnel gateway state is inconsistent');
    const frames = buildTunnelMessageFragments(message, delivery);
    try {
      const connection = await this.connectPeer(tunnel.gatewayIdentityHash);
      if (connection.remoteIdentityHash && !connection.remoteIdentityHash.equals(tunnel.gatewayIdentityHash)) throw new Error('Outbound tunnel gateway identity mismatch');
      const layerKeys = tunnel.hops.map(({ layerKey, ivKey }) => ({ layerKey, ivKey }));
      for (const frame of frames) {
        const preprocessed = preprocessOutboundTunnelMessage(frame, layerKeys);
        try {
          await connection.sendI2np({
            type: 18, id: randomInt(1, 0x1_0000_0000), expiration: message.expiration,
            payload: encodeTunnelDataPayload(tunnel.gatewayTunnelId, preprocessed),
          });
        } finally { preprocessed.fill(0); }
      }
    } finally { for (const frame of frames) frame.fill(0); }
  }

  private async bootstrapPeers(): Promise<number> {
    const candidates = this.netDb.all().filter(info => !info.identityHash.equals(this.identity.identityHash) && !this.peers.has(info.identityHash.toString('hex')));
    for (let index = candidates.length - 1; index > 0; index--) {
      const other = randomInt(index + 1); [candidates[index], candidates[other]] = [candidates[other]!, candidates[index]!];
    }
    const bounded = candidates.slice(0, Math.max(32, this.targetOutboundPeers * 4));
    let attempted = 0;
    const failures: Error[] = [];
    while (this.isRunning && this.peers.size < this.targetOutboundPeers && attempted < bounded.length) {
      const count = Math.min(this.targetOutboundPeers - this.peers.size, 4, bounded.length - attempted);
      const batch = bounded.slice(attempted, attempted + count); attempted += batch.length;
      await Promise.all(batch.map(async info => {
        try {
          const connection = await this.connectPeer(info.identityHash);
          void this.netDbProtocol.explore(connection).catch(error => this.emit('netDbError', error));
        } catch (error) { failures.push(error instanceof Error ? error : new Error(String(error))); }
      }));
    }
    this.emit('bootstrapComplete', { connected: this.peers.size, attempted, failed: failures.length });
    if (this.peers.size === 0 && failures.length) throw new AggregateError(failures, 'Could not connect to any known I2P router');
    return this.peers.size;
  }

  async stop(): Promise<void> {
    if (!this.started && !this.listener.listening) return;
    this.stopping = true;
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    this.refreshTimer = undefined;
    await this.listener.stop();
    for (const connection of this.peers.values()) connection.close();
    this.peers.clear(); this.netDbProtocol.stop(); this.transitTunnels.stop();
    for (const timer of this.pendingInfoLookups.values()) clearTimeout(timer);
    this.pendingInfoLookups.clear();
    await Promise.allSettled(this.connecting.values());
    this.started = false; this.stopping = false;
    this.emit('stopped');
  }

  private onInbound(connection: Ntcp2Connection): void {
    if (this.stopping) { connection.close(); return; }
    this.netDbProtocol.attach(connection);
    void this.netDbProtocol.announceLocalRouterInfo(connection).catch(error => this.emit('netDbError', error));
    connection.once('close', () => this.emit('peerClosed', connection));
    this.emit('peer', connection.remoteIdentityHash, connection, 'inbound');
  }
}
