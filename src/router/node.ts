import { EventEmitter } from 'node:events';
import type net from 'node:net';
import { createHash, randomBytes, randomInt } from 'node:crypto';
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
import { ShortTunnelBuildCreator, type BuiltInboundTunnel, type BuiltOutboundTunnel, type ShortBuildHop, type ShortBuildReplyTunnel } from './tunnel/builder.ts';
import { TunnelPool } from './tunnel/pool.ts';
import { DestinationSessionManager, leaseSetToRemote, type RemoteLease } from './destination-session.ts';
import { createDestinationKeys, encodeDestinationBase64, parseDestination, type DestinationKeys } from './protocol/destination.ts';
import type { LeaseSet2 } from './protocol/leaseset.ts';
import { encodeDatabaseLookup, decryptDatabaseLookupReply, encryptDatabaseLookupReply, parseDatabaseLookup, parseDatabaseSearchReply, encodeDatabaseSearchReply } from './netdb/messages.ts';
import { encodeDatabaseStoreLeaseSet2, encodeDatabaseStoreRouterInfo, parseDatabaseStore } from './netdb/database-store.ts';
import { unwrapEciesRouterGarlicMessage, wrapEciesRouterGarlicMessage } from './tunnel/garlic.ts';
import { ADDRESS_BOOK_SUBSCRIPTIONS, HostsBook } from './netdb/hosts.ts';
import { httpGetOverStream } from './http-client.ts';
import { destinationBytesFromHelper, extractHelperDestination, JUMP_SERVICES } from './http-helper.ts';
import { PeerProfiler } from './peer-profile.ts';
import { TunnelTester } from './tunnel/test.ts';
import { TokenBucket } from './util/rate-limit.ts';
import { I2NP_DELIVERY_STATUS } from './protocol/delivery-status.ts';
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
  destination?: DestinationKeys;
  floodfill?: boolean;
  hopCount?: number;
  exploratoryCount?: number;
  outboundBytesPerSecond?: number;
  enableJump?: boolean;
};

export type RouterStatus = {
  identityHash: string;
  destination: string;
  peers: number;
  netDb: number;
  inboundTunnels: number;
  outboundTunnels: number;
  hosts: number;
  leaseSets: number;
  floodfill: boolean;
  running: boolean;
  exploratoryInbound: number;
  exploratoryOutbound: number;
};

export class DatabaseSearchError extends Error {
  readonly peers: Buffer[];
  constructor(peers: Buffer[]) {
    super('Floodfill does not have this LeaseSet');
    this.peers = peers;
  }
}

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
  readonly tunnelPool: TunnelPool;
  readonly destinations: DestinationSessionManager;
  readonly hosts = new HostsBook();
  readonly profiles = new PeerProfiler();
  readonly tester = new TunnelTester();
  private readonly leaseSets = new Map<string, LeaseSet2>();
  private readonly outboundLimiter: TokenBucket;
  private readonly enableJump: boolean;
  readonly listener: Ntcp2Listener;
  private readonly connectOptions: Ntcp2ConnectOptions;
  private readonly maxOutboundConnections: number;
  private readonly targetOutboundPeers: number;
  private readonly autoBootstrap: boolean;
  private readonly floodfill: boolean;
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
    this.transitTunnels.on('localMessage', message => {
      if (this.dispatchLocalI2np(message)) return;
      this.emit('tunnelMessage', message);
    });
    this.transitTunnels.on('inboundBuildReply', message => this.emit('inboundBuildReply', message));
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
    this.floodfill = options.floodfill ?? false;
    this.enableJump = options.enableJump ?? true;
    this.outboundLimiter = new TokenBucket(options.outboundBytesPerSecond ?? 0);
    this.routerInfoRefreshMs = options.routerInfoRefreshMs ?? 30 * 60 * 1000;
    if (!Number.isSafeInteger(this.maxOutboundConnections) || this.maxOutboundConnections < 1 || this.maxOutboundConnections > 100_000) throw new RangeError('maxOutboundConnections must be between 1 and 100000');
    if (!Number.isSafeInteger(this.targetOutboundPeers) || this.targetOutboundPeers < 0 || this.targetOutboundPeers > this.maxOutboundConnections) throw new RangeError('targetOutboundPeers must be between 0 and maxOutboundConnections');
    if (!Number.isSafeInteger(this.routerInfoRefreshMs) || (this.routerInfoRefreshMs !== 0 && (this.routerInfoRefreshMs < 60_000 || this.routerInfoRefreshMs > 86_400_000))) throw new RangeError('routerInfoRefreshMs must be 0 or 60000..86400000 ms');
    this.destinations = new DestinationSessionManager({
      local: options.destination ?? createDestinationKeys(),
      sendGarlic: async (message, remote) => {
        await this.sendThroughOutboundTunnel(this.tunnelPool.currentOutbound(), message, {
          type: 'tunnel', gatewayHash: remote.gatewayHash, tunnelId: remote.tunnelId,
        });
      },
    });
    this.destinations.on('leaseSet', (ls: LeaseSet2) => this.cacheLeaseSet(ls));
    this.destinations.on('inboundStream', (_stream, nsr, remote) => {
      if (remote.gatewayHash.equals(Buffer.alloc(32))) return;
      void this.sendThroughOutboundTunnel(this.tunnelPool.currentOutbound(), nsr, {
        type: 'tunnel', gatewayHash: remote.gatewayHash, tunnelId: remote.tunnelId,
      }).catch(error => this.emit('tunnelError', error));
    });
    this.tunnelPool = new TunnelPool({
      identity: options.identity, builder: this.shortTunnelBuilds, transit: this.transitTunnels,
      selectPath: (hopCount, excluded) => this.selectTunnelHops(hopCount, excluded),
      sendThroughOutbound: (tunnel, message, delivery) => this.sendThroughOutboundTunnel(tunnel, message, delivery),
      hopCount: options.hopCount ?? 2,
      exploratoryCount: options.exploratoryCount ?? 1,
      testPair: (outbound, inbound) => this.testTunnelPair(outbound, inbound),
      recordHop: (hash, success) => success ? this.profiles.recordSuccess(hash) : this.profiles.recordFailure(hash),
    });
    this.tunnelPool.on('change', () => {
      if (this.tunnelPool.inbound.length) void this.publishLocalLeaseSet().catch(error => this.emit('tunnelError', error));
    });
    this.tunnelPool.on('error', error => this.emit('tunnelError', error));
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
      this.profiles.recordSuccess(identityHash);
      this.emit('peer', identityHash, connection, 'outbound');
      return connection;
    }).catch(error => {
      this.profiles.recordFailure(identityHash);
      throw error;
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

  private readonly pendingLookups = new Map<string, { key: Buffer; tag: Buffer; resolve: (ls: LeaseSet2) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();

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
    const usable = candidates.filter(info => !this.profiles.isUnusable(info.identityHash));
    const pool = usable.length >= hopCount ? usable : candidates;
    if (pool.length < hopCount) throw new Error(`Only ${pool.length} eligible NTCP2 routers are available; ${hopCount} are required`);
    const ranked = this.profiles.rank(pool.map(info => info.identityHash));
    return ranked.slice(0, hopCount).map(hash => Buffer.from(hash));
  }

  selectTunnelHops(hopCount: number, excludedIdentityHashes: readonly Buffer[] = []): ShortBuildHop[] {
    return this.selectOutboundTunnelPath(hopCount, excludedIdentityHashes).map(identityHash => {
      const info = this.netDb.get(identityHash);
      if (!info) throw new Error('Selected tunnel hop disappeared from netDb');
      return { identityHash: Buffer.from(info.identityHash), encryptionPublicKey: Buffer.from(info.identity.subarray(0, 32)) };
    });
  }

  selectFloodfills(target: Buffer, count = 3): Buffer[] {
    if (!Number.isInteger(count) || count < 1 || count > 16) throw new RangeError('Floodfill count must be 1..16');
    const floodfills = this.netDb.all().filter(info => (info.options.get('caps') ?? '').includes('f') && !info.identityHash.equals(this.identity.identityHash));
    const pool = floodfills.length ? floodfills : this.netDb.all().filter(info => !info.identityHash.equals(this.identity.identityHash));
    if (!pool.length) throw new Error('No floodfill or peer is available for a netDb lookup');
    pool.sort((a, b) => {
      for (let index = 0; index < 32; index++) {
        const left = a.identityHash[index]! ^ target[index]!;
        const right = b.identityHash[index]! ^ target[index]!;
        if (left !== right) return left - right;
      }
      return 0;
    });
    return pool.slice(0, Math.min(count, pool.length)).map(info => Buffer.from(info.identityHash));
  }

  selectFloodfill(target: Buffer): Buffer {
    return this.selectFloodfills(target, 1)[0]!;
  }

  async buildInboundTunnel(pathIdentityHashes: readonly Buffer[], outbound?: BuiltOutboundTunnel): Promise<BuiltInboundTunnel> {
    if (!this.isRunning) throw new Error('Router node is not running');
    const hops = this.selectTunnelHops(pathIdentityHashes.length, []).filter((_, index) => pathIdentityHashes[index]);
    const path = pathIdentityHashes.map(identityHash => {
      const info = this.netDb.get(identityHash);
      if (!info) throw new Error(`Verified RouterInfo is not in netDb for ${identityHash.toString('hex')}`);
      return { identityHash: Buffer.from(info.identityHash), encryptionPublicKey: Buffer.from(info.identity.subarray(0, 32)) };
    });
    const via = outbound ?? (this.tunnelPool.outbound[0]);
    const first = path[0]!;
    void hops;
    return this.shortTunnelBuilds.buildInbound(path, via ? {
      sendBuild: async message => {
        const garlic = wrapEciesRouterGarlicMessage(message, first.encryptionPublicKey);
        await this.sendThroughOutboundTunnel(via, garlic, { type: 'router', identityHash: first.identityHash });
      },
    } : {});
  }

  cacheLeaseSet(ls: LeaseSet2): void {
    this.leaseSets.set(ls.destinationHash.toString('hex'), ls);
  }

  getLeaseSet(destinationHash: Buffer): LeaseSet2 | undefined {
    return this.leaseSets.get(destinationHash.toString('hex'));
  }

  async lookupLeaseSet(destinationHash: Buffer, timeoutMs = 20_000): Promise<LeaseSet2> {
    if (!this.isRunning) throw new Error('Router node is not running');
    const cached = this.getLeaseSet(destinationHash);
    if (cached) return cached;
    const tried = new Set<string>();
    const queue = this.selectFloodfills(destinationHash, 8);
    const deadline = Date.now() + timeoutMs;
    let lastError: Error = new Error('LeaseSet lookup timed out');
    while (queue.length && Date.now() < deadline) {
      const floodfill = queue.shift()!;
      const key = floodfill.toString('hex');
      if (tried.has(key)) continue;
      tried.add(key);
      try {
        return await this.lookupLeaseSetOnce(destinationHash, floodfill, [...tried].map(hex => Buffer.from(hex, 'hex')), Math.min(8_000, deadline - Date.now()));
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (error instanceof DatabaseSearchError) for (const peer of error.peers) queue.push(peer);
      }
    }
    throw lastError;
  }

  async sendDatagram(hostname: string, payload: Buffer): Promise<void> {
    const resolved = this.hosts.resolve(hostname);
    const hash = resolved?.hash;
    if (!hash) throw new Error(`Unknown hostname ${hostname}`);
    const ls = this.getLeaseSet(hash) ?? await this.lookupLeaseSet(hash);
    await this.destinations.sendDatagram(leaseSetToRemote(ls), payload);
  }

  status(): RouterStatus {
    return {
      identityHash: this.identity.identityHash.toString('base64'),
      destination: encodeDestinationBase64(this.destinations.local.destination),
      peers: this.peers.size,
      netDb: this.netDb.size,
    inboundTunnels: this.tunnelPool.inbound.length,
    outboundTunnels: this.tunnelPool.outbound.length,
    exploratoryInbound: this.tunnelPool.exploratoryInbound.length,
    exploratoryOutbound: this.tunnelPool.exploratoryOutbound.length,
    hosts: this.hosts.size,
    leaseSets: this.leaseSets.size,
    floodfill: this.floodfill,
    running: this.isRunning,
    };
  }

  async connectDestination(hostname: string): Promise<{ stream: Awaited<ReturnType<DestinationSessionManager['connect']>>; remote: RemoteLease }> {
    const resolved = await this.resolveName(hostname);
    return this.connectToHash(resolved.hash);
  }

  /** Resolves a hostname via hosts.txt, b32, or jump services. */
  async resolveName(hostname: string, timeoutMs = 15_000): Promise<{ destination: Buffer; hash: Buffer }> {
    const resolved = this.hosts.resolve(hostname);
    if (resolved?.destination) return { destination: resolved.destination, hash: resolved.hash };
    if (resolved?.hash) {
      const ls = this.getLeaseSet(resolved.hash) ?? await this.lookupLeaseSet(resolved.hash, timeoutMs);
      return { destination: Buffer.from(ls.destination), hash: Buffer.from(ls.destinationHash) };
    }
    if (this.enableJump) {
      const jumped = await this.lookupViaJump(hostname, timeoutMs);
      if (jumped) return jumped;
    }
    throw new Error(`Unknown hostname ${hostname}; only .b32.i2p, hosts.txt names, and jump services are resolved`);
  }

  async connectToDestination(destination: Buffer): Promise<{ stream: Awaited<ReturnType<DestinationSessionManager['connect']>>; remote: RemoteLease }> {
    return this.connectToHash(parseDestination(destination).destinationHash);
  }

  private async connectToHash(hash: Buffer): Promise<{ stream: Awaited<ReturnType<DestinationSessionManager['connect']>>; remote: RemoteLease }> {
    const ls = this.getLeaseSet(hash) ?? await this.lookupLeaseSet(hash);
    const remote = leaseSetToRemote(ls);
    const stream = await this.destinations.connect(remote);
    return { stream, remote };
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
      await this.outboundLimiter.take(frames.reduce((sum, frame) => sum + frame.length, 0));
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

  async publishLocalLeaseSet(): Promise<Buffer> {
    if (!this.isRunning) throw new Error('Router node is not running');
    const inbound = this.tunnelPool.inbound;
    if (!inbound.length) throw new Error('Cannot publish a LeaseSet2 without an inbound tunnel');
    const now = Math.floor(Date.now() / 1000);
    const leases = inbound.map(tunnel => ({
      gatewayHash: Buffer.from(tunnel.gatewayIdentityHash),
      tunnelId: tunnel.gatewayTunnelId,
      expiresAtSeconds: Math.max(now + 60, Math.floor(tunnel.expiresAt / 1000)),
    }));
    const encoded = this.destinations.createLeaseSet(leases);
    const parsed = parseDatabaseStore(encodeDatabaseStoreLeaseSet2(encoded));
    if (parsed.kind !== 'leaseSet2') throw new Error('Published record was not a LeaseSet2');
    this.cacheLeaseSet(parsed.record.leaseSet);
    const replyTunnel = inbound[0]!;
    const storePayload = encodeDatabaseStoreLeaseSet2(encoded, {
      replyToken: randomInt(1, 0x1_0000_0000),
      replyTunnelId: replyTunnel.gatewayTunnelId,
      replyGateway: replyTunnel.gatewayIdentityHash,
    });
    const store: I2npMessage = { type: 1, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: storePayload };
    const outbound = this.tunnelPool.currentOutbound();
    const floodfills = this.selectFloodfills(parsed.record.leaseSet.destinationHash, 3);
    await Promise.all(floodfills.map(floodfill => this.sendToFloodfill(outbound, floodfill, store)));
    this.emit('leaseSetPublished', parsed.record.leaseSet);
    return encoded;
  }

  async refreshAddressBook(): Promise<{ host: string; path: string; imported: number; error?: string }[]> {
    const results: { host: string; path: string; imported: number; error?: string }[] = [];
    for (const subscription of ADDRESS_BOOK_SUBSCRIPTIONS) {
      try {
        const { stream } = await this.connectDestination(subscription.host);
        try {
          const response = await httpGetOverStream(stream, { host: subscription.host, path: subscription.path, timeoutMs: 120_000 });
          if (response.status >= 400) throw new Error(`HTTP ${response.status} ${response.statusText}`);
          const imported = this.hosts.importHostsTxt(response.body.toString('utf8'));
          results.push({ host: subscription.host, path: subscription.path, imported });
          this.emit('addressBook', { host: subscription.host, imported });
        } finally {
          await stream.close().catch(() => undefined);
        }
      } catch (error) {
        results.push({ host: subscription.host, path: subscription.path, imported: 0, error: error instanceof Error ? error.message : String(error) });
      }
    }
    return results;
  }

  private async sendToFloodfill(outbound: BuiltOutboundTunnel, floodfill: Buffer, message: I2npMessage): Promise<void> {
    const info = this.netDb.get(floodfill);
    const enc = info?.identity.subarray(0, 32);
    const wrapped = enc && enc.length === 32 ? wrapEciesRouterGarlicMessage(message, enc) : message;
    await this.sendThroughOutboundTunnel(outbound, wrapped, { type: 'router', identityHash: floodfill });
  }

  private async lookupLeaseSetOnce(destinationHash: Buffer, floodfill: Buffer, excludedPeers: Buffer[], timeoutMs: number): Promise<LeaseSet2> {
    const inbound = this.tunnelPool.inbound[0] ?? this.tunnelPool.exploratoryInbound[0];
    const outbound = this.tunnelPool.exploratoryOutbound[0] ?? this.tunnelPool.currentOutbound();
    const replyKey = randomBytes(32);
    const replyTag = randomBytes(8);
    const from = inbound ? inbound.gatewayIdentityHash : this.identity.identityHash;
    const payload = encodeDatabaseLookup({
      key: destinationHash, from, kind: 'leaseSet', excludedPeers,
      ...(inbound ? { replyTunnelId: inbound.gatewayTunnelId } : {}),
      encryptedReply: { key: replyKey, tag: replyTag },
    });
    const lookup: I2npMessage = { type: 2, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload };
    await this.sendToFloodfill(outbound, floodfill, lookup);
    return new Promise<LeaseSet2>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingLookups.delete(replyTag.toString('hex'));
        reject(new Error('LeaseSet lookup timed out'));
      }, Math.max(1, timeoutMs));
      this.pendingLookups.set(replyTag.toString('hex'), { key: replyKey, tag: replyTag, resolve, reject, timer });
    });
  }

  private dispatchLocalI2np(message: I2npMessage): boolean {
    if (message.type === I2NP_DELIVERY_STATUS) return this.tester.handle(message);
    if (message.type === 11) {
      if (this.tryEncryptedLookupReply(message) || this.destinations.handleGarlic(message) || this.tryRouterGarlic(message)) return true;
    }
    if (message.type === 2) {
      void this.answerDatabaseLookup(message).catch(error => this.emit('netDbError', error));
      return true;
    }
    if (message.type === 1 || message.type === 3) {
      this.handleNetDbReply(message);
      return true;
    }
    return false;
  }

  private tryRouterGarlic(message: I2npMessage): boolean {
    try {
      const opened = unwrapEciesRouterGarlicMessage(message, this.identity.encryptionPrivateKey, this.identity.identity.subarray(0, 32));
      for (const clove of opened.cloves) this.dispatchLocalI2np(clove.message);
      return true;
    } catch {
      return false;
    }
  }

  private async answerDatabaseLookup(message: I2npMessage): Promise<void> {
    const lookup = parseDatabaseLookup(message.payload);
    let reply: I2npMessage | undefined;
    if (lookup.kind === 'leaseSet') {
      const ls = this.getLeaseSet(lookup.key);
      if (ls) {
        const encoded = Buffer.concat([ls.signedData, ls.signature]);
        reply = { type: 1, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: encodeDatabaseStoreLeaseSet2(encoded) };
      }
    }
    if (!reply && this.floodfill && lookup.kind === 'routerInfo') {
      const info = this.netDb.get(lookup.key);
      if (info) {
        reply = {
          type: 1, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000,
          payload: encodeDatabaseStoreRouterInfo(Buffer.concat([info.signedData, info.signature])),
        };
      }
    }
    if (!reply) {
      const peers = this.selectFloodfills(lookup.key, 8).filter(peer => !peer.equals(lookup.from) && !peer.equals(this.identity.identityHash));
      reply = { type: 3, id: randomInt(1, 0x1_0000_0000), expiration: Date.now() + 60_000, payload: encodeDatabaseSearchReply({ key: lookup.key, peers, from: this.identity.identityHash }) };
    }
    if (lookup.encryptedReply) {
      const body = encryptDatabaseLookupReply(reply, lookup.encryptedReply.key, lookup.encryptedReply.tag);
      const payload = Buffer.allocUnsafe(4 + body.length);
      payload.writeUInt32BE(body.length, 0);
      body.copy(payload, 4);
      reply = { type: 11, id: reply.id, expiration: reply.expiration, payload };
    }
    const outbound = this.tunnelPool.outbound[0];
    if (lookup.replyTunnelId && outbound) {
      await this.sendThroughOutboundTunnel(outbound, reply, { type: 'tunnel', gatewayHash: lookup.from, tunnelId: lookup.replyTunnelId });
      return;
    }
    if (outbound) await this.sendToFloodfill(outbound, lookup.from, reply);
  }

  private handleNetDbReply(message: I2npMessage): void {
    try {
      if (message.type === 1) {
        const parsed = parseDatabaseStore(message.payload);
        if (parsed.kind === 'leaseSet2') {
          this.cacheLeaseSet(parsed.record.leaseSet);
          this.emit('leaseSet', parsed.record.leaseSet);
        } else if (parsed.kind === 'encryptedLeaseSet') {
          this.emit('encryptedLeaseSet', parsed.record.leaseSet);
        }
      } else if (message.type === 3) {
        const reply = parseDatabaseSearchReply(message.payload);
        this.emit('searchReply', reply);
      }
    } catch (error) { this.emit('netDbError', error); }
  }

  private tryEncryptedLookupReply(message: I2npMessage): boolean {
    if (message.payload.length < 12) return false;
    const tag = message.payload.subarray(4, 12).toString('hex');
    const pending = this.pendingLookups.get(tag);
    if (!pending) return false;
    this.pendingLookups.delete(tag);
    clearTimeout(pending.timer);
    try {
      const inner = decryptDatabaseLookupReply(message.payload.subarray(4), pending.key, pending.tag);
      this.handleNetDbReply(inner);
      if (inner.type === 3) {
        const search = parseDatabaseSearchReply(inner.payload);
        throw new DatabaseSearchError(search.peers);
      }
      if (inner.type !== 1) throw new Error('Encrypted lookup missed the LeaseSet');
      const parsed = parseDatabaseStore(inner.payload);
      if (parsed.kind !== 'leaseSet2') throw new Error('Encrypted lookup reply was not a LeaseSet2');
      pending.resolve(parsed.record.leaseSet);
    } catch (error) { pending.reject(error instanceof Error ? error : new Error(String(error))); }
    return true;
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
    this.peers.clear(); this.netDbProtocol.stop(); this.tunnelPool.stop(); this.transitTunnels.stop();
    this.tester.stop(); this.outboundLimiter.stop();
    for (const timer of this.pendingInfoLookups.values()) clearTimeout(timer);
    this.pendingInfoLookups.clear();
    await Promise.allSettled(this.connecting.values());
    this.started = false; this.stopping = false;
    this.emit('stopped');
  }

  async addAddressHelper(hostname: string, helper: string): Promise<Buffer> {
    const bytes = destinationBytesFromHelper(helper);
    this.hosts.add(hostname, bytes);
    this.emit('addressHelper', { hostname, destination: bytes });
    return bytes;
  }

  private async testTunnelPair(outbound: BuiltOutboundTunnel, inbound: BuiltInboundTunnel): Promise<boolean> {
    const message = this.tester.create();
    const waiting = this.tester.wait(message.id, 8_000);
    await this.sendThroughOutboundTunnel(outbound, message, {
      type: 'tunnel', gatewayHash: inbound.gatewayIdentityHash, tunnelId: inbound.gatewayTunnelId,
    });
    const result = await waiting;
    this.emit('tunnelTest', result);
    return true;
  }

  private async lookupViaJump(hostname: string, timeoutMs: number): Promise<{ destination: Buffer; hash: Buffer } | undefined> {
    for (const service of JUMP_SERVICES) {
      const known = this.hosts.resolve(service.host);
      if (!known?.hash) continue;
      try {
        const { stream } = await this.connectToHash(known.hash);
        try {
          const response = await httpGetOverStream(stream, {
            host: service.host, path: service.pathFor(hostname), timeoutMs: Math.min(20_000, Math.max(1_000, timeoutMs)),
          });
          const location = response.headers.get('location') ?? '';
          const helper = extractHelperDestination(location) ?? extractHelperDestination(response.body.toString('utf8'));
          if (!helper) continue;
          const bytes = destinationBytesFromHelper(helper);
          this.hosts.add(hostname, bytes);
          this.emit('addressHelper', { hostname, destination: bytes, via: service.host });
          return { destination: Buffer.from(bytes), hash: createHash('sha256').update(bytes).digest() };
        } finally {
          await stream.close().catch(() => undefined);
        }
      } catch { continue; }
    }
    return undefined;
  }

  private onInbound(connection: Ntcp2Connection): void {
    if (this.stopping) { connection.close(); return; }
    this.netDbProtocol.attach(connection);
    void this.netDbProtocol.announceLocalRouterInfo(connection).catch(error => this.emit('netDbError', error));
    connection.once('close', () => this.emit('peerClosed', connection));
    this.emit('peer', connection.remoteIdentityHash, connection, 'inbound');
  }
}
