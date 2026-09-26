import net from 'node:net';
import { EventEmitter } from 'node:events';
import type { RouterIdentityKeys } from '../../identity.ts';
import { acceptNtcp2, Ntcp2ReplayCache, type Ntcp2AcceptOptions } from './accept.ts';
import { Ntcp2Connection } from './connection.ts';
import { parseRouterInfo, verifyRouterInfoSignature } from '../../protocol/router-info.ts';

function decodeI2pBase64(value: string): Buffer {
  if (!/^([A-Za-z0-9~-]+)(={0,2})$/.test(value)) throw new Error('Invalid I2P base64 address value');
  const raw = value.replace(/=+$/, '');
  return Buffer.from(raw.replace(/-/g, '+').replace(/~/g, '/') + '='.repeat((4 - raw.length % 4) % 4), 'base64');
}

type ListenerConfig = Omit<Ntcp2AcceptOptions, 'publishedIv'> & {
  identity: RouterIdentityKeys;
  routerInfo: Buffer;
  publishedIv: Buffer;
  host?: string;
  port: number;
  maxConnections?: number;
};

/** TCP NTCP2 acceptor. RouterInfo/address publication and NAT/firewall handling remain caller responsibilities. */
export class Ntcp2Listener extends EventEmitter {
  private readonly config: ListenerConfig;
  private server: net.Server | undefined;
  private readonly pending = new Set<net.Socket>();
  private readonly connections = new Set<Ntcp2Connection>();
  private stopping = false;

  constructor(config: ListenerConfig) {
    super();
    const maxConnections = config.maxConnections ?? 256;
    if (!Number.isInteger(config.port) || config.port < 0 || config.port > 65535) throw new RangeError('port must be between 0 and 65535');
    if (!Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 100_000) throw new RangeError('maxConnections must be between 1 and 100000');
    if (!Buffer.isBuffer(config.routerInfo) || !Buffer.isBuffer(config.publishedIv) || config.publishedIv.length !== 16) throw new TypeError('routerInfo and 16-byte publishedIv are required');
    this.config = { ...config, maxConnections, networkId: config.networkId ?? 2, replayCache: config.replayCache ?? new Ntcp2ReplayCache() };
  }

  get listening(): boolean { return this.server?.listening === true; }
  get activeConnections(): number { return this.connections.size; }
  get pendingHandshakes(): number { return this.pending.size; }
  get address(): net.AddressInfo | null {
    const address = this.server?.address();
    return address && typeof address !== 'string' ? address : null;
  }

  updateRouterInfo(routerInfo: Buffer): void {
    const info = parseRouterInfo(routerInfo);
    const current = parseRouterInfo(this.config.routerInfo);
    if (!verifyRouterInfoSignature(info) || !info.identity.equals(this.config.identity.identity) || info.options.get('netId') !== String(this.config.networkId ?? 2)) throw new Error('Updated RouterInfo does not match listener identity/network');
    if (!info.addresses.some(address => (address.transport === 'NTCP2' || address.transport === 'NTCP') && address.options.get('v')?.split(',').includes('2') && decodeI2pBase64(address.options.get('s') ?? '').equals(this.config.identity.identity.subarray(0, 32)) && decodeI2pBase64(address.options.get('i') ?? '').equals(this.config.publishedIv))) throw new Error('Updated RouterInfo does not retain the listener static key and IV');
    if (!current.identityHash.equals(info.identityHash)) throw new Error('Updated RouterInfo identity hash changed');
    this.config.routerInfo = Buffer.from(routerInfo);
  }

  async start(): Promise<net.AddressInfo> {
    if (this.server) throw new Error('NTCP2 listener has already been started');
    const server = net.createServer({ pauseOnConnect: true });
    this.server = server;
    server.on('connection', socket => this.onSocket(socket));
    server.on('error', error => this.emit('listenerError', error));
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => { server.removeListener('listening', onListening); reject(error); };
      const onListening = () => { server.removeListener('error', onError); resolve(); };
      server.once('error', onError); server.once('listening', onListening);
      server.listen({ host: this.config.host ?? '0.0.0.0', port: this.config.port });
    }).catch(error => { this.server = undefined; throw error; });
    const address = this.address;
    if (!address) throw new Error('NTCP2 listener did not bind a TCP address');
    this.stopping = false;
    this.emit('listening', address);
    return address;
  }

  private onSocket(socket: net.Socket): void {
    if (this.stopping || this.pending.size + this.connections.size >= this.config.maxConnections!) {
      socket.destroy(); this.emit('rejectedConnection'); return;
    }
    socket.setNoDelay(true);
    this.pending.add(socket);
    const acceptOptions: Ntcp2AcceptOptions = {
      publishedIv: this.config.publishedIv,
      replayCache: this.config.replayCache!,
      ...(this.config.networkId === undefined ? {} : { networkId: this.config.networkId }),
      ...(this.config.timeoutMs === undefined ? {} : { timeoutMs: this.config.timeoutMs }),
      ...(this.config.maxClockSkewSeconds === undefined ? {} : { maxClockSkewSeconds: this.config.maxClockSkewSeconds }),
    };
    void acceptNtcp2(socket, this.config.identity, this.config.routerInfo, acceptOptions).then(connection => {
      this.pending.delete(socket);
      if (this.stopping) { connection.close(); return; }
      this.connections.add(connection);
      connection.once('close', () => this.connections.delete(connection));
      this.emit('connection', connection);
    }, error => {
      this.pending.delete(socket);
      if (!this.stopping) this.emit('handshakeError', error);
    });
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    this.stopping = true;
    const server = this.server; this.server = undefined;
    for (const socket of this.pending) socket.destroy();
    this.pending.clear();
    for (const connection of this.connections) connection.close();
    this.connections.clear();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    this.emit('close');
  }
}
