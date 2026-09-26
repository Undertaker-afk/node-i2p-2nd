import { EventEmitter } from 'node:events';
import { randomBytes, randomInt } from 'node:crypto';
import { encodeDatabaseStoreRouterInfo, parseDatabaseStoreRouterInfo } from './database-store.ts';
import { encodeDatabaseLookup, encodeDatabaseSearchReply, parseDatabaseLookup, parseDatabaseSearchReply } from './messages.ts';
import { parseRouterInfo, verifyRouterInfoSignature } from '../protocol/router-info.ts';
import type { I2npMessage } from '../protocol/i2np.ts';
import type { Ntcp2Connection } from '../transport/ntcp2/connection.ts';
import { VerifiedRouterInfoStore } from './store.ts';

const I2NP_DATABASE_STORE = 1;
const I2NP_DATABASE_LOOKUP = 2;
const I2NP_DATABASE_SEARCH_REPLY = 3;
const I2NP_DELIVERY_STATUS = 10;
const MAX_REPLY_PEERS = 16;

type PeerServiceOptions = {
  identityHash: Buffer;
  routerInfo: Buffer;
  store: VerifiedRouterInfoStore;
  maxKnownPeers?: number;
};

/** Handles direct router-to-router I2NP netDb exchanges over established transports. */
export class PeerNetDbService extends EventEmitter {
  readonly identityHash: Buffer;
  routerInfo: Buffer;
  readonly store: VerifiedRouterInfoStore;
  private readonly maxKnownPeers: number;
  private knownPeers = new Map<string, Buffer>();
  private readonly connections = new Set<Ntcp2Connection>();
  private readonly handlers = new Map<Ntcp2Connection, (message: I2npMessage) => void>();
  private nextMessageId = randomInt(1, 0x1_0000_0000);

  constructor(options: PeerServiceOptions) {
    super();
    if (!Buffer.isBuffer(options.identityHash) || options.identityHash.length !== 32) throw new Error('identityHash must be 32 bytes');
    const localInfo = parseRouterInfo(options.routerInfo);
    if (!verifyRouterInfoSignature(localInfo) || !localInfo.identityHash.equals(options.identityHash)) throw new Error('Local RouterInfo does not match identityHash or has an invalid signature');
    if (localInfo.options.get('netId') !== options.store.expectedNetId) throw new Error('Local RouterInfo and netDb network IDs do not match');
    this.identityHash = Buffer.from(options.identityHash);
    this.routerInfo = Buffer.from(options.routerInfo);
    this.store = options.store;
    this.store.store(localInfo);
    this.maxKnownPeers = options.maxKnownPeers ?? 10_000;
    if (!Number.isSafeInteger(this.maxKnownPeers) || this.maxKnownPeers < 1) throw new RangeError('maxKnownPeers must be a positive safe integer');
  }

  addConnection(connection: Ntcp2Connection): void { this.attach(connection); }

  updateLocalRouterInfo(bytes: Buffer): boolean {
    const info = parseRouterInfo(bytes);
    if (!verifyRouterInfoSignature(info) || !info.identityHash.equals(this.identityHash) || info.options.get('netId') !== this.store.expectedNetId) throw new Error('Updated local RouterInfo is invalid or belongs to another identity/network');
    this.routerInfo = Buffer.from(bytes);
    const inserted = this.store.store(info);
    this.emit('routerInfo', info, inserted);
    return inserted;
  }

  removeConnection(connection: Ntcp2Connection): void {
    this.connections.delete(connection);
    const handler = this.handlers.get(connection);
    if (handler) connection.removeListener('i2np', handler);
    this.handlers.delete(connection);
  }

  /** Attaches a protocol handler to a direct peer connection. */
  attach(connection: Ntcp2Connection): void {
    if (this.handlers.has(connection)) return;
    this.connections.add(connection);
    const handler = (message: I2npMessage) => {
      if (message.expiration <= Date.now()) { this.emit('expiredMessage', message); return; }
      void this.handleMessage(connection, message).catch(error => this.emit('messageError', error, message));
    };
    this.handlers.set(connection, handler);
    connection.on('i2np', handler);
    connection.once('close', () => this.removeConnection(connection));
  }

  /** Announces this router's signed RouterInfo directly to a connected peer. */
  async announceLocalRouterInfo(connection: Ntcp2Connection): Promise<void> {
    if (!this.connections.has(connection)) this.attach(connection);
    await connection.sendI2np({ type: I2NP_DATABASE_STORE, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload: encodeDatabaseStoreRouterInfo(this.routerInfo) });
  }

  /** Sends a direct RouterInfo lookup to an established peer connection. */
  async requestRouterInfo(connection: Ntcp2Connection, key: Buffer, excludedPeers: readonly Buffer[] = []): Promise<void> {
    if (!this.connections.has(connection)) this.attach(connection);
    const payload = encodeDatabaseLookup({ key, from: this.identityHash, kind: 'routerInfo', excludedPeers: [...excludedPeers] });
    await connection.sendI2np({ type: I2NP_DATABASE_LOOKUP, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload });
  }

  stop(): void {
    for (const connection of this.connections) this.removeConnection(connection);
    this.knownPeers.clear();
  }

  async explore(connection: Ntcp2Connection, key = randomBytes(32)): Promise<void> {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Exploration key must be a 32-byte hash');
    if (!this.connections.has(connection)) this.attach(connection);
    const payload = encodeDatabaseLookup({ key, from: this.identityHash, kind: 'exploration', excludedPeers: [] });
    await connection.sendI2np({ type: I2NP_DATABASE_LOOKUP, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload });
  }

  private async handleMessage(connection: Ntcp2Connection, message: I2npMessage): Promise<void> {
    switch (message.type) {
      case I2NP_DATABASE_STORE: {
        const record = parseDatabaseStoreRouterInfo(message.payload);
        const inserted = this.store.store(record.routerInfo);
        this.rememberPeer(record.key);
        if (record.replyToken && record.replyTunnelId === undefined) await this.sendDeliveryStatus(connection, record.replyToken);
        this.emit('routerInfo', record.routerInfo, inserted);
        return;
      }
      case I2NP_DATABASE_LOOKUP:
        await this.handleLookup(connection, parseDatabaseLookup(message.payload));
        return;
      case I2NP_DATABASE_SEARCH_REPLY: {
        const reply = parseDatabaseSearchReply(message.payload);
        for (const peer of reply.peers) this.rememberPeer(peer);
        this.emit('searchReply', reply, connection);
        return;
      }
      default:
        this.emit('message', connection, message);
    }
  }

  private async handleLookup(connection: Ntcp2Connection, lookup: ReturnType<typeof parseDatabaseLookup>): Promise<void> {
    if (lookup.replyTunnelId !== undefined) {
      this.emit('unsupportedReplyRoute', lookup);
      return;
    }
    if (lookup.kind === 'routerInfo') {
      const info = this.store.get(lookup.key);
      if (info) {
        const payload = encodeDatabaseStoreRouterInfo(info.signedData.length ? Buffer.concat([info.signedData, info.signature]) : this.routerInfo);
        await connection.sendI2np({ type: I2NP_DATABASE_STORE, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload });
        this.emit('lookupServed', lookup.key);
        return;
      }
    }
    const peers = this.closestPeers(lookup.key, lookup.excludedPeers, lookup.from);
    const payload = encodeDatabaseSearchReply({ key: lookup.key, peers, from: this.identityHash });
    await connection.sendI2np({ type: I2NP_DATABASE_SEARCH_REPLY, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload });
    this.emit('lookupMiss', lookup.key, peers.length);
  }

  private closestPeers(key: Buffer, excluded: readonly Buffer[], from: Buffer): Buffer[] {
    const blocked = new Set([...excluded.map(peer => peer.toString('hex')), from.toString('hex'), this.identityHash.toString('hex')]);
    const peers = new Map<string, Buffer>();
    for (const info of this.store.all()) peers.set(info.identityHash.toString('hex'), info.identityHash);
    for (const [hash, peer] of this.knownPeers) peers.set(hash, peer);
    return [...peers.entries()].filter(([hash]) => !blocked.has(hash)).map(([, peer]) => Buffer.from(peer))
      .sort((a, b) => compareDistance(a, b, key)).slice(0, MAX_REPLY_PEERS);
  }

  private rememberPeer(hash: Buffer): void {
    if (!Buffer.isBuffer(hash) || hash.length !== 32 || hash.equals(this.identityHash)) return;
    const key = hash.toString('hex');
    this.knownPeers.delete(key); this.knownPeers.set(key, Buffer.from(hash));
    while (this.knownPeers.size > this.maxKnownPeers) this.knownPeers.delete(this.knownPeers.keys().next().value!);
  }

  private async sendDeliveryStatus(connection: Ntcp2Connection, token: number): Promise<void> {
    const payload = Buffer.alloc(12); payload.writeUInt32BE(token, 0); payload.writeBigUInt64BE(BigInt(Date.now()), 4);
    await connection.sendI2np({ type: I2NP_DELIVERY_STATUS, id: this.allocateMessageId(), expiration: Date.now() + 60_000, payload });
  }

  private allocateMessageId(): number {
    const id = this.nextMessageId >>> 0;
    this.nextMessageId = (id + 1) >>> 0;
    if (this.nextMessageId === 0) this.nextMessageId = 1;
    return id;
  }

}

function compareDistance(a: Buffer, b: Buffer, target: Buffer): number {
  for (let index = 0; index < 32; index++) {
    const left = a[index]! ^ target[index]!; const right = b[index]! ^ target[index]!;
    if (left !== right) return left - right;
  }
  return 0;
}
