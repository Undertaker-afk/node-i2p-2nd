import { createHash, randomInt } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { RouterIdentityKeys } from '../identity.ts';
import type { I2npMessage } from '../protocol/i2np.ts';
import type { Ntcp2Connection } from '../transport/ntcp2/connection.ts';
import { processTunnelDataLayer, removeTunnelDataLayer } from './data.ts';
import { decodeTunnelDataPayload, decodeTunnelGatewayPayload, encodeTunnelDataPayload, encodeTunnelGatewayPayload } from './messages.ts';
import { unwrapEciesExistingSessionGarlicMessage, unwrapEciesRouterGarlicMessage, wrapEciesExistingSessionGarlicMessage } from './garlic.ts';
import { buildTunnelMessageFragments } from './fragments.ts';
import { TunnelFragmentReassembler } from './reassembly.ts';
import {
  decryptShortBuildRequestRecord, encodeShortBuildReplyPlaintext, encryptShortTunnelBuildReply,
  encryptShortTunnelBuildTransitRequest, parseShortTunnelBuildPayload,
  SHORT_BUILD_ENDPOINT_FLAG, SHORT_BUILD_GATEWAY_FLAG,
} from './short-build.ts';

const I2NP_GARLIC = 11;
const I2NP_TUNNEL_DATA = 18;
const I2NP_TUNNEL_GATEWAY = 19;
const I2NP_SHORT_TUNNEL_BUILD = 25;
const I2NP_SHORT_TUNNEL_BUILD_REPLY = 26;
const TRANSIT_TUNNEL_TTL_MS = 600_000;
const REPLAY_TTL_MS = 1_200_000;
const MAX_TUNNELS_DEFAULT = 5_000;
const MAX_PENDING_BUILDS = 2_000;
const MAX_REPLAY_ENTRIES = 100_000;

type TransitTunnel = {
  receiveTunnelId: number;
  nextTunnelId: number;
  nextIdentityHash: Buffer;
  layerKey: Buffer;
  ivKey: Buffer;
  endpoint: boolean;
  gateway: boolean;
  expiresAt: number;
};
type InboundEndpoint = {
  tunnelId: number;
  layerKeys: { layerKey: Buffer; ivKey: Buffer }[];
  expiresAt: number;
};
type OutboundEndpoint = {
  tunnelId: number;
  layerKey: Buffer;
  ivKey: Buffer;
  expiresAt: number;
};
export type TransitTunnelServiceOptions = {
  identity: RouterIdentityKeys;
  connectPeer: (identityHash: Buffer) => Promise<Ntcp2Connection>;
  maxTunnels?: number;
  allowTransit?: boolean;
};

/** Handles ECIES Short Tunnel Build participation and forwards established AES tunnel messages. */
export class TransitTunnelService extends EventEmitter {
  readonly identity: RouterIdentityKeys;
  private readonly connectPeer: (identityHash: Buffer) => Promise<Ntcp2Connection>;
  private readonly maxTunnels: number;
  private readonly allowTransit: boolean;
  private readonly tunnels = new Map<number, TransitTunnel>();
  private readonly inboundEndpoints = new Map<number, InboundEndpoint>();
  private readonly outboundEndpoints = new Map<number, OutboundEndpoint>();
  private readonly reassembler = new TunnelFragmentReassembler();
  private readonly replay = new Map<string, number>();
  private readonly outboundBuildReplies = new Map<string, { key: Buffer; tag: Buffer; expiresAt: number }>();
  private readonly inboundBuildReplies = new Map<number, number>();
  private readonly zeroHopInbounds = new Map<number, number>();
  private readonly garlicReplay = new Set<string>();
  private messageId = randomInt(1, 0x1_0000_0000);

  constructor(options: TransitTunnelServiceOptions) {
    super();
    this.identity = options.identity;
    this.connectPeer = options.connectPeer;
    this.maxTunnels = options.maxTunnels ?? MAX_TUNNELS_DEFAULT;
    this.allowTransit = options.allowTransit ?? true;
    if (!Number.isSafeInteger(this.maxTunnels) || this.maxTunnels < 1 || this.maxTunnels > 100_000) throw new RangeError('maxTunnels must be 1..100000');
  }

  get activeTunnels(): number { this.expireTunnels(Date.now()); return this.tunnels.size + this.inboundEndpoints.size + this.outboundEndpoints.size; }

  registerInboundEndpoint(tunnelId: number, layerKeys: readonly { layerKey: Buffer; ivKey: Buffer }[], expiresAt = Date.now() + TRANSIT_TUNNEL_TTL_MS): void {
    if (!Number.isSafeInteger(tunnelId) || tunnelId < 1 || tunnelId > 0xffff_ffff) throw new RangeError('Inbound tunnel ID must be a nonzero uint32');
    if (!Array.isArray(layerKeys) || layerKeys.length < 1 || layerKeys.length > 8) throw new RangeError('Inbound tunnel requires 1..8 layer-key pairs');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + TRANSIT_TUNNEL_TTL_MS + 60_000) throw new RangeError('Inbound tunnel expiration is out of range');
    this.expireTunnels(Date.now());
    if (this.tunnels.has(tunnelId) || this.inboundEndpoints.has(tunnelId) || this.outboundEndpoints.has(tunnelId)) throw new Error('Tunnel ID is already active');
    if (this.tunnels.size + this.inboundEndpoints.size + this.outboundEndpoints.size >= this.maxTunnels) throw new Error('Transit tunnel capacity is full');
    const copied = layerKeys.map(({ layerKey, ivKey }) => {
      if (!Buffer.isBuffer(layerKey) || layerKey.length !== 32 || !Buffer.isBuffer(ivKey) || ivKey.length !== 32) throw new Error('Inbound tunnel keys must be 32-byte AES keys');
      return { layerKey: Buffer.from(layerKey), ivKey: Buffer.from(ivKey) };
    });
    this.inboundEndpoints.set(tunnelId, { tunnelId, layerKeys: copied, expiresAt });
  }

  removeInboundEndpoint(tunnelId: number): boolean {
    const endpoint = this.inboundEndpoints.get(tunnelId);
    if (!endpoint) return false;
    for (const keys of endpoint.layerKeys) { keys.layerKey.fill(0); keys.ivKey.fill(0); }
    this.inboundEndpoints.delete(tunnelId);
    return true;
  }

  /** Installs an OBEP data endpoint; it applies its final AES layer before forwarding the I2NP message. */
  registerOutboundEndpoint(tunnelId: number, keys: { layerKey: Buffer; ivKey: Buffer }, expiresAt = Date.now() + TRANSIT_TUNNEL_TTL_MS): void {
    if (!Number.isSafeInteger(tunnelId) || tunnelId < 1 || tunnelId > 0xffff_ffff) throw new RangeError('Outbound endpoint tunnel ID must be a nonzero uint32');
    if (!Buffer.isBuffer(keys.layerKey) || keys.layerKey.length !== 32 || !Buffer.isBuffer(keys.ivKey) || keys.ivKey.length !== 32) throw new Error('Outbound endpoint keys must be 32-byte AES keys');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + TRANSIT_TUNNEL_TTL_MS + 60_000) throw new RangeError('Outbound endpoint expiration is out of range');
    this.expireTunnels(Date.now());
    if (this.tunnels.has(tunnelId) || this.inboundEndpoints.has(tunnelId) || this.outboundEndpoints.has(tunnelId)) throw new Error('Tunnel ID is already active');
    if (this.tunnels.size + this.inboundEndpoints.size + this.outboundEndpoints.size >= this.maxTunnels) throw new Error('Tunnel capacity is full');
    this.outboundEndpoints.set(tunnelId, {
      tunnelId, layerKey: Buffer.from(keys.layerKey), ivKey: Buffer.from(keys.ivKey), expiresAt,
    });
  }

  removeOutboundEndpoint(tunnelId: number): boolean {
    const endpoint = this.outboundEndpoints.get(tunnelId);
    if (!endpoint) return false;
    endpoint.layerKey.fill(0); endpoint.ivKey.fill(0);
    this.outboundEndpoints.delete(tunnelId);
    return true;
  }

  /** Saves a one-use OBEP reply secret until its Garlic-wrapped type-26 message arrives. */
  registerOutboundBuildReplyKey(key: Buffer, tag: Buffer, expiresAt = Date.now() + 60_000): void {
    if (!Buffer.isBuffer(key) || key.length !== 32 || !Buffer.isBuffer(tag) || tag.length !== 8) throw new Error('Outbound build reply key/tag size is invalid');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 10 * 60_000) throw new RangeError('Outbound build reply expiration is out of range');
    this.expireBuildReplies(Date.now());
    if (this.outboundBuildReplies.size >= MAX_PENDING_BUILDS) throw new Error('Pending outbound build reply limit reached');
    const id = tag.toString('hex');
    if (this.outboundBuildReplies.has(id)) throw new Error('Outbound build reply tag is already registered');
    this.outboundBuildReplies.set(id, { key: Buffer.from(key), tag: Buffer.from(tag), expiresAt });
  }

  /** Waits for a returning inbound ShortTunnelBuild (type 25) addressed to this creator. */
  registerInboundBuildReply(messageId: number, expiresAt = Date.now() + 60_000): void {
    if (!Number.isInteger(messageId) || messageId < 1 || messageId > 0xffff_ffff) throw new RangeError('Inbound build reply message ID must be a nonzero uint32');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 10 * 60_000) throw new RangeError('Inbound build reply expiration is out of range');
    this.expireBuildReplies(Date.now());
    if (this.inboundBuildReplies.size >= MAX_PENDING_BUILDS) throw new Error('Pending inbound build reply limit reached');
    if (this.inboundBuildReplies.has(messageId >>> 0)) throw new Error('Inbound build reply message ID is already registered');
    this.inboundBuildReplies.set(messageId >>> 0, expiresAt);
  }

  cancelInboundBuildReply(messageId: number): boolean { return this.inboundBuildReplies.delete(messageId >>> 0); }

  /** 0-hop inbound gateway/endpoint used to bootstrap the first real tunnels. */
  registerZeroHopInbound(tunnelId: number, expiresAt = Date.now() + TRANSIT_TUNNEL_TTL_MS): void {
    if (!Number.isSafeInteger(tunnelId) || tunnelId < 1 || tunnelId > 0xffff_ffff) throw new RangeError('Zero-hop inbound tunnel ID must be a nonzero uint32');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) throw new RangeError('Zero-hop inbound expiration is out of range');
    this.expireTunnels(Date.now());
    if (this.tunnels.has(tunnelId) || this.inboundEndpoints.has(tunnelId) || this.outboundEndpoints.has(tunnelId) || this.zeroHopInbounds.has(tunnelId)) throw new Error('Tunnel ID is already active');
    this.zeroHopInbounds.set(tunnelId, expiresAt);
  }

  removeZeroHopInbound(tunnelId: number): boolean { return this.zeroHopInbounds.delete(tunnelId); }

  cancelOutboundBuildReplyKey(tag: Buffer): boolean {
    if (!Buffer.isBuffer(tag) || tag.length !== 8) return false;
    const id = tag.toString('hex');
    const pending = this.outboundBuildReplies.get(id);
    if (!pending) return false;
    pending.key.fill(0); pending.tag.fill(0);
    this.outboundBuildReplies.delete(id);
    return true;
  }

  async handleMessage(connection: Ntcp2Connection, message: I2npMessage): Promise<boolean> {
    if (message.type === I2NP_GARLIC) { await this.handleGarlic(connection, message); return true; }
    if (message.type === I2NP_SHORT_TUNNEL_BUILD) {
      if (this.inboundBuildReplies.has(message.id >>> 0)) {
        this.inboundBuildReplies.delete(message.id >>> 0);
        this.emit('inboundBuildReply', message);
        return true;
      }
      await this.handleBuildRequest(connection, message); return true;
    }
    if (message.type === I2NP_TUNNEL_DATA) { await this.handleTunnelData(message); return true; }
    if (message.type === I2NP_TUNNEL_GATEWAY) { await this.handleTunnelGateway(message); return true; }
    return false;
  }

  stop(): void {
    for (const tunnel of this.tunnels.values()) { tunnel.layerKey.fill(0); tunnel.ivKey.fill(0); }
    this.tunnels.clear();
    for (const id of this.inboundEndpoints.keys()) this.removeInboundEndpoint(id);
    for (const id of this.outboundEndpoints.keys()) this.removeOutboundEndpoint(id);
    for (const reply of this.outboundBuildReplies.values()) { reply.key.fill(0); reply.tag.fill(0); }
    this.outboundBuildReplies.clear();
    this.inboundBuildReplies.clear();
    this.zeroHopInbounds.clear();
    this.garlicReplay.clear();
    this.reassembler.clear(); this.replay.clear();
  }

  private async handleGarlic(connection: Ntcp2Connection, message: I2npMessage): Promise<void> {
    this.expireBuildReplies(Date.now());
    if (message.payload.length >= 12) {
      const tag = message.payload.subarray(4, 12).toString('hex');
      const pending = this.outboundBuildReplies.get(tag);
      if (pending) {
        this.outboundBuildReplies.delete(tag);
        try {
          const reply = unwrapEciesExistingSessionGarlicMessage(message, pending.key, pending.tag);
          if (reply.type !== I2NP_SHORT_TUNNEL_BUILD_REPLY) throw new Error('Garlic build reply clove did not contain type 26');
          this.emit('outboundBuildReply', reply);
        } catch (error) { this.emit('tunnelError', error); }
        finally { pending.key.fill(0); pending.tag.fill(0); }
        return;
      }
    }
    let unwrapped;
    try {
      unwrapped = unwrapEciesRouterGarlicMessage(message, this.identity.encryptionPrivateKey, this.identity.identity.subarray(0, 32));
    } catch (error) {
      this.emit('tunnelError', error);
      return;
    }
    const replayKey = unwrapped.ephemeralPublicKey.toString('hex');
    if (this.garlicReplay.has(replayKey)) { this.emit('duplicateTunnelMessage', 0); return; }
    this.garlicReplay.add(replayKey);
    if (this.garlicReplay.size > MAX_REPLAY_ENTRIES) this.garlicReplay.delete(this.garlicReplay.keys().next().value!);
    for (const clove of unwrapped.cloves) {
      if (clove.delivery.type !== 'local') {
        this.emit('tunnelError', new Error(`Router Garlic clove delivery ${clove.delivery.type} is not handled`));
        continue;
      }
      await this.handleMessage(connection, clove.message);
    }
  }

  private async handleBuildRequest(connection: Ntcp2Connection, message: I2npMessage): Promise<void> {
    const upstreamIdentityHash = connection.remoteIdentityHash;
    if (!upstreamIdentityHash) { this.emit('buildRejected', 'peer identity unavailable', message); return; }
    let records: Buffer[];
    try { records = parseShortTunnelBuildPayload(message.payload); }
    catch (error) { this.emit('buildRejected', error, message); return; }
    const candidates = records.flatMap((record, index) => record.subarray(0, 16).equals(this.identity.identityHash.subarray(0, 16)) ? [index] : []);
    if (candidates.length === 0) return;
    if (candidates.length !== 1) { this.emit('buildRejected', 'multiple records addressed to local identity', message); return; }
    const recordIndex = candidates[0]!;
    let request;
    try {
      request = decryptShortBuildRequestRecord(records[recordIndex]!, this.identity.identityHash, this.identity.encryptionPrivateKey, this.identity.identity.subarray(0, 32));
      this.validateBuildRequest(request.raw, message);
    } catch (error) { this.emit('buildRejected', error, message); return; }

    const isEndpoint = Boolean(request.flags & SHORT_BUILD_ENDPOINT_FLAG);
    if (request.nextTunnelId === 0 || message.expiration <= Date.now() || (!isEndpoint && request.nextIdentityHash.equals(this.identity.identityHash))) {
      request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
      request.garlicReplyKey?.fill(0); request.garlicReplyTag?.fill(0);
      this.emit('buildRejected', 'invalid next-hop route or expired build request', message);
      return;
    }

    this.expireTunnels(Date.now());
    const routeAlreadyExists = this.tunnels.has(request.receiveTunnelId) || this.inboundEndpoints.has(request.receiveTunnelId) || this.outboundEndpoints.has(request.receiveTunnelId);
    const atCapacity = this.tunnels.size + this.inboundEndpoints.size + this.outboundEndpoints.size >= this.maxTunnels;
    let returnCode = !this.allowTransit || routeAlreadyExists || atCapacity ? 30 : 0;
    if (isEndpoint) {
      let endpointRegistered = false;
      if (returnCode === 0) {
        try {
          this.registerOutboundEndpoint(request.receiveTunnelId, { layerKey: request.layerKey, ivKey: request.ivKey });
          endpointRegistered = true;
        } catch (error) { returnCode = 30; this.emit('buildRejected', error, message); }
      }
      try {
        await this.sendOutboundEndpointReply(request, records, recordIndex, returnCode);
        if (endpointRegistered) this.emit('tunnelEstablished', { receiveTunnelId: request.receiveTunnelId, expiresAt: Date.now() + TRANSIT_TUNNEL_TTL_MS, endpoint: true });
        else this.emit('buildDeclined', { receiveTunnelId: request.receiveTunnelId, returnCode });
      } catch (error) {
        if (endpointRegistered) this.removeOutboundEndpoint(request.receiveTunnelId);
        this.emit('tunnelError', error);
      } finally {
        request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
        request.garlicReplyKey?.fill(0); request.garlicReplyTag?.fill(0);
      }
      return;
    }
    let downstream: Ntcp2Connection;
    try { downstream = await this.connectPeer(request.nextIdentityHash); }
    catch (error) {
      request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
      this.emit('buildRejected', `could not connect to next tunnel hop: ${error instanceof Error ? error.message : String(error)}`, message);
      return;
    }
    if (downstream.remoteIdentityHash && !downstream.remoteIdentityHash.equals(request.nextIdentityHash)) {
      request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
      this.emit('buildRejected', 'connected peer identity does not match requested next hop', message);
      return;
    }

    let candidate: TransitTunnel | undefined;
    if (returnCode === 0) {
      candidate = {
        receiveTunnelId: request.receiveTunnelId, nextTunnelId: request.nextTunnelId,
        nextIdentityHash: Buffer.from(request.nextIdentityHash), layerKey: Buffer.from(request.layerKey),
        ivKey: Buffer.from(request.ivKey), endpoint: false,
        gateway: Boolean(request.flags & SHORT_BUILD_GATEWAY_FLAG), expiresAt: Date.now() + TRANSIT_TUNNEL_TTL_MS,
      };
      // Transit state is installed before forwarding, as the build response returns to the creator
      // over its separate reply tunnel and is never sent back hop-by-hop over this TCP connection.
      this.tunnels.set(candidate.receiveTunnelId, candidate);
    }
    const replyPlaintext = encodeShortBuildReplyPlaintext(returnCode);
    const encrypted = encryptShortTunnelBuildTransitRequest(records, recordIndex, replyPlaintext, request.replyKey, request.handshakeHash);
    const payload = Buffer.concat([Buffer.from([encrypted.length]), ...encrypted]);
    request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
    try {
      await downstream.sendI2np({ type: I2NP_SHORT_TUNNEL_BUILD, id: request.nextMessageId, expiration: message.expiration, payload });
      if (candidate) this.emit('tunnelEstablished', { receiveTunnelId: candidate.receiveTunnelId, expiresAt: candidate.expiresAt });
      else this.emit('buildDeclined', { receiveTunnelId: request.receiveTunnelId, returnCode });
      this.emit('buildForwarded', { receiveTunnelId: request.receiveTunnelId, nextIdentityHash: request.nextIdentityHash, returnCode });
    } catch (error) {
      if (candidate) {
        candidate.layerKey.fill(0); candidate.ivKey.fill(0); this.tunnels.delete(candidate.receiveTunnelId);
      }
      this.emit('tunnelError', error);
    }
  }

  private async sendOutboundEndpointReply(
    request: ReturnType<typeof decryptShortBuildRequestRecord>,
    records: Buffer[],
    recordIndex: number,
    returnCode: number,
  ): Promise<void> {
    const payload = Buffer.concat([
      Buffer.from([records.length]),
      ...encryptShortTunnelBuildReply(records, recordIndex, encodeShortBuildReplyPlaintext(returnCode), request.replyKey, request.handshakeHash),
    ]);
    const expiration = Date.now() + 60_000;
    const reply: I2npMessage = { type: I2NP_SHORT_TUNNEL_BUILD_REPLY, id: request.nextMessageId, expiration, payload };
    if (request.nextIdentityHash.equals(this.identity.identityHash)) {
      const localReplyTunnel = this.tunnels.get(request.nextTunnelId);
      if (!localReplyTunnel?.gateway) throw new Error('Local inbound reply tunnel gateway is unavailable');
      await this.handleTunnelGateway({
        type: 19, id: this.allocateMessageId(), expiration,
        payload: encodeTunnelGatewayPayload(request.nextTunnelId, reply),
      });
      return;
    }
    if (!request.garlicReplyKey || !request.garlicReplyTag) throw new Error('OBEP garlic reply keys are missing');
    const garlic = wrapEciesExistingSessionGarlicMessage(reply, request.garlicReplyKey, request.garlicReplyTag);
    const connection = await this.connectPeer(request.nextIdentityHash);
    if (connection.remoteIdentityHash && !connection.remoteIdentityHash.equals(request.nextIdentityHash)) throw new Error('Reply tunnel gateway identity mismatch');
    await connection.sendI2np({
      type: 19, id: this.allocateMessageId(), expiration: garlic.expiration,
      payload: encodeTunnelGatewayPayload(request.nextTunnelId, garlic),
    });
  }

  private async handleTunnelData(message: I2npMessage): Promise<void> {
    if (message.expiration <= Date.now()) return;
    let data;
    try { data = decodeTunnelDataPayload(message.payload); }
    catch (error) { this.emit('tunnelError', error); return; }
    this.expireTunnels(Date.now());
    this.expireBuildReplies(Date.now());
    const tunnel = this.tunnels.get(data.tunnelId);
    const endpoint = this.inboundEndpoints.get(data.tunnelId);
    const outboundEndpoint = this.outboundEndpoints.get(data.tunnelId);
    if (!tunnel && !endpoint && !outboundEndpoint) return;
    const replayFingerprint = Buffer.allocUnsafe(16);
    for (let index = 0; index < 16; index++) replayFingerprint[index] = data.message[index]! ^ data.message[16 + index]!;
    const replayKey = createHash('sha256').update(replayFingerprint).digest('hex');
    replayFingerprint.fill(0);
    this.expireReplay(Date.now());
    if (this.replay.has(replayKey)) { this.emit('duplicateTunnelMessage', data.tunnelId); return; }
    this.replay.set(replayKey, Date.now() + REPLAY_TTL_MS);
    while (this.replay.size > MAX_REPLAY_ENTRIES) this.replay.delete(this.replay.keys().next().value!);
    if (endpoint || outboundEndpoint) {
      let plaintext: Buffer<ArrayBufferLike> = Buffer.from(data.message);
      try {
        if (outboundEndpoint) {
          const forwarded = processTunnelDataLayer(plaintext, outboundEndpoint.layerKey, outboundEndpoint.ivKey);
          plaintext.fill(0); plaintext = forwarded;
        } else if (endpoint) {
          for (let index = endpoint.layerKeys.length - 1; index >= 0; index--) {
            const keys = endpoint.layerKeys[index]!;
            const unwrapped = removeTunnelDataLayer(plaintext, keys.layerKey, keys.ivKey);
            plaintext.fill(0); plaintext = unwrapped;
          }
        }
        const completed = this.reassembler.add(plaintext);
        if (completed) {
          this.emit('tunnelMessage', completed);
          if (completed.delivery.type === 'local') {
            const tag = completed.message.type === 11 && completed.message.payload.length >= 12 ? completed.message.payload.subarray(4, 12).toString('hex') : '';
            const pending = tag ? this.outboundBuildReplies.get(tag) : undefined;
            if (pending) {
              this.outboundBuildReplies.delete(tag);
              try {
                const reply = unwrapEciesExistingSessionGarlicMessage(completed.message, pending.key, pending.tag);
                if (reply.type !== I2NP_SHORT_TUNNEL_BUILD_REPLY) throw new Error('Garlic build reply clove did not contain type 26');
                this.emit('outboundBuildReply', reply);
              } catch (error) { this.emit('tunnelError', error); }
              finally { pending.key.fill(0); pending.tag.fill(0); }
            } else this.emit('localMessage', completed.message);
          } else if (completed.delivery.type === 'router') this.emit('routerDelivery', completed.delivery, completed.message);
          else this.emit('tunnelDelivery', completed.delivery, completed.message);
        }
      } catch (error) { this.emit('tunnelError', error); }
      finally { plaintext.fill(0); }
      return;
    }
    if (!tunnel) return;
    let transformed: Buffer;
    try { transformed = processTunnelDataLayer(data.message, tunnel.layerKey, tunnel.ivKey); }
    catch (error) { this.emit('tunnelError', error); return; }
    try {
      const next = await this.connectPeer(tunnel.nextIdentityHash);
      await next.sendI2np({ type: I2NP_TUNNEL_DATA, id: this.allocateMessageId(), expiration: Math.min(message.expiration, Date.now() + 60_000), payload: encodeTunnelDataPayload(tunnel.nextTunnelId, transformed) });
      this.emit('tunnelDataForwarded', { receiveTunnelId: tunnel.receiveTunnelId, nextTunnelId: tunnel.nextTunnelId });
    } catch (error) { this.emit('tunnelError', error); }
    finally { transformed.fill(0); }
  }

  private async handleTunnelGateway(message: I2npMessage): Promise<void> {
    if (message.expiration <= Date.now()) return;
    let gateway;
    try { gateway = decodeTunnelGatewayPayload(message.payload); }
    catch (error) { this.emit('tunnelError', error); return; }
    this.expireTunnels(Date.now());
    if (this.zeroHopInbounds.has(gateway.tunnelId)) {
      const synthetic = { remoteIdentityHash: this.identity.identityHash, isClosed: false, sendI2np: async () => undefined } as unknown as Ntcp2Connection;
      await this.handleMessage(synthetic, gateway.message);
      return;
    }
    const tunnel = this.tunnels.get(gateway.tunnelId);
    if (!tunnel || !tunnel.gateway) return;
    const replayKey = createHash('sha256').update(`gateway:${gateway.tunnelId}:${gateway.message.id}`).digest('hex');
    this.expireReplay(Date.now());
    if (this.replay.has(replayKey)) { this.emit('duplicateTunnelMessage', gateway.tunnelId); return; }
    this.replay.set(replayKey, Date.now() + REPLAY_TTL_MS);
    while (this.replay.size > MAX_REPLAY_ENTRIES) this.replay.delete(this.replay.keys().next().value!);
    let frames: Buffer[];
    try { frames = buildTunnelMessageFragments(gateway.message, { type: 'local' }); }
    catch (error) { this.emit('tunnelError', error); return; }
    try {
      const next = await this.connectPeer(tunnel.nextIdentityHash);
      for (const frame of frames) {
        const transformed = processTunnelDataLayer(frame, tunnel.layerKey, tunnel.ivKey);
        try {
          await next.sendI2np({ type: I2NP_TUNNEL_DATA, id: this.allocateMessageId(), expiration: message.expiration, payload: encodeTunnelDataPayload(tunnel.nextTunnelId, transformed) });
        } finally { transformed.fill(0); }
      }
      this.emit('tunnelGatewayForwarded', { receiveTunnelId: gateway.tunnelId, nextTunnelId: tunnel.nextTunnelId, fragments: frames.length });
    } catch (error) { this.emit('tunnelError', error); }
    finally { for (const frame of frames) frame.fill(0); }
  }

  private validateBuildRequest(raw: Buffer, message: I2npMessage): void {
    if (raw.length !== 154) throw new Error('Short-build request length is invalid');
    if ((raw[41] !== 0 || raw[42] !== 0) || raw[43] !== 0) throw new Error('Unsupported ShortBuildRequestRecord flags or layer cipher');
    const flags = raw[40]!;
    if ((flags & 0x3f) !== 0 || (flags & 0xc0) === 0xc0) throw new Error('Invalid ShortBuildRequestRecord flags');
    if (raw.readUInt32BE(0) === 0 || raw.readUInt32BE(4) === 0) throw new Error('Tunnel IDs must be nonzero');
    if (raw.readUInt32BE(48) !== 600) throw new Error('Unsupported tunnel expiration');
    const requestTime = raw.readUInt32BE(44) * 60_000;
    if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() - requestTime) > 10 * 60_000) throw new Error('Tunnel build request time is outside accepted clock skew');
    const length = raw.readUInt16BE(56);
    if (length > 96) throw new Error('Short-build request options exceed limits');
    const content = raw.subarray(58, 58 + length);
    if (content.some(byte => byte < 0x20 || byte > 0x7e)) throw new Error('Tunnel build Mapping contains invalid ASCII');
    if (message.expiration <= Date.now()) throw new Error('Tunnel build I2NP message has expired');
  }

  private allocateMessageId(): number {
    const id = this.messageId >>> 0; this.messageId = (id + 1) >>> 0; if (!this.messageId) this.messageId = 1; return id;
  }
  private expireTunnels(now: number): void {
    for (const [id, tunnel] of this.tunnels) if (tunnel.expiresAt <= now) {
      tunnel.layerKey.fill(0); tunnel.ivKey.fill(0); this.tunnels.delete(id); this.emit('tunnelExpired', id);
    }
    for (const [id, endpoint] of this.inboundEndpoints) if (endpoint.expiresAt <= now) {
      this.removeInboundEndpoint(id); this.emit('tunnelExpired', id);
    }
    for (const [id, endpoint] of this.outboundEndpoints) if (endpoint.expiresAt <= now) {
      this.removeOutboundEndpoint(id); this.emit('tunnelExpired', id);
    }
    for (const [id, expiresAt] of this.zeroHopInbounds) if (expiresAt <= now) {
      this.zeroHopInbounds.delete(id); this.emit('tunnelExpired', id);
    }
  }
  private expireReplay(now: number): void {
    for (const [key, expiration] of this.replay) if (expiration <= now) this.replay.delete(key);
  }
  private expireBuildReplies(now: number): void {
    for (const [tag, pending] of this.outboundBuildReplies) if (pending.expiresAt <= now) {
      pending.key.fill(0); pending.tag.fill(0); this.outboundBuildReplies.delete(tag);
    }
    for (const [id, expiresAt] of this.inboundBuildReplies) if (expiresAt <= now) this.inboundBuildReplies.delete(id);
  }
}
