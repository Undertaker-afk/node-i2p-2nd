import { randomInt, randomBytes } from 'node:crypto';
import type { RouterIdentityKeys } from '../identity.ts';
import type { I2npMessage } from '../protocol/i2np.ts';
import type { Ntcp2Connection } from '../transport/ntcp2/connection.ts';
import { TransitTunnelService } from './transit.ts';
import {
  decryptShortTunnelBuildReplyRecord, encodeShortBuildRequestPlaintext,
  encodeShortTunnelBuildPayload, encryptShortBuildRequestRecord, parseShortBuildReplyPlaintext,
  parseShortTunnelBuildPayload, SHORT_BUILD_ENDPOINT_FLAG, SHORT_BUILD_MAX_RECORDS,
  transformShortBuildReplyCoverRecords,
} from './short-build.ts';

const I2NP_SHORT_TUNNEL_BUILD = 25;
const DEFAULT_REPLY_TIMEOUT_MS = 30_000;
const DEFAULT_TUNNEL_LIFETIME_MS = 600_000;

export type ShortBuildHop = {
  identityHash: Buffer;
  encryptionPublicKey: Buffer;
};
export type ShortBuildReplyTunnel = { gatewayIdentityHash: Buffer; tunnelId: number };
export type BuiltOutboundHop = ShortBuildHop & {
  receiveTunnelId: number;
  layerKey: Buffer;
  ivKey: Buffer;
};
export type BuiltOutboundTunnel = {
  gatewayIdentityHash: Buffer;
  gatewayTunnelId: number;
  hops: BuiltOutboundHop[];
  expiresAt: number;
};
export type ShortTunnelBuildCreatorOptions = {
  identity: RouterIdentityKeys;
  transitTunnels: TransitTunnelService;
  connectPeer: (identityHash: Buffer) => Promise<Ntcp2Connection>;
  replyTimeoutMs?: number;
  maxConcurrentBuilds?: number;
  messageId?: () => number;
  tunnelId?: () => number;
};

/** Creates outbound short tunnels over direct NTCP2 and receives their replies via an existing inbound tunnel. */
export class ShortTunnelBuildCreator {
  private readonly identity: RouterIdentityKeys;
  private readonly transitTunnels: TransitTunnelService;
  private readonly connectPeer: (identityHash: Buffer) => Promise<Ntcp2Connection>;
  private readonly replyTimeoutMs: number;
  private readonly maxConcurrentBuilds: number;
  private activeBuilds = 0;
  private readonly messageId: () => number;
  private readonly tunnelId: () => number;

  constructor(options: ShortTunnelBuildCreatorOptions) {
    this.identity = options.identity;
    this.transitTunnels = options.transitTunnels;
    this.connectPeer = options.connectPeer;
    this.replyTimeoutMs = options.replyTimeoutMs ?? DEFAULT_REPLY_TIMEOUT_MS;
    this.maxConcurrentBuilds = options.maxConcurrentBuilds ?? 8;
    if (!Number.isSafeInteger(this.maxConcurrentBuilds) || this.maxConcurrentBuilds < 1 || this.maxConcurrentBuilds > 256) throw new RangeError('maxConcurrentBuilds must be 1..256');
    this.messageId = options.messageId ?? (() => randomInt(1, 0x1_0000_0000));
    this.tunnelId = options.tunnelId ?? (() => randomInt(1, 0x1_0000_0000));
    if (!Number.isSafeInteger(this.replyTimeoutMs) || this.replyTimeoutMs < 1_000 || this.replyTimeoutMs > 60_000) throw new RangeError('replyTimeoutMs must be 1000..60000 ms');
  }

  async buildOutbound(path: readonly ShortBuildHop[], replyTunnel: ShortBuildReplyTunnel): Promise<BuiltOutboundTunnel> {
    if (this.activeBuilds >= this.maxConcurrentBuilds) throw new Error('Concurrent tunnel build limit reached');
    this.activeBuilds++;
    try { return await this.buildOutboundInternal(path, replyTunnel); }
    finally { this.activeBuilds--; }
  }

  private async buildOutboundInternal(path: readonly ShortBuildHop[], replyTunnel: ShortBuildReplyTunnel): Promise<BuiltOutboundTunnel> {
    if (!Array.isArray(path) || path.length < 1 || path.length > SHORT_BUILD_MAX_RECORDS) throw new RangeError('Outbound short tunnel path must contain 1..8 hops');
    if (!Buffer.isBuffer(replyTunnel.gatewayIdentityHash) || replyTunnel.gatewayIdentityHash.length !== 32 || replyTunnel.gatewayIdentityHash.equals(this.identity.identityHash)) throw new Error('Reply tunnel gateway identity is invalid');
    if (!Number.isSafeInteger(replyTunnel.tunnelId) || replyTunnel.tunnelId < 1 || replyTunnel.tunnelId > 0xffff_ffff) throw new RangeError('Reply tunnel ID must be a nonzero uint32');
    for (const hop of path) {
      if (!Buffer.isBuffer(hop.identityHash) || hop.identityHash.length !== 32 || hop.identityHash.equals(this.identity.identityHash)) throw new Error('Tunnel hop identity hash is invalid');
      if (!Buffer.isBuffer(hop.encryptionPublicKey) || hop.encryptionPublicKey.length !== 32) throw new Error('Tunnel hop X25519 public key is invalid');
    }
    const seen = new Set<string>();
    for (const hop of path) {
      const id = hop.identityHash.toString('hex');
      if (seen.has(id)) throw new Error('Outbound tunnel path contains a repeated router');
      seen.add(id);
    }
    const recordCount = Math.max(4, path.length);
    const receiveIds = path.map(() => this.uniqueTunnelId());
    if (new Set(receiveIds).size !== receiveIds.length) throw new Error('Tunnel ID generator returned a duplicate ID');
    const nextMessageIds = path.map(() => this.uniqueMessageId());
    const endpointReplyMessageId = nextMessageIds.at(-1)!;
    const requests = path.map((hop, index) => {
      const isEndpoint = index === path.length - 1;
      const nextHash = isEndpoint ? replyTunnel.gatewayIdentityHash : path[index + 1]!.identityHash;
      const nextId = isEndpoint ? replyTunnel.tunnelId : receiveIds[index + 1]!;
      const plaintext = encodeShortBuildRequestPlaintext({
        receiveTunnelId: receiveIds[index]!, nextTunnelId: nextId, nextIdentityHash: nextHash,
        flags: isEndpoint ? SHORT_BUILD_ENDPOINT_FLAG : 0,
        nextMessageId: nextMessageIds[index]!,
      });
      return encryptShortBuildRequestRecord(hop.identityHash, hop.encryptionPublicKey, plaintext);
    });
    const recordIndexes = Array.from({ length: recordCount }, (_, index) => index);
    for (let index = recordIndexes.length - 1; index > 0; index--) {
      const other = randomInt(index + 1);
      [recordIndexes[index], recordIndexes[other]] = [recordIndexes[other]!, recordIndexes[index]!];
    }
    const requestIndexes = recordIndexes.slice(0, path.length);
    const records: Buffer<ArrayBufferLike>[] = Array.from({ length: recordCount }, () => randomBytes(218));
    for (let hopIndex = 0; hopIndex < requests.length; hopIndex++) records[requestIndexes[hopIndex]!] = requests[hopIndex]!.bytes;
    const payload = encodeShortTunnelBuildPayload(records);
    const endpointKeys = requests.at(-1)!;
    const expectedReplyId = endpointReplyMessageId;
    const expiration = Date.now() + this.replyTimeoutMs + 15_000;
    try { this.transitTunnels.registerOutboundBuildReplyKey(endpointKeys.garlicReplyKey!, endpointKeys.garlicReplyTag!, expiration); }
    catch (error) {
      for (const request of requests) {
        request.replyKey.fill(0); request.handshakeHash.fill(0); request.layerKey.fill(0); request.ivKey.fill(0);
        request.garlicReplyKey?.fill(0); request.garlicReplyTag?.fill(0);
      }
      throw error;
    }

    let timeout: NodeJS.Timeout | undefined;
    let onReply: ((message: I2npMessage) => void) | undefined;
    const replyPromise = new Promise<I2npMessage>((resolve, reject) => {
      onReply = message => {
        if (message.id !== expectedReplyId || message.type !== 26) return;
        cleanup(); resolve(message);
      };
      const cleanup = (): void => {
        if (timeout) clearTimeout(timeout);
        this.transitTunnels.off('outboundBuildReply', onReply!);
        this.transitTunnels.off('localMessage', onReply!);
      };
      timeout = setTimeout(() => { cleanup(); reject(new Error('Outbound tunnel build reply timed out')); }, this.replyTimeoutMs);
      this.transitTunnels.on('outboundBuildReply', onReply);
      this.transitTunnels.on('localMessage', onReply);
    });

    let builtHops: BuiltOutboundHop[] = [];
    try {
      const first = path[0]!;
      const connection = await this.connectPeer(first.identityHash);
      if (connection.remoteIdentityHash && !connection.remoteIdentityHash.equals(first.identityHash)) throw new Error('First tunnel hop connection identity mismatch');
      await connection.sendI2np({
        type: I2NP_SHORT_TUNNEL_BUILD, id: this.uniqueMessageId(),
        expiration: Date.now() + this.replyTimeoutMs + 15_000,
        payload,
      });
      const replyMessage = await replyPromise;
      this.transitTunnels.cancelOutboundBuildReplyKey(endpointKeys.garlicReplyTag!);
      if (replyMessage.expiration <= Date.now()) throw new Error('Outbound tunnel build reply has expired');
      const replyRecords = parseShortTunnelBuildPayload(replyMessage.payload);
      if (replyRecords.length !== recordCount) throw new Error('Outbound tunnel build reply record count does not match request');
      const endpointRecordIndex = requestIndexes.at(-1)!;
      const uncovered = transformShortBuildReplyCoverRecords(replyRecords, endpointRecordIndex, endpointKeys.replyKey);
      builtHops = [];
      try {
        for (let index = 0; index < path.length; index++) {
          const request = requests[index]!;
          const recordIndex = requestIndexes[index]!;
          const clear = decryptShortTunnelBuildReplyRecord(uncovered[recordIndex]!, recordIndex, request.replyKey, request.handshakeHash);
          let status: number;
          try { status = parseShortBuildReplyPlaintext(clear).returnCode; }
          finally { clear.fill(0); }
          if (status !== 0) throw new Error(`Outbound tunnel hop ${index + 1} rejected the request with status ${status}`);
          builtHops.push({
            identityHash: Buffer.from(path[index]!.identityHash), encryptionPublicKey: Buffer.from(path[index]!.encryptionPublicKey),
            receiveTunnelId: receiveIds[index]!, layerKey: Buffer.from(request.layerKey), ivKey: Buffer.from(request.ivKey),
          });
        }
      } finally { for (const record of uncovered) record.fill(0); }
      return {
        gatewayIdentityHash: Buffer.from(path[0]!.identityHash), gatewayTunnelId: receiveIds[0]!,
        hops: builtHops, expiresAt: Date.now() + DEFAULT_TUNNEL_LIFETIME_MS,
      };
    } catch (error) {
      if (onReply) {
        this.transitTunnels.off('outboundBuildReply', onReply);
        this.transitTunnels.off('localMessage', onReply);
      }
      if (timeout) clearTimeout(timeout);
      this.transitTunnels.cancelOutboundBuildReplyKey(endpointKeys.garlicReplyTag!);
      for (const hop of builtHops) { hop.layerKey.fill(0); hop.ivKey.fill(0); }
      throw error;
    } finally {
      for (const request of requests) {
        request.replyKey.fill(0); request.handshakeHash.fill(0);
        request.garlicReplyKey?.fill(0); request.garlicReplyTag?.fill(0);
        request.layerKey.fill(0); request.ivKey.fill(0);
      }
    }
  }

  private uniqueTunnelId(): number {
    const id = this.tunnelId();
    if (!Number.isSafeInteger(id) || id < 1 || id > 0xffff_ffff) throw new RangeError('Tunnel ID generator returned an invalid value');
    return id;
  }
  private uniqueMessageId(): number {
    const id = this.messageId();
    if (!Number.isSafeInteger(id) || id < 1 || id > 0xffff_ffff) throw new RangeError('Message ID generator returned an invalid value');
    return id;
  }
}
