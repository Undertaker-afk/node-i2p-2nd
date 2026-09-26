import { ByteReader, I2P_HASH_LENGTH } from '../protocol/common.ts';

export type LookupKind = 'routerInfo' | 'exploration';
export type DatabaseLookup = {
  key: Buffer;
  from: Buffer;
  kind: LookupKind;
  replyTunnelId?: number;
  excludedPeers: Buffer[];
};
export type DatabaseSearchReply = { key: Buffer; peers: Buffer[]; from: Buffer };
const MAX_EXCLUDED_PEERS = 512;
function hash(value: Buffer, label: string): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== I2P_HASH_LENGTH) throw new Error(`${label} must be a 32-byte hash`);
  return value;
}

/** Builds an unencrypted RouterInfo or exploratory DatabaseLookup payload. */
export function encodeDatabaseLookup(lookup: DatabaseLookup): Buffer {
  const key = hash(lookup.key, 'lookup key'); const from = hash(lookup.from, 'from hash');
  const isExploration = lookup.kind === 'exploration';
  if (!isExploration && lookup.kind !== 'routerInfo') throw new Error('Unsupported lookup kind');
  if (lookup.excludedPeers.length > MAX_EXCLUDED_PEERS) throw new RangeError(`At most ${MAX_EXCLUDED_PEERS} excluded peers are supported`);
  const tunnelled = lookup.replyTunnelId !== undefined;
  if (tunnelled && (!Number.isInteger(lookup.replyTunnelId) || lookup.replyTunnelId! < 1 || lookup.replyTunnelId! > 0xffff_ffff)) throw new RangeError('replyTunnelId must be a nonzero uint32');
  const flags = ((isExploration ? 3 : 2) << 2) | (tunnelled ? 1 : 0);
  const count = Buffer.allocUnsafe(2); count.writeUInt16BE(lookup.excludedPeers.length);
  const tunnelId = tunnelled ? (() => { const value = Buffer.allocUnsafe(4); value.writeUInt32BE(lookup.replyTunnelId!); return value; })() : Buffer.alloc(0);
  return Buffer.concat([key, from, Buffer.from([flags]), tunnelId, count, ...lookup.excludedPeers.map((peer, index) => hash(peer, `excluded peer ${index}`))]);
}

/** Parses unencrypted DatabaseLookup payloads; encrypted reply modes are rejected. */
export function parseDatabaseLookup(payload: Buffer): DatabaseLookup {
  const reader = new ByteReader(payload, 32 + 32 + 1 + 4 + 2 + MAX_EXCLUDED_PEERS * 32);
  const key = Buffer.from(reader.readHash()); const from = Buffer.from(reader.readHash());
  const flags = reader.readUInt8();
  if ((flags & 0x02) !== 0 || (flags & 0x10) !== 0) throw new Error('Encrypted DatabaseLookup replies are not supported');
  const deliveryFlag = (flags & 1) !== 0;
  const lookupType = (flags >> 2) & 3;
  if (lookupType !== 2 && lookupType !== 3) throw new Error(`Unsupported DatabaseLookup type ${lookupType}`);
  let replyTunnelId: number | undefined;
  if (deliveryFlag) {
    replyTunnelId = reader.readUInt32();
    if (replyTunnelId === 0) throw new Error('DatabaseLookup reply tunnel ID must be nonzero');
  }
  const count = reader.readUInt16();
  if (count > MAX_EXCLUDED_PEERS) throw new Error(`DatabaseLookup excludes too many peers: ${count}`);
  const excludedPeers: Buffer[] = [];
  for (let index = 0; index < count; index++) excludedPeers.push(Buffer.from(reader.readHash()));
  reader.assertEnd();
  return { key, from, kind: lookupType === 3 ? 'exploration' : 'routerInfo', ...(replyTunnelId === undefined ? {} : { replyTunnelId }), excludedPeers };
}

export function encodeDatabaseSearchReply(reply: DatabaseSearchReply): Buffer {
  const key = hash(reply.key, 'search key'); const from = hash(reply.from, 'from hash');
  if (reply.peers.length > 255) throw new RangeError('DatabaseSearchReply supports at most 255 peers');
  return Buffer.concat([key, Buffer.from([reply.peers.length]), ...reply.peers.map((peer, index) => hash(peer, `peer ${index}`)), from]);
}

export function parseDatabaseSearchReply(payload: Buffer): DatabaseSearchReply {
  const reader = new ByteReader(payload, 32 + 1 + 255 * 32 + 32);
  const key = Buffer.from(reader.readHash()); const count = reader.readUInt8();
  const peers: Buffer[] = [];
  for (let index = 0; index < count; index++) peers.push(Buffer.from(reader.readHash()));
  const from = Buffer.from(reader.readHash()); reader.assertEnd();
  return { key, peers, from };
}
