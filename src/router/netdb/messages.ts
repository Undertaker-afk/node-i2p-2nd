import { ByteReader, I2P_HASH_LENGTH } from '../protocol/common.ts';
import { decryptAead, encryptAead } from '../crypto/x25519.ts';
import type { I2npMessage } from '../protocol/i2np.ts';
import { decodeI2np, encodeI2np } from '../protocol/i2np.ts';
import { parseGarlicPayloadBlocks } from '../tunnel/garlic.ts';

export type LookupKind = 'routerInfo' | 'exploration' | 'leaseSet';
export type EncryptedLookupReply = { key: Buffer; tag: Buffer };
export type DatabaseLookup = {
  key: Buffer;
  from: Buffer;
  kind: LookupKind;
  replyTunnelId?: number;
  excludedPeers: Buffer[];
  encryptedReply?: EncryptedLookupReply;
};
export type DatabaseSearchReply = { key: Buffer; peers: Buffer[]; from: Buffer };
const MAX_EXCLUDED_PEERS = 512;
function hash(value: Buffer, label: string): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== I2P_HASH_LENGTH) throw new Error(`${label} must be a 32-byte hash`);
  return value;
}

/** Builds a DatabaseLookup payload. ECIES AEAD replies use flag bit 4, a 32-byte key, and one 8-byte tag. */
export function encodeDatabaseLookup(lookup: DatabaseLookup): Buffer {
  const key = hash(lookup.key, 'lookup key'); const from = hash(lookup.from, 'from hash');
  const kindBits = lookup.kind === 'exploration' ? 3 : lookup.kind === 'leaseSet' ? 1 : lookup.kind === 'routerInfo' ? 2 : -1;
  if (kindBits < 0) throw new Error('Unsupported lookup kind');
  if (lookup.excludedPeers.length > MAX_EXCLUDED_PEERS) throw new RangeError(`At most ${MAX_EXCLUDED_PEERS} excluded peers are supported`);
  const tunnelled = lookup.replyTunnelId !== undefined;
  if (tunnelled && (!Number.isInteger(lookup.replyTunnelId) || lookup.replyTunnelId! < 1 || lookup.replyTunnelId! > 0xffff_ffff)) throw new RangeError('replyTunnelId must be a nonzero uint32');
  const encrypted = lookup.encryptedReply;
  if (encrypted && (!Buffer.isBuffer(encrypted.key) || encrypted.key.length !== 32 || !Buffer.isBuffer(encrypted.tag) || encrypted.tag.length !== 8)) throw new Error('Encrypted lookup reply key/tag is invalid');
  const flags = (kindBits << 2) | (tunnelled ? 1 : 0) | (encrypted ? 0x10 : 0);
  const count = Buffer.allocUnsafe(2); count.writeUInt16BE(lookup.excludedPeers.length);
  const tunnelId = tunnelled ? (() => { const value = Buffer.allocUnsafe(4); value.writeUInt32BE(lookup.replyTunnelId!); return value; })() : Buffer.alloc(0);
  const encryption = encrypted ? Buffer.concat([encrypted.key, Buffer.from([1]), encrypted.tag]) : Buffer.alloc(0);
  return Buffer.concat([key, from, Buffer.from([flags]), tunnelId, count, ...lookup.excludedPeers.map((peer, index) => hash(peer, `excluded peer ${index}`)), encryption]);
}

/** Parses unencrypted DatabaseLookup payloads; encrypted reply modes are rejected. */
export function parseDatabaseLookup(payload: Buffer): DatabaseLookup {
  const reader = new ByteReader(payload, 32 + 32 + 1 + 4 + 2 + MAX_EXCLUDED_PEERS * 32);
  const key = Buffer.from(reader.readHash()); const from = Buffer.from(reader.readHash());
  const flags = reader.readUInt8();
  if ((flags & 0x02) !== 0) throw new Error('Encrypted DatabaseLookup replies are not supported');
  const deliveryFlag = (flags & 1) !== 0;
  const lookupType = (flags >> 2) & 3;
  if (lookupType !== 1 && lookupType !== 2 && lookupType !== 3) throw new Error(`Unsupported DatabaseLookup type ${lookupType}`);
  let replyTunnelId: number | undefined;
  if (deliveryFlag) {
    replyTunnelId = reader.readUInt32();
    if (replyTunnelId === 0) throw new Error('DatabaseLookup reply tunnel ID must be nonzero');
  }
  const count = reader.readUInt16();
  if (count > MAX_EXCLUDED_PEERS) throw new Error(`DatabaseLookup excludes too many peers: ${count}`);
  const excludedPeers: Buffer[] = [];
  for (let index = 0; index < count; index++) excludedPeers.push(Buffer.from(reader.readHash()));
  let encryptedReply: EncryptedLookupReply | undefined;
  if (flags & 0x10) {
    const replyKey = Buffer.from(reader.readBytes(32));
    const tagCount = reader.readUInt8();
    if (tagCount !== 1) throw new Error('ECIES DatabaseLookup replies require exactly one tag');
    encryptedReply = { key: replyKey, tag: Buffer.from(reader.readBytes(8)) };
  }
  reader.assertEnd();
  const kind: LookupKind = lookupType === 3 ? 'exploration' : lookupType === 1 ? 'leaseSet' : 'routerInfo';
  return { key, from, kind, excludedPeers, ...(replyTunnelId === undefined ? {} : { replyTunnelId }), ...(encryptedReply === undefined ? {} : { encryptedReply }) };
}

/** Encrypts a DatabaseStore/SearchReply as an ECIES existing-session netDb reply (flag bit 4). */
export function encryptDatabaseLookupReply(message: I2npMessage, key: Buffer, tag: Buffer): Buffer {
  if (!Buffer.isBuffer(key) || key.length !== 32 || !Buffer.isBuffer(tag) || tag.length !== 8) throw new Error('Lookup reply key/tag is invalid');
  const plaintext = encodeI2np(message);
  const ciphertext = encryptAead(key, Buffer.alloc(12), tag, plaintext);
  return Buffer.concat([tag, ciphertext]);
}

export function decryptDatabaseLookupReply(body: Buffer, key: Buffer, tag: Buffer): I2npMessage {
  if (!Buffer.isBuffer(body) || body.length < 8 + 16) throw new Error('Encrypted lookup reply is truncated');
  if (!body.subarray(0, 8).equals(tag)) throw new Error('Lookup reply tag mismatch');
  const plaintext = decryptAead(key, Buffer.alloc(12), tag, body.subarray(8));
  try { return decodeI2np(plaintext); }
  catch {
    try {
      const parsed = parseGarlicPayloadBlocks(plaintext);
      const clove = parsed.cloves[0];
      if (!clove) throw new Error('Encrypted lookup reply Garlic contained no cloves');
      return clove.message;
    } catch {
      throw new Error('Encrypted lookup reply is neither I2NP nor Garlic');
    }
  }
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
