import { verifyRouterInfoSignature, type RouterInfo } from '../protocol/router-info.ts';
import { parseDatabaseStoreRouterInfo } from './database-store.ts';

/** Bounded in-memory cache that accepts only signature-verified RouterInfo records. */
function cloneInfo(info: RouterInfo): RouterInfo {
  return {
    ...info,
    identity: Buffer.from(info.identity), identityHash: Buffer.from(info.identityHash),
    addresses: info.addresses.map(address => ({ ...address, options: new Map(address.options) })),
    peers: info.peers.map(peer => Buffer.from(peer)), options: new Map(info.options),
    signature: Buffer.from(info.signature), signedData: Buffer.from(info.signedData),
  };
}

export class VerifiedRouterInfoStore {
  private records = new Map<string, RouterInfo>();
  readonly maxRecords: number;
  readonly expectedNetId: string;
  constructor(maxRecords = 10_000, expectedNetId = '2') {
    this.maxRecords = maxRecords; this.expectedNetId = expectedNetId;
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1) throw new RangeError('maxRecords must be a positive safe integer');
    if (!expectedNetId || /[;=\0\r\n]/.test(expectedNetId)) throw new Error('expectedNetId must be a valid network identifier');
  }

  /** Returns false for a valid but older/equal publication; invalid signatures throw. */
  store(info: RouterInfo): boolean {
    if (!verifyRouterInfoSignature(info)) throw new Error('RouterInfo signature is invalid');
    if (info.options.get('netId') !== this.expectedNetId) throw new Error(`RouterInfo network ID does not match ${this.expectedNetId}`);
    const key = info.identityHash.toString('hex');
    const current = this.records.get(key);
    if (current && current.published >= info.published) return false;
    this.records.delete(key);
    this.records.set(key, cloneInfo(info));
    while (this.records.size > this.maxRecords) {
      const oldestKey = this.records.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.records.delete(oldestKey);
    }
    return true;
  }

  /** Parses a DatabaseStore RouterInfo record, checks its network ID/signature, then indexes by identity hash. Reply tokens are not acted upon. */
  storeDatabaseStore(payload: Buffer): boolean {
    const record = parseDatabaseStoreRouterInfo(payload);
    return this.store(record.routerInfo);
  }

  all(): RouterInfo[] { return [...this.records.values()].map(cloneInfo); }

  get(identityHash: Buffer): RouterInfo | undefined {
    if (!Buffer.isBuffer(identityHash) || identityHash.length !== 32) throw new Error('Router identity hash must be 32 bytes');
    const key = identityHash.toString('hex');
    const info = this.records.get(key);
    if (!info) return undefined;
    // Touch the entry so capacity eviction is least-recently-used.
    this.records.delete(key); this.records.set(key, info);
    return cloneInfo(info);
  }

  delete(identityHash: Buffer): boolean {
    if (!Buffer.isBuffer(identityHash) || identityHash.length !== 32) throw new Error('Router identity hash must be 32 bytes');
    return this.records.delete(identityHash.toString('hex'));
  }

  get size(): number { return this.records.size; }
  clear(): void { this.records.clear(); }
}
