import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { parseRouterInfo, verifyRouterInfoSignature, type RouterInfo } from '../protocol/router-info.ts';
import { VerifiedRouterInfoStore } from './store.ts';

const MAX_RECORD_BYTES = 1_048_576;
const RECORD_NAME = /^[0-9a-f]{64}\.ri$/;

/** Atomic, permission-restricted disk persistence for signature-verified RouterInfo records. */
export class PersistentRouterInfoStore {
  private readonly memory: VerifiedRouterInfoStore;
  readonly directory: string;
  readonly maxRecords: number;
  readonly expectedNetId: string;
  private constructor(directory: string, maxRecords: number, expectedNetId: string) {
    this.directory = directory; this.maxRecords = maxRecords; this.expectedNetId = expectedNetId;
    this.memory = new VerifiedRouterInfoStore(maxRecords, expectedNetId);
  }

  static async open(directory: string, options: { maxRecords?: number; expectedNetId?: string } = {}): Promise<PersistentRouterInfoStore> {
    if (!path.isAbsolute(directory)) throw new Error('NetDb directory must be an absolute path');
    const maxRecords = options.maxRecords ?? 10_000;
    const expectedNetId = options.expectedNetId ?? '2';
    const store = new PersistentRouterInfoStore(path.resolve(directory), maxRecords, expectedNetId);
    await mkdir(store.directory, { recursive: true, mode: 0o700 });
    const dirStat = await lstat(store.directory);
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) throw new Error('NetDb path must be a real directory, not a symlink');
    await chmod(store.directory, 0o700);
    await store.loadExisting();
    await store.prune();
    return store;
  }

  private async loadExisting(): Promise<void> {
    for (const entry of await readdir(this.directory, { withFileTypes: true })) {
      if (!RECORD_NAME.test(entry.name) || !entry.isFile()) continue;
      const filePath = path.join(this.directory, entry.name);
      const metadata = await lstat(filePath);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_RECORD_BYTES || (metadata.mode & 0o077) !== 0) continue;
      const handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      let encoded: Buffer;
      try {
        const checked = await handle.stat();
        if (!checked.isFile() || checked.ino !== metadata.ino || checked.dev !== metadata.dev || checked.size > MAX_RECORD_BYTES) continue;
        encoded = await handle.readFile();
      } finally { await handle.close(); }
      const info = parseRouterInfo(encoded);
      if (`${info.identityHash.toString('hex')}.ri` !== entry.name) throw new Error(`RouterInfo filename/hash mismatch: ${entry.name}`);
      this.memory.store(info);
    }
  }

  async store(info: RouterInfo): Promise<boolean> {
    if (!verifyRouterInfoSignature(info)) throw new Error('RouterInfo signature is invalid');
    if (info.options.get('netId') !== this.expectedNetId) throw new Error(`RouterInfo network ID does not match ${this.expectedNetId}`);
    const existing = this.memory.get(info.identityHash);
    if (existing && existing.published >= info.published) return false;
    const encoded = Buffer.concat([info.signedData, info.signature]);
    if (encoded.length > MAX_RECORD_BYTES) throw new Error('RouterInfo exceeds persistence size limit');
    const destination = path.join(this.directory, `${info.identityHash.toString('hex')}.ri`);
    const temporary = path.join(this.directory, `.record-${process.pid}-${randomUUID()}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(encoded); await handle.sync(); } finally { await handle.close(); }
    try {
      await rename(temporary, destination);
      const dirHandle = await open(this.directory, 'r');
      try { await dirHandle.sync(); } finally { await dirHandle.close(); }
    } finally { await unlink(temporary).catch(() => undefined); }
    this.memory.store(info);
    await this.prune();
    return true;
  }

  private async prune(): Promise<void> {
    const candidates: Array<{ path: string; mtime: number }> = [];
    for (const entry of await readdir(this.directory, { withFileTypes: true })) {
      if (!RECORD_NAME.test(entry.name) || !entry.isFile()) continue;
      const filePath = path.join(this.directory, entry.name);
      const metadata = await lstat(filePath);
      if (metadata.isFile() && !metadata.isSymbolicLink()) candidates.push({ path: filePath, mtime: metadata.mtimeMs });
    }
    candidates.sort((a, b) => a.mtime - b.mtime);
    while (candidates.length > this.maxRecords) {
      const oldest = candidates.shift()!;
      await unlink(oldest.path);
    }
  }

  all(): RouterInfo[] { return this.memory.all(); }
  get(identityHash: Buffer): RouterInfo | undefined { return this.memory.get(identityHash); }
  get size(): number { return this.memory.size; }
}
