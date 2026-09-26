import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, link, mkdir, open, readFile, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { RouterIdentityKeys } from './identity.ts';
import { createRouterIdentity } from './identity.ts';

const IDENTITY_FILE = 'router-identity.json';
const MAX_FILE_BYTES = 16 * 1024;
type IdentityFile = { format: 1; identity: string; signingPrivateKey: string; encryptionPrivateKey: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function decodeBase64(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`Invalid ${label} encoding`);
  return Buffer.from(value, 'base64');
}
function encodePrivateKey(key: RouterIdentityKeys['signingPrivateKey']): string {
  const der = key.export({ format: 'der', type: 'pkcs8' });
  if (!Buffer.isBuffer(der)) throw new Error('Unable to serialize private key');
  return der.toString('base64');
}

function decodeIdentityFile(json: string): RouterIdentityKeys {
  let parsed: unknown;
  try { parsed = JSON.parse(json); } catch { throw new Error('Router identity file is not valid JSON'); }
  if (!isRecord(parsed) || parsed.format !== 1) throw new Error('Unsupported router identity file format');
  const identity = decodeBase64(parsed.identity, 'identity');
  if (identity.length !== 391 || identity[384] !== 5 || identity.readUInt16BE(385) !== 4 || identity.readUInt16BE(387) !== 7 || identity.readUInt16BE(389) !== 4) {
    throw new Error('Persisted identity is not a supported Ed25519/X25519 RouterIdentity');
  }
  const signingPrivateKey = createPrivateKey({ key: decodeBase64(parsed.signingPrivateKey, 'signing private key'), format: 'der', type: 'pkcs8' });
  const encryptionPrivateKey = createPrivateKey({ key: decodeBase64(parsed.encryptionPrivateKey, 'encryption private key'), format: 'der', type: 'pkcs8' });
  const signingPublic = createPublicKey(signingPrivateKey).export({ format: 'der', type: 'spki' });
  const encryptionPublic = createPublicKey(encryptionPrivateKey).export({ format: 'der', type: 'spki' });
  if (!Buffer.isBuffer(signingPublic) || !Buffer.isBuffer(encryptionPublic) ||
      !signingPublic.subarray(-32).equals(identity.subarray(352, 384)) ||
      !encryptionPublic.subarray(-32).equals(identity.subarray(0, 32))) {
    throw new Error('Persisted private keys do not match RouterIdentity public keys');
  }
  return {
    identity,
    identityHash: createHash('sha256').update(identity).digest(),
    signingPrivateKey,
    encryptionPrivateKey,
  };
}

function encodeIdentityFile(keys: RouterIdentityKeys): string {
  const file: IdentityFile = {
    format: 1,
    identity: keys.identity.toString('base64'),
    signingPrivateKey: encodePrivateKey(keys.signingPrivateKey),
    encryptionPrivateKey: encodePrivateKey(keys.encryptionPrivateKey),
  };
  return `${JSON.stringify(file)}\n`;
}

async function readIdentityFile(filePath: string): Promise<RouterIdentityKeys> {
  const before = await lstat(filePath);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('Router identity path must be a regular file, not a symlink');
  if ((before.mode & 0o077) !== 0) throw new Error('Router identity file permissions are too broad; expected mode 0600');
  if (before.size > MAX_FILE_BYTES) throw new Error('Router identity file exceeds size limit');
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(filePath, flags);
  try {
    const after = await handle.stat();
    if (!after.isFile() || after.ino !== before.ino || after.dev !== before.dev) throw new Error('Router identity file changed during open');
    if (after.size > MAX_FILE_BYTES) throw new Error('Router identity file exceeds size limit');
    return decodeIdentityFile(await handle.readFile('utf8'));
  } finally { await handle.close(); }
}

/** Loads a persistent identity, or atomically creates one with restrictive permissions. */
export async function loadOrCreateRouterIdentity(stateDir: string): Promise<RouterIdentityKeys> {
  if (!path.isAbsolute(stateDir)) throw new Error('Router state directory must be an absolute path');
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const directory = await lstat(stateDir);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error('Router state directory must be a real directory, not a symlink');
  await chmod(stateDir, 0o700);
  const canonicalDir = await realpath(stateDir);
  const destination = path.join(canonicalDir, IDENTITY_FILE);
  try { return await readIdentityFile(destination); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }

  const generated = createRouterIdentity();
  const temporary = path.join(canonicalDir, `.identity-${process.pid}-${randomUUID()}.tmp`);
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(encodeIdentityFile(generated), 'utf8');
    await handle.sync();
  } finally { await handle.close(); }
  try {
    try { await link(temporary, destination); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
    const directoryHandle = await open(canonicalDir, 'r');
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally { await unlink(temporary).catch(() => undefined); }
  return readIdentityFile(destination);
}
