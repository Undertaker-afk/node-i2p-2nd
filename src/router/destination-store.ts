import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, link, mkdir, open, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import { createDestinationKeys, parseDestination, type DestinationKeys } from './protocol/destination.ts';
import { rawPublicKey } from './crypto/x25519.ts';

const DESTINATION_FILE = 'destination.json';
const MAX_FILE_BYTES = 16 * 1024;
type DestinationFile = { format: 1; destination: string; signingPrivateKey: string; encryptionPrivateKey: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeBase64(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`Invalid ${label} encoding`);
  return Buffer.from(value, 'base64');
}

function encodePrivateKey(key: DestinationKeys['signingPrivateKey']): string {
  const der = key.export({ format: 'der', type: 'pkcs8' });
  if (!Buffer.isBuffer(der)) throw new Error('Unable to serialize private key');
  return der.toString('base64');
}

function decodeDestinationFile(json: string): DestinationKeys {
  let parsed: unknown;
  try { parsed = JSON.parse(json); } catch { throw new Error('Destination identity file is not valid JSON'); }
  if (!isRecord(parsed) || parsed.format !== 1) throw new Error('Unsupported destination identity file format');
  const destination = decodeBase64(parsed.destination, 'destination');
  const parsedDest = parseDestination(destination);
  const signingPrivateKey = createPrivateKey({ key: decodeBase64(parsed.signingPrivateKey, 'signing private key'), format: 'der', type: 'pkcs8' });
  const encryptionPrivateKey = createPrivateKey({ key: decodeBase64(parsed.encryptionPrivateKey, 'encryption private key'), format: 'der', type: 'pkcs8' });
  const signingPublic = createPublicKey(signingPrivateKey);
  const encryptionPublic = rawPublicKey(createPublicKey(encryptionPrivateKey));
  if (!rawPublicKey(signingPublic).equals(parsedDest.signingPublicKey)) throw new Error('Persisted destination signing key does not match Destination');
  return {
    destination: parsedDest.destination,
    destinationHash: parsedDest.destinationHash,
    signingPrivateKey,
    encryptionPrivateKey,
    encryptionPublicKey: encryptionPublic,
  };
}

function encodeDestinationFile(keys: DestinationKeys): string {
  const file: DestinationFile = {
    format: 1,
    destination: keys.destination.toString('base64'),
    signingPrivateKey: encodePrivateKey(keys.signingPrivateKey),
    encryptionPrivateKey: encodePrivateKey(keys.encryptionPrivateKey),
  };
  return `${JSON.stringify(file)}\n`;
}

async function readDestinationFile(filePath: string): Promise<DestinationKeys> {
  const before = await lstat(filePath);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('Destination identity path must be a regular file, not a symlink');
  if ((before.mode & 0o077) !== 0) throw new Error('Destination identity file permissions are too broad; expected mode 0600');
  if (before.size > MAX_FILE_BYTES) throw new Error('Destination identity file exceeds size limit');
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(filePath, flags);
  try {
    const after = await handle.stat();
    if (!after.isFile() || after.ino !== before.ino || after.dev !== before.dev) throw new Error('Destination identity file changed during open');
    if (after.size > MAX_FILE_BYTES) throw new Error('Destination identity file exceeds size limit');
    return decodeDestinationFile(await handle.readFile('utf8'));
  } finally { await handle.close(); }
}

/** Loads a persistent destination, or atomically creates one with restrictive permissions. */
export async function loadOrCreateDestinationKeys(stateDir: string): Promise<DestinationKeys> {
  if (!path.isAbsolute(stateDir)) throw new Error('Router state directory must be an absolute path');
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const directory = await lstat(stateDir);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error('Router state directory must be a real directory, not a symlink');
  await chmod(stateDir, 0o700);
  const canonicalDir = await realpath(stateDir);
  const destination = path.join(canonicalDir, DESTINATION_FILE);
  try { return await readDestinationFile(destination); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }

  const generated = createDestinationKeys();
  const temporary = path.join(canonicalDir, `.destination-${process.pid}-${randomUUID()}.tmp`);
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(encodeDestinationFile(generated), 'utf8');
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
  return readDestinationFile(destination);
}
