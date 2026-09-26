import { constants, createHash, publicDecrypt, X509Certificate, type KeyObject } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import https from 'node:https';
import { parseRouterInfo } from '../protocol/router-info.ts';
import { VerifiedRouterInfoStore } from './store.ts';

const SU3_HEADER_LENGTH = 40;
const SU3_SIGNATURE_TYPE_RSA_SHA512_4096 = 6;
const SU3_SIGNATURE_LENGTH = 512;
const SU3_CONTENT_TYPE_RESEED = 3;
const DEFAULT_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_ROUTER_INFO_BYTES = 1024 * 1024;
const MAX_ZIP_ENTRIES = 4096;

export const DEFAULT_RESEED_URLS = [
  'https://reseed.diva.exchange/',
  'https://reseed2.i2p.net/',
  'https://reseed-fr.i2pd.xyz/',
  'https://reseed.stormycloud.org/',
  'https://reseed.i2pgit.org/',
  'https://i2pseed.creativecowpat.net:8443/',
  'https://reseed.onion.im/',
  'https://reseed-pl.i2pd.xyz/',
  'https://www2.mk16.de/',
  'https://i2p.novg.net/',
  'https://reseed.sahil.world/',
  'https://i2p.diyarciftci.xyz/',
  'https://furland.horoshij.space/reseed/',
  'https://spiral.likogan.dev/',
] as const;

export type ReseedOptions = {
  urls?: readonly string[];
  timeoutMs?: number;
  maxArchiveBytes?: number;
  minRouterInfos?: number;
  certificateDirectory?: string;
};
export type ReseedResult = { url: string; imported: number; rejected: number; signer: string };

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); table[n] = c >>> 0; }
  return table;
})();
function crc32(bytes: Buffer): number {
  let value = 0xffff_ffff;
  for (const byte of bytes) value = crcTable[(value ^ byte) & 0xff]! ^ (value >>> 8);
  return (value ^ 0xffff_ffff) >>> 0;
}
function readZipEntries(zip: Buffer, options: { maxArchiveBytes: number }): Buffer[] {
  if (zip.length < 22 || zip.length > options.maxArchiveBytes) throw new Error('Reseed ZIP size is invalid');
  const minEnd = Math.max(0, zip.length - 22 - 0xffff); let endOffset = -1;
  for (let offset = zip.length - 22; offset >= minEnd; offset--) {
    if (zip.readUInt32LE(offset) === 0x06054b50 && offset + 22 + zip.readUInt16LE(offset + 20) === zip.length) { endOffset = offset; break; }
  }
  if (endOffset < 0) throw new Error('Reseed ZIP end-of-central-directory record is missing');
  if (zip.readUInt16LE(endOffset + 4) !== 0 || zip.readUInt16LE(endOffset + 6) !== 0) throw new Error('Multi-disk reseed ZIP is unsupported');
  const entryCount = zip.readUInt16LE(endOffset + 10);
  const centralSize = zip.readUInt32LE(endOffset + 12); const centralOffset = zip.readUInt32LE(endOffset + 16);
  if (entryCount > MAX_ZIP_ENTRIES || centralOffset + centralSize > endOffset) throw new Error('Reseed ZIP central directory bounds are invalid');
  const records: Buffer[] = []; let cursor = centralOffset; let totalExpanded = 0;
  for (let entryIndex = 0; entryIndex < entryCount; entryIndex++) {
    if (cursor + 46 > centralOffset + centralSize || zip.readUInt32LE(cursor) !== 0x02014b50) throw new Error('Malformed reseed ZIP central directory');
    const flags = zip.readUInt16LE(cursor + 8); const method = zip.readUInt16LE(cursor + 10);
    const expectedCrc = zip.readUInt32LE(cursor + 16); const compressedLength = zip.readUInt32LE(cursor + 20); const expandedLength = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28); const extraLength = zip.readUInt16LE(cursor + 30); const commentLength = zip.readUInt16LE(cursor + 32);
    const localOffset = zip.readUInt32LE(cursor + 42); const next = cursor + 46 + nameLength + extraLength + commentLength;
    if (next > centralOffset + centralSize) throw new Error('Truncated reseed ZIP central entry');
    const name = zip.toString('utf8', cursor + 46, cursor + 46 + nameLength); cursor = next;
    if (flags & 1) throw new Error('Encrypted reseed ZIP entries are unsupported');
    if (method !== 0 && method !== 8) throw new Error(`Unsupported ZIP compression method ${method}`);
    if (compressedLength > options.maxArchiveBytes || expandedLength > MAX_ROUTER_INFO_BYTES) throw new Error('Reseed ZIP RouterInfo entry exceeds size limits');
    totalExpanded += expandedLength;
    if (totalExpanded > options.maxArchiveBytes) throw new Error('Reseed ZIP expanded size exceeds archive limit');
    if (!name.toLowerCase().endsWith('.dat')) continue;
    if (!name || name.includes('/') || name.includes('\\') || name === '..' || name.includes('\0')) throw new Error('Unsafe RouterInfo filename in reseed ZIP');
    if (localOffset + 30 > zip.length || zip.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('Invalid reseed ZIP local file header');
    const localFlags = zip.readUInt16LE(localOffset + 6); const localMethod = zip.readUInt16LE(localOffset + 8);
    const localNameLength = zip.readUInt16LE(localOffset + 26); const localExtraLength = zip.readUInt16LE(localOffset + 28);
    if (localFlags !== flags || localMethod !== method || localOffset + 30 + localNameLength + localExtraLength + compressedLength > zip.length) throw new Error('Mismatched or truncated reseed ZIP local entry');
    const localName = zip.toString('utf8', localOffset + 30, localOffset + 30 + localNameLength);
    if (localName !== name) throw new Error('Reseed ZIP local/central filenames differ');
    const compressed = zip.subarray(localOffset + 30 + localNameLength + localExtraLength, localOffset + 30 + localNameLength + localExtraLength + compressedLength);
    let decoded: Buffer;
    try { decoded = method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: MAX_ROUTER_INFO_BYTES }); }
    catch (error) { throw new Error(`Invalid compressed RouterInfo in reseed ZIP: ${error instanceof Error ? error.message : String(error)}`); }
    if (decoded.length !== expandedLength || crc32(decoded) !== expectedCrc) throw new Error('Reseed ZIP RouterInfo size or CRC mismatch');
    records.push(decoded);
  }
  if (cursor !== centralOffset + centralSize) throw new Error('Reseed ZIP central directory length mismatch');
  return records;
}

/** Verifies an I2P SU3 reseed bundle and stores supported, signed RouterInfos. */
export function importSu3Reseed(bytes: Buffer, trustedSigners: ReadonlyMap<string, KeyObject>, store: VerifiedRouterInfoStore, options: { maxArchiveBytes?: number; minRouterInfos?: number } = {}): ReseedResult {
  const maxArchiveBytes = options.maxArchiveBytes ?? DEFAULT_MAX_ARCHIVE_BYTES; const minRouterInfos = options.minRouterInfos ?? 1;
  if (!Number.isSafeInteger(maxArchiveBytes) || maxArchiveBytes < 1024 || maxArchiveBytes > DEFAULT_MAX_ARCHIVE_BYTES) throw new RangeError('Reseed maxArchiveBytes is out of range');
  if (!Number.isSafeInteger(minRouterInfos) || minRouterInfos < 1 || minRouterInfos > 1000) throw new RangeError('minRouterInfos must be 1..1000');
  if (!Buffer.isBuffer(bytes) || bytes.length < SU3_HEADER_LENGTH + SU3_SIGNATURE_LENGTH || bytes.length > maxArchiveBytes + 1024) throw new Error('SU3 reseed file size is invalid');
  if (!bytes.subarray(0, 7).equals(Buffer.from('I2Psu3\0', 'ascii'))) throw new Error('Invalid SU3 magic');
  const formatVersion = bytes[7]!; const signatureType = bytes.readUInt16BE(8); const signatureLength = bytes.readUInt16BE(10);
  const versionLength = bytes[13]!; const signerLength = bytes[15]!; const contentLengthBig = bytes.readBigUInt64BE(16);
  if (formatVersion !== 0 || signatureType !== SU3_SIGNATURE_TYPE_RSA_SHA512_4096 || signatureLength !== SU3_SIGNATURE_LENGTH) throw new Error('Unsupported SU3 format or signature type');
  if (bytes[12] !== 0 || bytes[14] !== 0 || bytes[24] !== 0 || bytes[26] !== 0 || bytes[28]! !== 0) throw new Error('SU3 reserved header bytes must be zero');
  if (bytes[25] !== 0 || bytes[27] !== SU3_CONTENT_TYPE_RESEED || bytes.subarray(29, 40).some(byte => byte !== 0)) throw new Error('SU3 file/content type is not a reseed ZIP');
  if (contentLengthBig > BigInt(maxArchiveBytes)) throw new Error('SU3 reseed archive exceeds configured size limit');
  const contentLength = Number(contentLengthBig); const contentOffset = SU3_HEADER_LENGTH + versionLength + signerLength;
  const signatureOffset = contentOffset + contentLength;
  if (signatureOffset + signatureLength !== bytes.length) throw new Error('SU3 content/signature lengths do not match file size');
  const version = bytes.toString('ascii', SU3_HEADER_LENGTH, SU3_HEADER_LENGTH + versionLength);
  if (!version || /[^\x20-\x7e]/.test(version)) throw new Error('Invalid SU3 version string');
  const signer = bytes.toString('ascii', SU3_HEADER_LENGTH + versionLength, contentOffset);
  if (!signer || /[^\x20-\x7e]/.test(signer)) throw new Error('Invalid SU3 signer ID');
  const key = trustedSigners.get(signer);
  if (!key || key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails?.modulusLength !== 4096) throw new Error(`SU3 signer is not trusted: ${signer}`);
  const signedData = bytes.subarray(0, signatureOffset); const digest = createHash('sha512').update(signedData).digest();
  let decodedSignature: Buffer;
  try { decodedSignature = publicDecrypt({ key, padding: constants.RSA_NO_PADDING }, bytes.subarray(signatureOffset)); }
  catch { throw new Error('SU3 RSA signature is invalid'); }
  if (decodedSignature.subarray(0, -digest.length).some(byte => byte !== 0) || !decodedSignature.subarray(-digest.length).equals(digest)) throw new Error('SU3 signature verification failed');

  const routerInfoRecords = readZipEntries(bytes.subarray(contentOffset, signatureOffset), { maxArchiveBytes });
  const staged = new VerifiedRouterInfoStore(MAX_ZIP_ENTRIES, store.expectedNetId);
  let rejected = 0;
  for (const routerInfoBytes of routerInfoRecords) {
    try { staged.store(parseRouterInfo(routerInfoBytes)); }
    catch { rejected++; }
  }
  if (staged.size < minRouterInfos) throw new Error(`SU3 reseed contained only ${staged.size} usable RouterInfos`);
  let imported = 0;
  for (const info of staged.all()) if (store.store(info)) imported++;
  return { url: 'local', imported, rejected, signer };
}

export async function loadReseedSigners(directory = fileURLToPath(new URL('./reseed-certs/', import.meta.url))): Promise<Map<string, KeyObject>> {
  const trusted = new Map<string, KeyObject>();
  const files = (await readdir(directory)).filter(file => file.endsWith('.crt')).sort();
  for (const file of files) {
    const certificate = new X509Certificate(await readFile(`${directory}/${file}`));
    const commonName = certificate.issuer.split('\n').find(line => line.startsWith('CN='))?.slice(3);
    const now = Date.now();
    if (now < certificate.validFromDate.getTime() || now > certificate.validToDate.getTime()) continue;
    if (!commonName || certificate.publicKey.asymmetricKeyType !== 'rsa' || certificate.publicKey.asymmetricKeyDetails?.modulusLength !== 4096) continue;
    if (trusted.has(commonName)) throw new Error(`Duplicate reseed signer certificate: ${commonName}`);
    trusted.set(commonName, certificate.publicKey);
  }
  if (!trusted.size) throw new Error('No valid trusted reseed signer certificates were found');
  return trusted;
}

async function downloadSu3(url: URL, timeoutMs: number, maxBytes: number, redirects = 0): Promise<Buffer> {
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('Reseed endpoint must be a clean HTTPS URL');
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { accept: 'application/octet-stream', 'accept-encoding': 'identity', 'user-agent': 'Wget/1.11.4' }, maxHeaderSize: 16 * 1024 }, response => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirects >= 3) { reject(new Error('Too many reseed redirects')); return; }
        const next = new URL(response.headers.location, url);
        if (next.protocol !== 'https:') { reject(new Error('Reseed redirect downgraded from HTTPS')); return; }
        if (!next.searchParams.has('netid') && url.searchParams.has('netid')) next.searchParams.set('netid', url.searchParams.get('netid')!);
        void downloadSu3(next, timeoutMs, maxBytes, redirects + 1).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`Reseed server returned HTTP ${response.statusCode ?? 'unknown'}`)); return; }
      const chunks: Buffer[] = []; let total = 0;
      response.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > maxBytes) { request.destroy(new Error('Reseed download exceeds size limit')); return; }
        chunks.push(Buffer.from(chunk));
      });
      response.once('end', () => resolve(Buffer.concat(chunks, total)));
      response.once('error', reject);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('Reseed download timed out')));
    request.once('error', reject);
  });
}

/** Imports a verified reseed into the bounded in-memory RouterInfo store. */
export async function reseedRouterInfoStore(store: VerifiedRouterInfoStore, options: ReseedOptions = {}): Promise<ReseedResult> {
  const urls = options.urls ?? DEFAULT_RESEED_URLS;
  const timeoutMs = options.timeoutMs ?? 20_000; const maxArchiveBytes = options.maxArchiveBytes ?? DEFAULT_MAX_ARCHIVE_BYTES;
  const minRouterInfos = options.minRouterInfos ?? 10;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) throw new RangeError('Reseed timeout must be 1000..120000 ms');
  if (!Number.isSafeInteger(maxArchiveBytes) || maxArchiveBytes < 1024 || maxArchiveBytes > DEFAULT_MAX_ARCHIVE_BYTES) throw new RangeError('Reseed maxArchiveBytes is out of range');
  if (!Number.isSafeInteger(minRouterInfos) || minRouterInfos < 1 || minRouterInfos > 1000) throw new RangeError('minRouterInfos must be 1..1000');
  const signers = await loadReseedSigners(options.certificateDirectory);
  const failures: Error[] = [];
  for (const base of urls) {
    try {
      const url = new URL(base.endsWith('/') ? `${base}i2pseeds.su3` : `${base}/i2pseeds.su3`);
      url.searchParams.set('netid', store.expectedNetId);
      const bundle = await downloadSu3(url, timeoutMs, maxArchiveBytes + 1024);
      const result = importSu3Reseed(bundle, signers, store, { maxArchiveBytes, minRouterInfos });
      return { ...result, url: url.origin };
    } catch (error) { failures.push(new Error(`${base}: ${error instanceof Error ? error.message : String(error)}`)); }
  }
  throw new AggregateError(failures, 'All configured I2P reseed servers failed');
}
