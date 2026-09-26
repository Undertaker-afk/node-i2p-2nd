import net from 'node:net';
import { createCipheriv, createDecipheriv, createHash, createHmac, diffieHellman, generateKeyPairSync, createPublicKey, type KeyObject } from 'node:crypto';
import type { RouterIdentityKeys } from '../../identity.ts';
import { parseRouterInfo, verifyRouterInfoSignature } from '../../protocol/router-info.ts';
import { decodeNtcp2Blocks } from './blocks.ts';
import { Ntcp2Connection } from './connection.ts';
import { Ntcp2DataCipher } from './data-cipher.ts';
import type { SipHashKeys } from './siphash.ts';

const PROTOCOL_NAME = Buffer.from('Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256', 'ascii');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const sha = (data: Buffer) => createHash('sha256').update(data).digest();
const mac = (key: Buffer, data: Buffer) => createHmac('sha256', key).update(data).digest();
function nonce(index: number): Buffer { const value = Buffer.alloc(12); value.writeBigUInt64LE(BigInt(index), 4); return value; }
function keyObject(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
function rawPublic(key: KeyObject): Buffer { const der = key.export({ format: 'der', type: 'spki' }); return Buffer.from(der.subarray(-32)); }
function validateDh(secret: Buffer): void { if (secret.length !== 32 || secret.every(byte => byte === 0)) throw new Error('Invalid low-order X25519 point'); }

export class Ntcp2ReplayCache {
  private seen = new Map<string, number>();
  readonly maxEntries: number;
  constructor(maxEntries = 10_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be positive');
    this.maxEntries = maxEntries;
  }
  remember(encryptedEphemeral: Buffer, nowMs: number, ttlMs: number): boolean {
    if (!Buffer.isBuffer(encryptedEphemeral) || encryptedEphemeral.length !== 32) throw new Error('Replay key must be a 32-byte encrypted ephemeral');
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new RangeError('Invalid replay-cache time or TTL');
    for (const [key, expiry] of this.seen) if (expiry <= nowMs) this.seen.delete(key);
    const key = encryptedEphemeral.toString('hex');
    if (this.seen.has(key)) return false;
    this.seen.set(key, nowMs + ttlMs);
    while (this.seen.size > this.maxEntries) this.seen.delete(this.seen.keys().next().value!);
    return true;
  }
}

export type Ntcp2AcceptOptions = {
  networkId?: number;
  publishedIv: Buffer;
  timeoutMs?: number;
  maxClockSkewSeconds?: number;
  replayCache?: Ntcp2ReplayCache;
};

async function readExact(socket: net.Socket, length: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let received = 0; let settled = false;
    const finish = (error?: Error, result?: Buffer) => {
      if (settled) return; settled = true; clearTimeout(timer);
      socket.removeListener('data', onData); socket.removeListener('error', onError); socket.removeListener('end', onEnd); socket.removeListener('close', onClose);
      if (error) reject(error); else resolve(result!);
    };
    const onError = (error: Error) => finish(error);
    const onEnd = () => finish(new Error('NTCP2 peer ended during handshake'));
    const onClose = () => finish(new Error('NTCP2 peer closed during handshake'));
    const onData = (chunk: Buffer) => {
      const needed = length - received;
      if (chunk.length < needed) { chunks.push(Buffer.from(chunk)); received += chunk.length; return; }
      const result = Buffer.concat([...chunks, chunk.subarray(0, needed)], length); const extra = chunk.subarray(needed);
      socket.pause(); if (extra.length) socket.unshift(extra);
      finish(undefined, result);
    };
    const timer = setTimeout(() => finish(new Error('Timed out waiting for NTCP2 handshake bytes')), timeoutMs);
    socket.on('data', onData); socket.once('error', onError); socket.once('end', onEnd); socket.once('close', onClose); socket.resume();
  });
}
async function writeAll(socket: net.Socket, data: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => socket.write(data, error => error ? reject(error) : resolve()));
}
function decryptAead(key: Buffer, ad: Buffer, frame: Buffer, counter: number): Buffer {
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce(counter), { authTagLength: 16 });
  decipher.setAAD(ad, { plaintextLength: frame.length - 16 }); decipher.setAuthTag(frame.subarray(-16));
  return Buffer.concat([decipher.update(frame.subarray(0, -16)), decipher.final()]);
}
function encryptAead(key: Buffer, ad: Buffer, plain: Buffer, counter: number): Buffer {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce(counter), { authTagLength: 16 });
  cipher.setAAD(ad, { plaintextLength: plain.length });
  return Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}
function deriveDataKeys(ck: Buffer, h: Buffer) {
  const split = mac(ck, Buffer.alloc(0));
  const keyAb = mac(split, Buffer.from([1])); const keyBa = mac(split, Buffer.concat([keyAb, Buffer.from([2])]));
  const askMaster = mac(split, Buffer.concat([Buffer.from('ask'), Buffer.from([1])]));
  const sipTemp = mac(askMaster, Buffer.concat([h, Buffer.from('siphash')]));
  const sipMaster = mac(sipTemp, Buffer.from([1])); const temp = mac(sipMaster, Buffer.alloc(0));
  const ab = mac(temp, Buffer.from([1])); const ba = mac(temp, Buffer.concat([ab, Buffer.from([2])]));
  const lengthKeys = (value: Buffer): SipHashKeys => ({ key1: Buffer.from(value.subarray(0, 8)), key2: Buffer.from(value.subarray(8, 16)), iv: Buffer.from(value.subarray(16, 24)) });
  const sendLength = lengthKeys(ba); const receiveLength = lengthKeys(ab);
  split.fill(0); askMaster.fill(0); sipTemp.fill(0); sipMaster.fill(0); temp.fill(0); ab.fill(0); ba.fill(0);
  return { sendKey: keyBa, receiveKey: keyAb, sendLength, receiveLength };
}

/** Accepts one NTCP2 initiator handshake and returns a verified data-phase connection. */
export async function acceptNtcp2(socket: net.Socket, localIdentity: RouterIdentityKeys, localRouterInfoBytes: Buffer, options: Ntcp2AcceptOptions): Promise<Ntcp2Connection> {
  try { return await acceptNtcp2Inner(socket, localIdentity, localRouterInfoBytes, options); }
  catch (error) { socket.destroy(); throw error; }
}

async function acceptNtcp2Inner(socket: net.Socket, localIdentity: RouterIdentityKeys, localRouterInfoBytes: Buffer, options: Ntcp2AcceptOptions): Promise<Ntcp2Connection> {
  const networkId = options.networkId ?? 2; const timeoutMs = options.timeoutMs ?? 15_000; const skew = options.maxClockSkewSeconds ?? 600;
  if (!Buffer.isBuffer(options.publishedIv) || options.publishedIv.length !== 16) throw new Error('Published NTCP2 IV must be 16 bytes');
  if (!Number.isInteger(networkId) || networkId < 1 || networkId > 255) throw new RangeError('networkId must be a uint8');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000 || !Number.isInteger(skew) || skew < 0) throw new RangeError('Invalid NTCP2 timeout or clock skew');
  const ownInfo = parseRouterInfo(localRouterInfoBytes);
  if (!verifyRouterInfoSignature(ownInfo) || !ownInfo.identity.equals(localIdentity.identity) || ownInfo.options.get('netId') !== String(networkId)) throw new Error('Local RouterInfo does not match identity/network');
  const publishesKeys = ownInfo.addresses.some(address => (address.transport === 'NTCP2' || address.transport === 'NTCP') && address.options.get('v')?.split(',').includes('2') && address.options.get('i') !== undefined && i2pBase64(address.options.get('s') ?? '').equals(localIdentity.identity.subarray(0, 32)) && i2pBase64(address.options.get('i') ?? '').equals(options.publishedIv));
  if (!publishesKeys) throw new Error('Local RouterInfo does not publish the provided NTCP2 key and IV');

  socket.setNoDelay(true); socket.setTimeout(timeoutMs, () => socket.destroy(new Error('NTCP2 handshake timed out')));
  try {
    const first = await readExact(socket, 64, timeoutMs); const encryptedX = first.subarray(0, 32); const message1Ciphertext = first.subarray(32, 64);
    if (!(options.replayCache ?? defaultReplayCache).remember(encryptedX, Date.now(), Math.max(1, 2 * skew * 1000))) throw new Error('Replayed NTCP2 SessionRequest');
    const aesIn = createDecipheriv('aes-256-cbc', ownInfo.identityHash, options.publishedIv); aesIn.setAutoPadding(false);
    const aliceEphemeral = Buffer.concat([aesIn.update(encryptedX), aesIn.final()]);
    const aliceEphemeralKey = keyObject(aliceEphemeral);
    let h = sha(PROTOCOL_NAME); let ck = Buffer.from(h); h = sha(h); h = sha(Buffer.concat([h, localIdentity.identity.subarray(0, 32)])); h = sha(Buffer.concat([h, aliceEphemeral]));
    const es = diffieHellman({ privateKey: localIdentity.encryptionPrivateKey, publicKey: aliceEphemeralKey }); validateDh(es);
    const temp1 = mac(ck, es); ck = mac(temp1, Buffer.from([1])); const key1 = mac(temp1, Buffer.concat([ck, Buffer.from([2])])); es.fill(0); temp1.fill(0);
    const requestDecipher = createDecipheriv('chacha20-poly1305', key1, nonce(0), { authTagLength: 16 });
    requestDecipher.setAAD(h, { plaintextLength: 16 }); requestDecipher.setAuthTag(message1Ciphertext.subarray(-16));
    const requestOptions = Buffer.concat([requestDecipher.update(message1Ciphertext.subarray(0, -16)), requestDecipher.final()]);
    if (requestOptions[0] !== networkId) throw new Error('NTCP2 network ID mismatch');
    if (requestOptions[1] !== 2 || requestOptions.readUInt16BE(6) !== 0 || requestOptions.readUInt32BE(12) !== 0) throw new Error('Unsupported NTCP2 SessionRequest options');
    const requestPaddingLength = requestOptions.readUInt16BE(2); const message3Length = requestOptions.readUInt16BE(4);
    if (requestPaddingLength > 880 || message3Length < 16 || message3Length > 65_487) throw new Error('Invalid NTCP2 SessionRequest lengths');
    const timestamp = requestOptions.readUInt32BE(8);
    if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > skew) throw new Error('NTCP2 SessionRequest timestamp is outside accepted clock skew');
    const requestPadding = requestPaddingLength ? await readExact(socket, requestPaddingLength, timeoutMs) : Buffer.alloc(0);
    h = sha(Buffer.concat([h, message1Ciphertext])); if (requestPadding.length) h = sha(Buffer.concat([h, requestPadding]));

    const bobEphemeral = generateKeyPairSync('x25519'); const bobY = rawPublic(bobEphemeral.publicKey); h = sha(Buffer.concat([h, bobY]));
    const ee = diffieHellman({ privateKey: bobEphemeral.privateKey, publicKey: aliceEphemeralKey }); validateDh(ee);
    const temp2 = mac(ck, ee); ck = mac(temp2, Buffer.from([1])); const key2 = mac(temp2, Buffer.concat([ck, Buffer.from([2])])); ee.fill(0); temp2.fill(0); key1.fill(0);
    const responseOptions = Buffer.alloc(16); responseOptions.writeUInt32BE(Math.floor(Date.now() / 1000), 12);
    const responseCiphertext = encryptAead(key2, h, responseOptions, 0);
    h = sha(Buffer.concat([h, responseCiphertext]));
    const aesOut = createCipheriv('aes-256-cbc', ownInfo.identityHash, encryptedX.subarray(16, 32)); aesOut.setAutoPadding(false);
    const encryptedY = Buffer.concat([aesOut.update(bobY), aesOut.final()]);
    await writeAll(socket, Buffer.concat([encryptedY, responseCiphertext]));

    const sessionConfirmed = await readExact(socket, 48 + message3Length, timeoutMs);
    const encryptedStatic = sessionConfirmed.subarray(0, 48); const aliceStatic = decryptAead(key2, h, encryptedStatic, 1);
    if (aliceStatic.length !== 32) throw new Error('Invalid SessionConfirmed static key length');
    h = sha(Buffer.concat([h, encryptedStatic]));
    const se = diffieHellman({ privateKey: bobEphemeral.privateKey, publicKey: keyObject(aliceStatic) }); validateDh(se);
    const temp3 = mac(ck, se); ck = mac(temp3, Buffer.from([1])); const key3 = mac(temp3, Buffer.concat([ck, Buffer.from([2])])); se.fill(0); temp3.fill(0); key2.fill(0);
    const encryptedPayload = sessionConfirmed.subarray(48);
    const payload = decryptAead(key3, h, encryptedPayload, 0); key3.fill(0); h = sha(Buffer.concat([h, encryptedPayload]));
    const blocks = decodeNtcp2Blocks(payload);
    if (blocks.length < 1 || blocks[0]!.type !== 2) throw new Error('SessionConfirmed must start with a RouterInfo block');
    const riBlock = blocks[0]!.data;
    if (riBlock.length < 2 || riBlock[0] !== 0) throw new Error('Invalid SessionConfirmed RouterInfo block flags');
    const peerInfoBytes = riBlock.subarray(1);
    let sawOptions = false; let sawPadding = false;
    for (const block of blocks.slice(1)) {
      if (block.type === 1 && !sawOptions && !sawPadding) sawOptions = true;
      else if (block.type === 254 && !sawPadding) sawPadding = true;
      else throw new Error('Unsupported, duplicate, or misordered SessionConfirmed block');
    }
    const remoteIdentityHash = validatePeerRouterInfo(peerInfoBytes, aliceStatic, networkId);
    const dataKeys = deriveDataKeys(ck, h); ck.fill(0);
    const cipher = new Ntcp2DataCipher(dataKeys.sendKey, dataKeys.receiveKey, dataKeys.sendLength, dataKeys.receiveLength);
    dataKeys.sendKey.fill(0); dataKeys.receiveKey.fill(0);
    for (const keys of [dataKeys.sendLength, dataKeys.receiveLength]) { keys.key1.fill(0); keys.key2.fill(0); keys.iv.fill(0); }
    socket.setTimeout(0);
    return new Ntcp2Connection(socket, cipher, undefined, remoteIdentityHash);
  } catch (error) {
    socket.destroy(); throw error;
  }
}

const defaultReplayCache = new Ntcp2ReplayCache();
function validatePeerRouterInfo(bytes: Buffer, staticKey: Buffer, networkId: number): Buffer {
  const info = parseRouterInfo(bytes);
  if (!verifyRouterInfoSignature(info) || info.options.get('netId') !== String(networkId)) throw new Error('Peer RouterInfo signature/network validation failed');
  const matches = info.addresses.some(address => {
    if (address.transport !== 'NTCP2' && address.transport !== 'NTCP') return false;
    if (!address.options.get('v')?.split(',').includes('2')) return false;
    try { return i2pBase64(address.options.get('s') ?? '').equals(staticKey); } catch { return false; }
  });
  if (!matches) throw new Error('Peer static key is absent or mismatched in RouterInfo');
  return Buffer.from(info.identityHash);
}
function i2pBase64(value: string): Buffer {
  if (!/^[A-Za-z0-9~\-=]+$/.test(value)) throw new Error('Invalid I2P base64');
  const raw = value.replace(/=+$/, '');
  return Buffer.from(raw.replace(/-/g, '+').replace(/~/g, '/') + '='.repeat((4 - raw.length % 4) % 4), 'base64');
}
