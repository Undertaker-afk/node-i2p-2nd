import { createCipheriv, createDecipheriv, createHash, diffieHellman, generateKeyPairSync, createPublicKey, createHmac, randomBytes, type KeyObject } from 'node:crypto';
import type { RouterIdentityKeys } from '../../identity.ts';
import { parseRouterInfo, verifyRouterInfoSignature } from '../../protocol/router-info.ts';
import type { SipHashKeys } from './siphash.ts';

const PROTOCOL_NAME = Buffer.from('Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256', 'ascii');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
export type SessionRequestOptions = {
  networkId: number;
  publishedRouterHash: Buffer;
  publishedIv: Buffer;
  publishedStaticKey: Buffer;
  timestampSeconds?: number;
  padding?: Buffer;
  message3Part2Length: number;
};
export type AliceHandshakeState = {
  message: Buffer;
  ephemeralPrivateKey: KeyObject;
  ephemeralPublicKey: Buffer;
  remoteStaticKey: Buffer;
  chainingKey: Buffer;
  handshakeHash: Buffer;
  requestCiphertext: Buffer;
  padding: Buffer;
  publishedRouterHash: Buffer;
  aesChainingIv: Buffer;
  message3Part2Length: number;
  peerEphemeralPublicKey?: Buffer;
  sessionCreatedCiphertext?: Buffer;
  sessionCreatedKey?: Buffer;
  sessionCreatedPadding?: Buffer;
  sessionConfirmedCiphertext?: Buffer;
  sendKey?: Buffer;
  receiveKey?: Buffer;
  sendLengthKeys?: SipHashKeys;
  receiveLengthKeys?: SipHashKeys;
};

function sha256(data: Buffer): Buffer { return createHash('sha256').update(data).digest(); }
function hmac(key: Buffer, data: Buffer): Buffer { return createHmac('sha256', key).update(data).digest(); }
function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'spki' });
  if (!Buffer.isBuffer(der) || der.length !== X25519_SPKI_PREFIX.length + 32 || !der.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)) throw new Error('Unexpected X25519 public key encoding');
  return Buffer.from(der.subarray(-32));
}
function importX25519Public(raw: Buffer): KeyObject {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
function validateX25519SharedSecret(secret: Buffer): void {
  if (secret.length !== 32 || secret.every(byte => byte === 0)) throw new Error('Invalid low-order X25519 public key');
}

function sessionRequestOptions(options: SessionRequestOptions, paddingLength: number): Buffer {
  const result = Buffer.alloc(16);
  result.writeUInt8(options.networkId, 0); result.writeUInt8(2, 1);
  result.writeUInt16BE(paddingLength, 2); result.writeUInt16BE(options.message3Part2Length, 4);
  result.writeUInt16BE(0, 6);
  const timestamp = options.timestampSeconds ?? Math.floor(Date.now() / 1000);
  if (!Number.isInteger(timestamp) || timestamp < 0 || timestamp > 0xffff_ffff) throw new RangeError('timestampSeconds must be a uint32');
  result.writeUInt32BE(timestamp, 8); result.writeUInt32BE(0, 12);
  return result;
}

/**
 * Creates NTCP2 XK SessionRequest (Noise message 1) for the currently supported
 * Ed25519/X25519 peer profile. This is a handshake primitive, not a complete transport.
 */
export function createSessionRequest(options: SessionRequestOptions): AliceHandshakeState {
  if (!Number.isInteger(options.networkId) || options.networkId < 1 || options.networkId > 255) throw new RangeError('networkId must be a uint8');
  if (!Buffer.isBuffer(options.publishedRouterHash) || options.publishedRouterHash.length !== 32) throw new Error('publishedRouterHash must be 32 bytes');
  if (!Buffer.isBuffer(options.publishedIv) || options.publishedIv.length !== 16) throw new Error('NTCP2 published IV must be 16 bytes');
  if (!Number.isInteger(options.message3Part2Length) || options.message3Part2Length < 16 || options.message3Part2Length > 65_487) throw new RangeError('message3Part2Length must be between 16 and 65487');
  const remoteStaticKey = Buffer.from(options.publishedStaticKey);
  const remoteKeyObject = importX25519Public(remoteStaticKey);
  const padding = options.padding === undefined ? Buffer.alloc(0) : Buffer.from(options.padding);
  if (padding.length > 880) throw new RangeError('SessionRequest padding exceeds 880 bytes');
  const plaintext = Buffer.concat([sessionRequestOptions(options, padding.length)]);

  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralPublicKey = rawPublicKey(ephemeral.publicKey);
  const sharedSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: remoteKeyObject });
  validateX25519SharedSecret(sharedSecret);

  // Noise_XK protocol initialization and XK message 1: -> e, es.
  let handshakeHash = sha256(PROTOCOL_NAME);
  let chainingKey: ReturnType<typeof hmac> = Buffer.from(handshakeHash);
  handshakeHash = sha256(handshakeHash); // MixHash(empty prologue)
  handshakeHash = sha256(Buffer.concat([handshakeHash, remoteStaticKey])); // MixHash(rs)
  handshakeHash = sha256(Buffer.concat([handshakeHash, ephemeralPublicKey])); // MixHash(e)

  const tempKey = hmac(chainingKey, sharedSecret);
  chainingKey = hmac(tempKey, Buffer.from([1]));
  const cipherKey = hmac(tempKey, Buffer.concat([chainingKey, Buffer.from([2])]));
  sharedSecret.fill(0); tempKey.fill(0);

  const cipher = createCipheriv('chacha20-poly1305', cipherKey, Buffer.alloc(12), { authTagLength: 16 });
  cipher.setAAD(handshakeHash, { plaintextLength: plaintext.length });
  const requestCiphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  cipherKey.fill(0);
  handshakeHash = sha256(Buffer.concat([handshakeHash, requestCiphertext]));
  if (padding.length) handshakeHash = sha256(Buffer.concat([handshakeHash, padding]));

  const aes = createCipheriv('aes-256-cbc', options.publishedRouterHash, options.publishedIv);
  aes.setAutoPadding(false);
  const obfuscatedEphemeral = Buffer.concat([aes.update(ephemeralPublicKey), aes.final()]);
  if (obfuscatedEphemeral.length !== 32 || 32 + requestCiphertext.length + padding.length > 65_535) throw new Error('Invalid SessionRequest frame size');
  return {
    message: Buffer.concat([obfuscatedEphemeral, requestCiphertext, padding]),
    ephemeralPrivateKey: ephemeral.privateKey,
    ephemeralPublicKey,
    remoteStaticKey,
    chainingKey,
    handshakeHash,
    requestCiphertext,
    padding,
    publishedRouterHash: Buffer.from(options.publishedRouterHash),
    aesChainingIv: Buffer.from(obfuscatedEphemeral.subarray(16, 32)),
    message3Part2Length: options.message3Part2Length,
  };
}

/** Authenticates the fixed SessionCreated header so a stream reader can learn its clear padding length. */
export function readSessionCreatedPaddingLength(state: AliceHandshakeState, header: Buffer): number {
  if (header.length !== 64) throw new Error('SessionCreated header must be exactly 64 bytes');
  const encryptedY = header.subarray(0, 32);
  const aes = createDecipheriv('aes-256-cbc', state.publishedRouterHash, state.aesChainingIv); aes.setAutoPadding(false);
  const peerY = Buffer.concat([aes.update(encryptedY), aes.final()]);
  const peerKey = importX25519Public(peerY);
  const associatedData = sha256(Buffer.concat([state.handshakeHash, peerY]));
  const dh = diffieHellman({ privateKey: state.ephemeralPrivateKey, publicKey: peerKey }); validateX25519SharedSecret(dh);
  const temp = hmac(state.chainingKey, dh); const ck = hmac(temp, Buffer.from([1])); const key = hmac(temp, Buffer.concat([ck, Buffer.from([2])]));
  dh.fill(0); temp.fill(0); ck.fill(0);
  const ciphertext = header.subarray(32);
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce(0), { authTagLength: 16 });
  decipher.setAAD(associatedData, { plaintextLength: 16 }); decipher.setAuthTag(ciphertext.subarray(16));
  let plaintext: Buffer;
  try { plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, 16)), decipher.final()]); }
  finally { key.fill(0); }
  if (plaintext.subarray(0, 10).some(byte => byte !== 0)) throw new Error('SessionCreated reserved option bytes must be zero');
  const paddingLength = plaintext.readUInt16BE(10);
  if (paddingLength > 848) throw new Error('SessionCreated padding exceeds 848 bytes');
  return paddingLength;
}

/** Processes the fixed-format NTCP2 SessionCreated (Noise XK message 2). */
export function processSessionCreated(
  state: AliceHandshakeState,
  message: Buffer,
  options: { nowSeconds?: number; maxClockSkewSeconds?: number } = {},
): AliceHandshakeState {
  if (state.peerEphemeralPublicKey) throw new Error('SessionCreated was already processed');
  if (!Buffer.isBuffer(message) || message.length < 64 || message.length > 65_535) throw new Error('Invalid NTCP2 SessionCreated size');
  const encryptedY = message.subarray(0, 32);
  const aes = createDecipheriv('aes-256-cbc', state.publishedRouterHash, state.aesChainingIv);
  aes.setAutoPadding(false);
  const peerEphemeralPublicKey = Buffer.concat([aes.update(encryptedY), aes.final()]);
  const peerEphemeralObject = importX25519Public(peerEphemeralPublicKey);

  let handshakeHash = sha256(Buffer.concat([state.handshakeHash, peerEphemeralPublicKey]));
  const dh = diffieHellman({ privateKey: state.ephemeralPrivateKey, publicKey: peerEphemeralObject });
  validateX25519SharedSecret(dh);
  const tempKey = hmac(state.chainingKey, dh);
  let chainingKey = hmac(tempKey, Buffer.from([1]));
  const cipherKey = hmac(tempKey, Buffer.concat([chainingKey, Buffer.from([2])]));
  dh.fill(0); tempKey.fill(0);

  const ciphertext = message.subarray(32, 64);
  const decipher = createDecipheriv('chacha20-poly1305', cipherKey, Buffer.alloc(12), { authTagLength: 16 });
  decipher.setAAD(handshakeHash, { plaintextLength: 16 }); decipher.setAuthTag(ciphertext.subarray(16));
  let plaintext: Buffer;
  try { plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, 16)), decipher.final()]); }
  catch (error) { cipherKey.fill(0); throw error; }
  if (plaintext.subarray(0, 10).some(byte => byte !== 0)) throw new Error('SessionCreated reserved option bytes must be zero');
  const paddingLength = plaintext.readUInt16BE(10);
  const timestampSeconds = plaintext.readUInt32BE(12);
  if (message.length !== 64 + paddingLength) throw new Error('SessionCreated padding length mismatch');
  if (paddingLength > 848) throw new Error('SessionCreated padding exceeds 848 bytes');
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const maxClockSkewSeconds = options.maxClockSkewSeconds ?? 600;
  if (!Number.isSafeInteger(nowSeconds) || !Number.isSafeInteger(maxClockSkewSeconds) || maxClockSkewSeconds < 0) throw new RangeError('Invalid clock validation settings');
  if (Math.abs(nowSeconds - timestampSeconds) > maxClockSkewSeconds) throw new Error('SessionCreated timestamp is outside the accepted clock skew');
  handshakeHash = sha256(Buffer.concat([handshakeHash, ciphertext]));
  const padding = Buffer.from(message.subarray(64));
  if (padding.length) handshakeHash = sha256(Buffer.concat([handshakeHash, padding]));
  return { ...state, chainingKey, handshakeHash, peerEphemeralPublicKey: Buffer.from(peerEphemeralPublicKey), sessionCreatedCiphertext: Buffer.from(ciphertext), sessionCreatedKey: cipherKey, sessionCreatedPadding: padding };
}

/** Creates NTCP2 SessionConfirmed (Noise XK message 3) and derives Alice's data-phase keys. */
export function createSessionConfirmed(state: AliceHandshakeState, identity: RouterIdentityKeys, routerInfoBytes: Buffer): AliceHandshakeState {
  if (!state.peerEphemeralPublicKey) throw new Error('SessionCreated must be processed before SessionConfirmed');
  if (state.sessionConfirmedCiphertext) throw new Error('SessionConfirmed was already created');
  const info = parseRouterInfo(routerInfoBytes);
  if (!verifyRouterInfoSignature(info)) throw new Error('Local RouterInfo signature is invalid');
  if (!info.identity.equals(identity.identity)) throw new Error('RouterInfo does not match local RouterIdentity');
  if (!info.identityHash.equals(identity.identityHash)) throw new Error('RouterInfo identity hash does not match local identity');
  if (!rawPublicKey(createPublicKey(identity.encryptionPrivateKey)).equals(identity.identity.subarray(0, 32))) throw new Error('Local X25519 private key does not match RouterIdentity');

  const staticKey = Buffer.from(identity.identity.subarray(0, 32));
  if (!state.sessionCreatedKey) throw new Error('SessionCreated key state is missing');
  const staticCipher = createCipheriv('chacha20-poly1305', state.sessionCreatedKey, nonce(1), { authTagLength: 16 });
  staticCipher.setAAD(state.handshakeHash, { plaintextLength: staticKey.length });
  const encryptedStatic = Buffer.concat([staticCipher.update(staticKey), staticCipher.final(), staticCipher.getAuthTag()]);
  state.sessionCreatedKey.fill(0);
  let handshakeHash = sha256(Buffer.concat([state.handshakeHash, encryptedStatic]));

  const dh = diffieHellman({ privateKey: identity.encryptionPrivateKey, publicKey: importX25519Public(state.peerEphemeralPublicKey) });
  validateX25519SharedSecret(dh);
  const tempKey = hmac(state.chainingKey, dh);
  let chainingKey = hmac(tempKey, Buffer.from([1]));
  const payloadKey = hmac(tempKey, Buffer.concat([chainingKey, Buffer.from([2])]));
  dh.fill(0); tempKey.fill(0);

  const routerInfoBlock = Buffer.allocUnsafe(4 + routerInfoBytes.length);
  routerInfoBlock[0] = 2; routerInfoBlock.writeUInt16BE(1 + routerInfoBytes.length, 1); routerInfoBlock[3] = 0;
  routerInfoBytes.copy(routerInfoBlock, 4);
  const plaintextLength = state.message3Part2Length - 16;
  const paddingLength = plaintextLength - routerInfoBlock.length;
  if (paddingLength > 0 && paddingLength < 3) throw new Error('Message 3 frame length leaves insufficient space for a padding block');
  if (paddingLength < 0) throw new Error('RouterInfo exceeds the advertised Message 3 frame size');
  let payload = routerInfoBlock;
  if (paddingLength >= 3) {
    const blockLength = paddingLength - 3;
    const paddingBlock = Buffer.allocUnsafe(paddingLength); paddingBlock[0] = 254; paddingBlock.writeUInt16BE(blockLength, 1); randomBytes(blockLength).copy(paddingBlock, 3);
    payload = Buffer.concat([payload, paddingBlock]);
  }
  const payloadCipher = createCipheriv('chacha20-poly1305', payloadKey, nonce(0), { authTagLength: 16 });
  payloadCipher.setAAD(handshakeHash, { plaintextLength: payload.length });
  const encryptedPayload = Buffer.concat([payloadCipher.update(payload), payloadCipher.final(), payloadCipher.getAuthTag()]);
  payloadKey.fill(0);
  if (encryptedPayload.length !== state.message3Part2Length) throw new Error('Message 3 frame length does not match the advertised length');
  handshakeHash = sha256(Buffer.concat([handshakeHash, encryptedPayload]));

  const split = hmac(chainingKey, Buffer.alloc(0));
  const sendKey = hmac(split, Buffer.from([1]));
  const receiveKey = hmac(split, Buffer.concat([sendKey, Buffer.from([2])]));
  const askMaster = hmac(split, Buffer.concat([Buffer.from('ask', 'ascii'), Buffer.from([1])]));
  const sipTemp = hmac(askMaster, Buffer.concat([handshakeHash, Buffer.from('siphash', 'ascii')]));
  const sipMaster = hmac(sipTemp, Buffer.from([1]));
  const sipTemp2 = hmac(sipMaster, Buffer.alloc(0));
  const sipKeysAb = hmac(sipTemp2, Buffer.from([1]));
  const sipKeysBa = hmac(sipTemp2, Buffer.concat([sipKeysAb, Buffer.from([2])]));
  const sendLengthKeys: SipHashKeys = { key1: Buffer.from(sipKeysAb.subarray(0, 8)), key2: Buffer.from(sipKeysAb.subarray(8, 16)), iv: Buffer.from(sipKeysAb.subarray(16, 24)) };
  const receiveLengthKeys: SipHashKeys = { key1: Buffer.from(sipKeysBa.subarray(0, 8)), key2: Buffer.from(sipKeysBa.subarray(8, 16)), iv: Buffer.from(sipKeysBa.subarray(16, 24)) };
  split.fill(0); askMaster.fill(0); sipTemp.fill(0); sipMaster.fill(0); sipTemp2.fill(0); sipKeysAb.fill(0); sipKeysBa.fill(0); chainingKey = Buffer.alloc(0);
  const sessionConfirmedCiphertext = Buffer.concat([encryptedStatic, encryptedPayload]);
  return { ...state, chainingKey, handshakeHash, sessionConfirmedCiphertext, sessionCreatedKey: Buffer.alloc(0), sendKey, receiveKey, sendLengthKeys, receiveLengthKeys };
}

function nonce(counter: number): Buffer {
  const result = Buffer.alloc(12); result.writeBigUInt64LE(BigInt(counter), 4); return result;
}
