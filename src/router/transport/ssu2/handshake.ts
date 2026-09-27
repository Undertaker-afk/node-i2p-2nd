import { randomBytes, randomInt, type KeyObject } from 'node:crypto';
import {
  decryptAead, encryptAead, generateX25519KeyPair, hkdf, mixKey, noiseNonce, sha256, x25519SharedSecret, chacha20,
} from '../../crypto/x25519.ts';
import {
  decodeSsu2LongHeader, decodeSsu2ShortHeader, encodeSsu2LongHeader, encodeSsu2ShortHeader, protectSsu2Header, unprotectSsu2Header,
  SSU2_DATA, SSU2_MAC_LENGTH, SSU2_MIN_PACKET, SSU2_RETRY, SSU2_SESSION_CONFIRMED, SSU2_SESSION_CREATED, SSU2_SESSION_REQUEST,
  SSU2_SHORT_HEADER_LENGTH, SSU2_TOKEN_REQUEST, SSU2_VERSION, type Ssu2LongHeader, type Ssu2ShortHeader,
} from './header.ts';
import { dateTimeBlock, decodeBlocks, encodeBlocks, padBlocks, type Ssu2Block } from './blocks.ts';

/**
 * SSU2 Noise protocol name. Different from NTCP2 because all three handshake messages
 * mix their (unprotected) header into h before encryption.
 */
export const SSU2_PROTOCOL_NAME = 'Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256';
const ZEROLEN = Buffer.alloc(0);
const ZERO_NONCE = Buffer.alloc(12);

export type NoiseState = { ck: Buffer; h: Buffer; k: Buffer };

/** KDF 1: h = SHA256(name); ck = h; MixHash(empty prologue); MixHash(rs). */
export function initSsu2Noise(responderStaticKey: Buffer): NoiseState {
  if (responderStaticKey.length !== 32) throw new Error('SSU2 responder static key must be 32 bytes');
  let h = sha256(Buffer.from(SSU2_PROTOCOL_NAME, 'ascii'));
  const ck = Buffer.from(h);
  h = sha256(h);
  h = sha256(h, responderStaticKey);
  return { ck, h, k: Buffer.alloc(32) };
}

function mixHash(state: NoiseState, ...parts: Buffer[]): void { state.h = sha256(state.h, ...parts); }
function mixDh(state: NoiseState, shared: Buffer): void {
  const next = mixKey(state.ck, shared);
  state.ck = Buffer.from(next.ck); state.k = Buffer.from(next.key);
  shared.fill(0);
}
function cloneNoise(state: NoiseState): NoiseState { return { ck: Buffer.from(state.ck), h: Buffer.from(state.h), k: Buffer.from(state.k) }; }

export function randomConnId(): Buffer {
  let id = randomBytes(8);
  while (id.every(byte => byte === 0)) id = randomBytes(8);
  return id;
}

function randomPacketNumber(): number { return randomInt(0, 0x1_0000_0000); }

function payloadFor(blocks: readonly Ssu2Block[], randomPadding = 16, max = 1200): Buffer {
  return encodeBlocks(padBlocks([...blocks], 8, max, randomPadding));
}

// ---------------------------------------------------------------------------
// Header peeking / classification
// ---------------------------------------------------------------------------

/** Removes the first 8-byte mask to recover the destination connection ID. */
export function peekDestConnId(packet: Buffer, kHeader1: Buffer): Buffer {
  if (packet.length < SSU2_MIN_PACKET) throw new Error('SSU2 packet is truncated');
  const mask = chacha20(kHeader1, packet.subarray(packet.length - 24, packet.length - 12), Buffer.alloc(8), 0);
  const id = Buffer.allocUnsafe(8);
  for (let index = 0; index < 8; index++) id[index] = packet[index]! ^ mask[index]!;
  return id;
}

/** Unmasks bytes 8..15 (packet number, type, ver, netId, flag) with k_header_2. */
export function peekHeaderBytes8to16(packet: Buffer, kHeader2: Buffer): { packetNumber: number; type: number; version: number; netId: number; flag: number } {
  if (packet.length < SSU2_MIN_PACKET) throw new Error('SSU2 packet is truncated');
  const mask = chacha20(kHeader2, packet.subarray(packet.length - 12), Buffer.alloc(8), 0);
  const bytes = Buffer.allocUnsafe(8);
  for (let index = 0; index < 8; index++) bytes[index] = packet[8 + index]! ^ mask[index]!;
  return { packetNumber: bytes.readUInt32BE(0), type: bytes[4]!, version: bytes[5]!, netId: bytes[6]!, flag: bytes[7]! };
}

// ---------------------------------------------------------------------------
// Token Request (type 10) / Retry (type 9): symmetric only, k = Bob intro key
// ---------------------------------------------------------------------------

type LongPacketOptions = {
  destConnId: Buffer;
  srcConnId: Buffer;
  netId: number;
  introKey: Buffer;
  packetNumber?: number;
  nowMs?: number;
  blocks?: Ssu2Block[];
};

function createSymmetricLongPacket(type: number, token: Buffer, options: LongPacketOptions): Buffer {
  const packetNumber = options.packetNumber ?? randomPacketNumber();
  const header = encodeSsu2LongHeader({
    destConnId: options.destConnId, packetNumber, type, version: SSU2_VERSION, netId: options.netId, flag: 0,
    srcConnId: options.srcConnId, token,
  });
  const payload = payloadFor([dateTimeBlock(options.nowMs), ...(options.blocks ?? [])]);
  const ciphertext = encryptAead(options.introKey, noiseNonce(packetNumber), header, payload);
  return protectSsu2Header(Buffer.concat([header, ciphertext]), options.introKey, options.introKey, 'retry');
}

function openSymmetricLongPacket(packet: Buffer, introKey: Buffer, expectedType: number): { header: Ssu2LongHeader; blocks: Ssu2Block[] } {
  if (packet.length < 32 + 8 + SSU2_MAC_LENGTH) throw new Error('SSU2 long-header packet is truncated');
  const clear = unprotectSsu2Header(packet, introKey, introKey, 'retry');
  const header = decodeSsu2LongHeader(clear);
  if (header.type !== expectedType) throw new Error(`Expected SSU2 packet type ${expectedType}, got ${header.type}`);
  const payload = decryptAead(introKey, noiseNonce(header.packetNumber), clear.subarray(0, 32), clear.subarray(32));
  return { header, blocks: decodeBlocks(payload) };
}

/** Alice → Bob when Alice has no token for Bob's endpoint. */
export function createTokenRequest(options: LongPacketOptions): Buffer {
  return createSymmetricLongPacket(SSU2_TOKEN_REQUEST, Buffer.alloc(8), options);
}

export function parseTokenRequest(packet: Buffer, bobIntroKey: Buffer): { header: Ssu2LongHeader; blocks: Ssu2Block[] } {
  return openSymmetricLongPacket(packet, bobIntroKey, SSU2_TOKEN_REQUEST);
}

/** Bob → Alice. `token` all-zero plus a Termination block means rejection. */
export function createRetry(options: LongPacketOptions & { token: Buffer }): Buffer {
  if (options.token.length !== 8) throw new Error('SSU2 token must be 8 bytes');
  return createSymmetricLongPacket(SSU2_RETRY, options.token, options);
}

export function parseRetry(packet: Buffer, bobIntroKey: Buffer): { header: Ssu2LongHeader; blocks: Ssu2Block[]; token: Buffer } {
  const opened = openSymmetricLongPacket(packet, bobIntroKey, SSU2_RETRY);
  return { ...opened, token: opened.header.token };
}

// ---------------------------------------------------------------------------
// Session Request (type 0): -> e, es
// ---------------------------------------------------------------------------

export type AliceSsu2State = {
  noise: NoiseState;
  ephemeralPrivateKey: KeyObject;
  ephemeralPublicKey: Buffer;
  bobStaticKey: Buffer;
  bobIntroKey: Buffer;
  destConnId: Buffer;
  srcConnId: Buffer;
  netId: number;
};

export type SessionRequestOptions = {
  destConnId: Buffer;
  srcConnId: Buffer;
  netId: number;
  token: Buffer;
  bobStaticKey: Buffer;
  bobIntroKey: Buffer;
  nowMs?: number;
  blocks?: Ssu2Block[];
  packetNumber?: number;
};

export function createSessionRequest(options: SessionRequestOptions): { packet: Buffer; state: AliceSsu2State } {
  if (options.destConnId.equals(options.srcConnId)) throw new Error('SSU2 source and destination connection IDs must differ');
  const noise = initSsu2Noise(options.bobStaticKey);
  const ephemeral = generateX25519KeyPair();
  const header = encodeSsu2LongHeader({
    destConnId: options.destConnId, packetNumber: options.packetNumber ?? randomPacketNumber(), type: SSU2_SESSION_REQUEST,
    version: SSU2_VERSION, netId: options.netId, flag: 0, srcConnId: options.srcConnId, token: options.token,
  });
  mixHash(noise, header);
  mixHash(noise, ephemeral.publicKey);
  mixDh(noise, x25519SharedSecret(ephemeral.privateKey, options.bobStaticKey));
  const payload = payloadFor([dateTimeBlock(options.nowMs), ...(options.blocks ?? [])]);
  const ciphertext = encryptAead(noise.k, ZERO_NONCE, noise.h, payload);
  mixHash(noise, ciphertext);
  const packet = protectSsu2Header(Buffer.concat([header, ephemeral.publicKey, ciphertext]), options.bobIntroKey, options.bobIntroKey, 'session-request');
  return {
    packet,
    state: {
      noise, ephemeralPrivateKey: ephemeral.privateKey, ephemeralPublicKey: ephemeral.publicKey,
      bobStaticKey: Buffer.from(options.bobStaticKey), bobIntroKey: Buffer.from(options.bobIntroKey),
      destConnId: Buffer.from(options.destConnId), srcConnId: Buffer.from(options.srcConnId), netId: options.netId,
    },
  };
}

/** Cheap first step for Bob: header + X without any DH, so the token can be checked first. */
export function openSessionRequestHeader(packet: Buffer, bobIntroKey: Buffer): { header: Ssu2LongHeader; headerBytes: Buffer; ephemeralKey: Buffer } {
  if (packet.length < 64 + 8 + SSU2_MAC_LENGTH) throw new Error('SSU2 Session Request is truncated');
  const clear = unprotectSsu2Header(packet, bobIntroKey, bobIntroKey, 'session-request');
  const header = decodeSsu2LongHeader(clear);
  if (header.type !== SSU2_SESSION_REQUEST) throw new Error('Not an SSU2 Session Request');
  return { header, headerBytes: Buffer.from(clear.subarray(0, 32)), ephemeralKey: Buffer.from(clear.subarray(32, 64)) };
}

export type BobSsu2Keys = { staticPrivateKey: KeyObject; staticPublicKey: Buffer; introKey: Buffer };

export function processSessionRequest(packet: Buffer, keys: BobSsu2Keys): { header: Ssu2LongHeader; ephemeralKey: Buffer; blocks: Ssu2Block[]; noise: NoiseState } {
  const opened = openSessionRequestHeader(packet, keys.introKey);
  const noise = initSsu2Noise(keys.staticPublicKey);
  mixHash(noise, opened.headerBytes);
  mixHash(noise, opened.ephemeralKey);
  mixDh(noise, x25519SharedSecret(keys.staticPrivateKey, opened.ephemeralKey));
  const ciphertext = packet.subarray(64);
  const payload = decryptAead(noise.k, ZERO_NONCE, noise.h, ciphertext);
  mixHash(noise, ciphertext);
  return { header: opened.header, ephemeralKey: opened.ephemeralKey, blocks: decodeBlocks(payload), noise };
}

// ---------------------------------------------------------------------------
// Session Created (type 1): <- e, ee
// ---------------------------------------------------------------------------

export function sessionCreatedHeaderKey(noise: NoiseState): Buffer { return hkdf(noise.ck, ZEROLEN, 'SessCreateHeader', 32); }
export function sessionConfirmedHeaderKey(noise: NoiseState): Buffer { return hkdf(noise.ck, ZEROLEN, 'SessionConfirmed', 32); }

export type BobSsu2State = {
  noise: NoiseState;
  ephemeralPrivateKey: KeyObject;
  ephemeralPublicKey: Buffer;
  aliceEphemeralKey: Buffer;
  /** k_header_2 for the Session Confirmed Alice will send. */
  confirmedHeaderKey: Buffer;
};

export function createSessionCreated(requestNoise: NoiseState, options: {
  destConnId: Buffer; srcConnId: Buffer; netId: number; bobIntroKey: Buffer; aliceEphemeralKey: Buffer;
  nowMs?: number; blocks?: Ssu2Block[]; packetNumber?: number;
}): { packet: Buffer; state: BobSsu2State } {
  const noise = cloneNoise(requestNoise);
  const kHeader2 = sessionCreatedHeaderKey(noise);
  const ephemeral = generateX25519KeyPair();
  const header = encodeSsu2LongHeader({
    destConnId: options.destConnId, packetNumber: options.packetNumber ?? randomPacketNumber(), type: SSU2_SESSION_CREATED,
    version: SSU2_VERSION, netId: options.netId, flag: 0, srcConnId: options.srcConnId, token: Buffer.alloc(8),
  });
  mixHash(noise, header);
  mixHash(noise, ephemeral.publicKey);
  mixDh(noise, x25519SharedSecret(ephemeral.privateKey, options.aliceEphemeralKey));
  const payload = payloadFor([dateTimeBlock(options.nowMs), ...(options.blocks ?? [])]);
  const ciphertext = encryptAead(noise.k, ZERO_NONCE, noise.h, payload);
  mixHash(noise, ciphertext);
  const packet = protectSsu2Header(Buffer.concat([header, ephemeral.publicKey, ciphertext]), options.bobIntroKey, kHeader2, 'session-request');
  return {
    packet,
    state: {
      noise, ephemeralPrivateKey: ephemeral.privateKey, ephemeralPublicKey: ephemeral.publicKey,
      aliceEphemeralKey: Buffer.from(options.aliceEphemeralKey), confirmedHeaderKey: sessionConfirmedHeaderKey(noise),
    },
  };
}

/** Alice: true when the packet unmasks as a Session Created for this handshake (vs. a Retry). */
export function looksLikeSessionCreated(packet: Buffer, state: AliceSsu2State): boolean {
  if (packet.length < 64 + 8 + SSU2_MAC_LENGTH) return false;
  const peek = peekHeaderBytes8to16(packet, sessionCreatedHeaderKey(state.noise));
  return peek.type === SSU2_SESSION_CREATED && peek.version === SSU2_VERSION && peek.netId === state.netId;
}

export function looksLikeRetry(packet: Buffer, bobIntroKey: Buffer, netId: number): boolean {
  if (packet.length < 32 + 8 + SSU2_MAC_LENGTH) return false;
  const peek = peekHeaderBytes8to16(packet, bobIntroKey);
  return peek.type === SSU2_RETRY && peek.version === SSU2_VERSION && peek.netId === netId;
}

export function processSessionCreated(packet: Buffer, state: AliceSsu2State): { header: Ssu2LongHeader; blocks: Ssu2Block[]; noise: NoiseState; bobEphemeralKey: Buffer } {
  if (packet.length < 64 + 8 + SSU2_MAC_LENGTH) throw new Error('SSU2 Session Created is truncated');
  const noise = cloneNoise(state.noise);
  const kHeader2 = sessionCreatedHeaderKey(noise);
  const clear = unprotectSsu2Header(packet, state.bobIntroKey, kHeader2, 'session-request');
  const header = decodeSsu2LongHeader(clear);
  if (header.type !== SSU2_SESSION_CREATED) throw new Error('Not an SSU2 Session Created');
  if (!header.destConnId.equals(state.srcConnId)) throw new Error('Session Created connection ID mismatch');
  const bobEphemeralKey = Buffer.from(clear.subarray(32, 64));
  mixHash(noise, clear.subarray(0, 32));
  mixHash(noise, bobEphemeralKey);
  mixDh(noise, x25519SharedSecret(state.ephemeralPrivateKey, bobEphemeralKey));
  const ciphertext = packet.subarray(64);
  const payload = decryptAead(noise.k, ZERO_NONCE, noise.h, ciphertext);
  mixHash(noise, ciphertext);
  return { header, blocks: decodeBlocks(payload), noise, bobEphemeralKey };
}

// ---------------------------------------------------------------------------
// Session Confirmed (type 2): -> s, se   (+ data-phase split)
// ---------------------------------------------------------------------------

export type DirectionKeys = { key: Buffer; headerKey: Buffer };
export type Ssu2DataKeys = { ab: DirectionKeys; ba: DirectionKeys };

/** split(): keydata = HKDF(ck, ZEROLEN, "", 64); per-direction HKDF(k, ZEROLEN, "HKDFSSU2DataKeys", 64). */
export function deriveSsu2DataKeys(ck: Buffer): Ssu2DataKeys {
  const keydata = hkdf(ck, ZEROLEN, '', 64);
  const ab = hkdf(keydata.subarray(0, 32), ZEROLEN, 'HKDFSSU2DataKeys', 64);
  const ba = hkdf(keydata.subarray(32, 64), ZEROLEN, 'HKDFSSU2DataKeys', 64);
  keydata.fill(0);
  return {
    ab: { key: Buffer.from(ab.subarray(0, 32)), headerKey: Buffer.from(ab.subarray(32, 64)) },
    ba: { key: Buffer.from(ba.subarray(0, 32)), headerKey: Buffer.from(ba.subarray(32, 64)) },
  };
}

/**
 * Builds Session Confirmed, fragmenting across several packets when needed
 * (all fragments share packet number 0; fragment 0's header is the Noise AD).
 */
export function createSessionConfirmed(createdNoise: NoiseState, options: {
  destConnId: Buffer; bobIntroKey: Buffer; bobEphemeralKey: Buffer;
  staticPrivateKey: KeyObject; staticPublicKey: Buffer; payloadBlocks: Ssu2Block[]; maxPacketSize: number;
}): { packets: Buffer[]; keys: Ssu2DataKeys } {
  const noise = cloneNoise(createdNoise);
  const kHeader2 = sessionConfirmedHeaderKey(noise);
  const perPacket = options.maxPacketSize - SSU2_SHORT_HEADER_LENGTH;
  const blocks = padBlocks([...options.payloadBlocks], 8, 0xffff, 0);
  const payload = encodeBlocks(blocks);
  const total = 48 + payload.length + 16;
  let fragments = Math.ceil(total / perPacket);
  let finalPayload = payload;
  // The last fragment needs >= 24 bytes for header protection.
  if (fragments > 1 && total - (fragments - 1) * perPacket < 24) {
    finalPayload = encodeBlocks(padBlocks([...options.payloadBlocks], payload.length + 24, 0xffff, 0));
    fragments = Math.ceil((48 + finalPayload.length + 16) / perPacket);
  }
  if (fragments > 15) throw new Error('Session Confirmed needs more than 15 fragments');
  const header = encodeSsu2ShortHeader({ destConnId: options.destConnId, packetNumber: 0, type: SSU2_SESSION_CONFIRMED, flag: fragments & 0x0f, moreFlags: 0 });
  mixHash(noise, header);
  const part1 = encryptAead(noise.k, noiseNonce(1), noise.h, options.staticPublicKey);
  mixHash(noise, part1);
  mixDh(noise, x25519SharedSecret(options.staticPrivateKey, options.bobEphemeralKey));
  const part2 = encryptAead(noise.k, ZERO_NONCE, noise.h, finalPayload);
  mixHash(noise, part2);
  const keys = deriveSsu2DataKeys(noise.ck);
  const body = Buffer.concat([part1, part2]);
  const packets: Buffer[] = [];
  for (let index = 0; index < fragments; index++) {
    const chunk = body.subarray(index * perPacket, (index + 1) * perPacket);
    const fragmentHeader = index === 0 ? header : encodeSsu2ShortHeader({
      destConnId: options.destConnId, packetNumber: 0, type: SSU2_SESSION_CONFIRMED, flag: ((index & 0x0f) << 4) | (fragments & 0x0f), moreFlags: 0,
    });
    packets.push(protectSsu2Header(Buffer.concat([fragmentHeader, chunk]), options.bobIntroKey, kHeader2, 'short'));
  }
  return { packets, keys };
}

/** Bob: unmasks a Session Confirmed fragment header. */
export function openSessionConfirmedHeader(packet: Buffer, bobIntroKey: Buffer, kHeader2: Buffer): { header: Ssu2ShortHeader; headerBytes: Buffer; fragment: number; total: number } {
  const clear = unprotectSsu2Header(packet, bobIntroKey, kHeader2, 'short');
  const header = decodeSsu2ShortHeader(clear);
  if (header.type !== SSU2_SESSION_CONFIRMED) throw new Error('Not an SSU2 Session Confirmed');
  if (header.packetNumber !== 0) throw new Error('Session Confirmed packet number must be 0');
  const total = header.flag & 0x0f; const fragment = header.flag >> 4;
  if (total < 1 || fragment >= total) throw new Error('Invalid Session Confirmed fragment info');
  return { header, headerBytes: Buffer.from(clear.subarray(0, 16)), fragment, total };
}

/** Bob: processes reassembled Session Confirmed (fragment 0 header + concatenated bodies). */
export function processSessionConfirmed(headerBytes: Buffer, body: Buffer, state: BobSsu2State): {
  aliceStaticKey: Buffer; blocks: Ssu2Block[]; keys: Ssu2DataKeys;
} {
  if (body.length < 48 + 8 + 16) throw new Error('SSU2 Session Confirmed is truncated');
  const noise = cloneNoise(state.noise);
  mixHash(noise, headerBytes);
  const part1 = body.subarray(0, 48);
  const aliceStaticKey = decryptAead(noise.k, noiseNonce(1), noise.h, part1);
  mixHash(noise, part1);
  mixDh(noise, x25519SharedSecret(state.ephemeralPrivateKey, aliceStaticKey));
  const part2 = body.subarray(48);
  const payload = decryptAead(noise.k, ZERO_NONCE, noise.h, part2);
  mixHash(noise, part2);
  return { aliceStaticKey: Buffer.from(aliceStaticKey), blocks: decodeBlocks(payload), keys: deriveSsu2DataKeys(noise.ck) };
}

// ---------------------------------------------------------------------------
// Data phase (type 6)
// ---------------------------------------------------------------------------

export function encryptDataPacket(options: {
  destConnId: Buffer; packetNumber: number; immediateAck?: boolean; payload: Buffer;
  send: DirectionKeys; remoteIntroKey: Buffer;
}): Buffer {
  if (options.payload.length < 8) throw new Error('SSU2 data payload must be at least 8 bytes');
  const header = encodeSsu2ShortHeader({
    destConnId: options.destConnId, packetNumber: options.packetNumber, type: SSU2_DATA, flag: options.immediateAck ? 1 : 0, moreFlags: 0,
  });
  const ciphertext = encryptAead(options.send.key, noiseNonce(options.packetNumber), header, options.payload);
  return protectSsu2Header(Buffer.concat([header, ciphertext]), options.remoteIntroKey, options.send.headerKey, 'short');
}

export function decryptDataPacket(packet: Buffer, options: { ownIntroKey: Buffer; receive: DirectionKeys }): { header: Ssu2ShortHeader; payload: Buffer } {
  const clear = unprotectSsu2Header(packet, options.ownIntroKey, options.receive.headerKey, 'short');
  const header = decodeSsu2ShortHeader(clear);
  if (header.type !== SSU2_DATA) throw new Error(`Unexpected SSU2 short-header type ${header.type}`);
  const payload = decryptAead(options.receive.key, noiseNonce(header.packetNumber), clear.subarray(0, 16), clear.subarray(16));
  return { header, payload };
}
