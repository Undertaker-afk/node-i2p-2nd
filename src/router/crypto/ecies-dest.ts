import { createPublicKey, randomInt, type KeyObject } from 'node:crypto';
import { decodeElligator2, generateElligator2KeyPair } from './elligator2.ts';
import {
  decryptAead, encryptAead, hkdf, mixKey, noiseNonce, rawPublicKey, sha256, x25519SharedSecret,
} from './x25519.ts';
import { RatchetTagSet, type SessionTagEntry } from './tagset.ts';
import {
  encodeDateTimeBlock, encodeGarlicCloveBlock, encodePaddingBlock, parseGarlicPayloadBlocks,
  type GarlicClove,
} from '../tunnel/garlic.ts';
import type { I2npMessage } from '../protocol/i2np.ts';
import { I2NP_MAX_PAYLOAD } from '../protocol/i2np.ts';

export const I2NP_GARLIC = 11;
const PROTOCOL_NAME = Buffer.from('Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256', 'ascii');
const ZERO = Buffer.alloc(0);

export type NoiseIkState = { h: Buffer; ck: Buffer; key: Buffer; n: number };
export type EstablishedDestSession = {
  send: RatchetTagSet;
  receive: RatchetTagSet;
  receiveTags: Map<string, SessionTagEntry>;
  remoteStaticPublicKey: Buffer;
};

function protocolNameHash(): Buffer { return sha256(PROTOCOL_NAME); }

export function initNoiseIk(bobStaticPublicKey: Buffer): NoiseIkState {
  if (!Buffer.isBuffer(bobStaticPublicKey) || bobStaticPublicKey.length !== 32) throw new Error('Bob static key must be 32 bytes');
  const nameHash = protocolNameHash();
  const hh = sha256(nameHash);
  return { h: sha256(hh, bobStaticPublicKey), ck: Buffer.from(nameHash), key: Buffer.alloc(32), n: 0 };
}

function mixHash(h: Buffer, data: Buffer): Buffer { return sha256(h, data); }

function encryptNoise(state: NoiseIkState, plaintext: Buffer): Buffer {
  const nonce = noiseNonce(state.n);
  const ciphertext = encryptAead(state.key, nonce, state.h, plaintext);
  state.n++;
  return ciphertext;
}

function decryptNoise(state: NoiseIkState, ciphertext: Buffer, plaintextLength: number): Buffer {
  const nonce = noiseNonce(state.n);
  const plaintext = decryptAead(state.key, nonce, state.h, ciphertext.subarray(0, plaintextLength + 16));
  state.n++;
  return plaintext;
}

function applyMixKey(state: NoiseIkState, shared: Buffer): void {
  const mixed = mixKey(state.ck, shared);
  state.ck = mixed.ck;
  state.key = mixed.key;
  state.n = 0;
}

export function encodeDestGarlicPayload(cloves: readonly GarlicClove[], includeDateTime = true): Buffer {
  const parts: Buffer[] = [];
  if (includeDateTime) parts.push(encodeDateTimeBlock());
  for (const clove of cloves) parts.push(encodeGarlicCloveBlock(clove));
  parts.push(encodePaddingBlock());
  return Buffer.concat(parts);
}

/**
 * Every garlic message needs a fresh I2NP message ID: gateways and routers drop repeated IDs as
 * replays (a fixed default of 1 made every ES message after the first vanish at the inbound gateway).
 */
export function randomMessageId(): number { return randomInt(1, 0x1_0000_0000); }

export function encodeGarlicEnvelope(body: Buffer, messageId: number, expiration: number): I2npMessage {
  if (4 + body.length > I2NP_MAX_PAYLOAD) throw new RangeError('Garlic Message exceeds I2NP payload size');
  const payload = Buffer.allocUnsafe(4 + body.length);
  payload.writeUInt32BE(body.length, 0);
  body.copy(payload, 4);
  return { type: I2NP_GARLIC, id: messageId >>> 0, expiration, payload };
}

export function decodeGarlicBody(message: I2npMessage): Buffer {
  if (message.type !== I2NP_GARLIC) throw new Error('Expected an I2NP Garlic Message');
  if (!Buffer.isBuffer(message.payload) || message.payload.length < 4) throw new Error('Garlic Message payload is truncated');
  const length = message.payload.readUInt32BE(0);
  if (length !== message.payload.length - 4) throw new Error('Garlic Message length mismatch');
  return message.payload.subarray(4);
}

function createNsrTagSet(chainKey: Buffer): RatchetTagSet {
  const tagsetKey = hkdf(chainKey, ZERO, 'SessionReplyTags', 32);
  const tagset = new RatchetTagSet();
  tagset.dhInitialize(chainKey, tagsetKey);
  return tagset;
}

function splitAndInitSessions(chainKey: Buffer, remoteStaticPublicKey: Buffer, role: 'alice' | 'bob'): EstablishedDestSession {
  const split = hkdf(chainKey, ZERO, '', 64);
  const kAb = split.subarray(0, 32);
  const kBa = split.subarray(32, 64);
  const send = new RatchetTagSet();
  const receive = new RatchetTagSet();
  send.dhInitialize(chainKey, role === 'alice' ? kAb : kBa);
  receive.dhInitialize(chainKey, role === 'alice' ? kBa : kAb);
  return {
    send, receive,
    receiveTags: new Map(receive.generateWindow(32).map(entry => [entry.tag.toString('hex'), entry])),
    remoteStaticPublicKey: Buffer.from(remoteStaticPublicKey),
  };
}

export type NewSessionResult = {
  message: I2npMessage;
  state: NoiseIkState;
  ephemeralPrivateKey: KeyObject;
  ephemeralPublicKey: Buffer;
  bobStaticPublicKey: Buffer;
  nsrTagSet: RatchetTagSet;
  nsrTags: Map<string, SessionTagEntry>;
};

/** Alice: Noise IK New Session with Elligator2 ephemeral and bound static key. */
export function wrapDestNewSession(
  cloves: readonly GarlicClove[],
  bobStaticPublicKey: Buffer,
  aliceStaticPublicKey: Buffer,
  aliceStaticPrivateKey: KeyObject,
  options: { messageId?: number; expiration?: number } = {},
): NewSessionResult {
  const ephemeral = generateElligator2KeyPair();
  const state = initNoiseIk(bobStaticPublicKey);
  state.h = mixHash(state.h, ephemeral.publicKey);
  applyMixKey(state, x25519SharedSecret(ephemeral.privateKey, bobStaticPublicKey));
  const staticCipher = encryptNoise(state, aliceStaticPublicKey);
  state.h = mixHash(state.h, staticCipher);
  applyMixKey(state, x25519SharedSecret(aliceStaticPrivateKey, bobStaticPublicKey));
  const payload = encodeDestGarlicPayload(cloves, true);
  let payloadCipher: Buffer;
  try { payloadCipher = encryptNoise(state, payload); }
  finally { payload.fill(0); }
  state.h = mixHash(state.h, payloadCipher);
  const body = Buffer.concat([ephemeral.encoded, staticCipher, payloadCipher]);
  const nsrTagSet = createNsrTagSet(state.ck);
  const nsrTags = new Map(nsrTagSet.generateWindow(12).map(entry => [entry.tag.toString('hex'), entry]));
  const expiration = options.expiration ?? Date.now() + 60_000;
  const messageId = options.messageId ?? randomMessageId();
  return {
    message: encodeGarlicEnvelope(body, messageId, expiration),
    state, ephemeralPrivateKey: ephemeral.privateKey, ephemeralPublicKey: ephemeral.publicKey,
    bobStaticPublicKey: Buffer.from(bobStaticPublicKey), nsrTagSet, nsrTags,
  };
}

export type IncomingNewSession = {
  state: NoiseIkState;
  aliceStaticPublicKey: Buffer;
  cloves: GarlicClove[];
  ephemeralPublicKey: Buffer;
};

/** Bob: decrypt a New Session addressed to his static X25519 key. */
export function unwrapDestNewSession(message: I2npMessage, bobStaticPrivateKey: KeyObject, bobStaticPublicKey: Buffer): IncomingNewSession {
  const body = decodeGarlicBody(message);
  if (body.length < 32 + 48 + 16) throw new Error('Destination New Session is truncated');
  const ephemeralPublicKey = decodeElligator2(body.subarray(0, 32));
  const state = initNoiseIk(bobStaticPublicKey);
  state.h = mixHash(state.h, ephemeralPublicKey);
  applyMixKey(state, x25519SharedSecret(bobStaticPrivateKey, ephemeralPublicKey));
  const aliceStaticPublicKey = decryptNoise(state, body.subarray(32), 32);
  state.h = mixHash(state.h, body.subarray(32, 80));
  if (aliceStaticPublicKey.every(byte => byte === 0)) throw new Error('Unbound destination sessions are not used for streaming');
  applyMixKey(state, x25519SharedSecret(bobStaticPrivateKey, aliceStaticPublicKey));
  const payloadCipher = body.subarray(80);
  const plaintext = decryptNoise(state, payloadCipher, payloadCipher.length - 16);
  state.h = mixHash(state.h, payloadCipher);
  try {
    const parsed = parseGarlicPayloadBlocks(plaintext);
    if (parsed.cloves.length < 1) throw new Error('Destination New Session contains no cloves');
    return { state, aliceStaticPublicKey, cloves: parsed.cloves, ephemeralPublicKey };
  } finally { plaintext.fill(0); }
}

export type NewSessionReplyResult = {
  message: I2npMessage;
  session: EstablishedDestSession;
};

/** Bob: Noise IK New Session Reply with Elligator2 ephemeral. */
export function wrapDestNewSessionReply(
  incoming: IncomingNewSession,
  cloves: readonly GarlicClove[],
  aliceStaticPublicKey: Buffer,
  bobStaticPrivateKey: KeyObject,
  options: { messageId?: number; expiration?: number } = {},
): NewSessionReplyResult {
  const nsrTagSet = createNsrTagSet(incoming.state.ck);
  const tag = nsrTagSet.nextTag().tag;
  const ephemeral = generateElligator2KeyPair();
  const state: NoiseIkState = { h: Buffer.from(incoming.state.h), ck: Buffer.from(incoming.state.ck), key: Buffer.from(incoming.state.key), n: 0 };
  state.h = mixHash(state.h, tag);
  state.h = mixHash(state.h, ephemeral.publicKey);
  applyMixKey(state, x25519SharedSecret(ephemeral.privateKey, incoming.ephemeralPublicKey));
  applyMixKey(state, x25519SharedSecret(ephemeral.privateKey, aliceStaticPublicKey));
  const emptyCipher = encryptNoise(state, ZERO);
  state.h = mixHash(state.h, emptyCipher);
  const split = hkdf(state.ck, ZERO, '', 64);
  const payloadKey = hkdf(split.subarray(32, 64), ZERO, 'AttachPayloadKDF', 32);
  const payload = encodeDestGarlicPayload(cloves, false);
  let payloadCipher: Buffer;
  try { payloadCipher = encryptAead(payloadKey, Buffer.alloc(12), state.h, payload); }
  finally { payload.fill(0); }
  const session = splitAndInitSessions(state.ck, aliceStaticPublicKey, 'bob');
  const body = Buffer.concat([tag, ephemeral.encoded, emptyCipher, payloadCipher]);
  return {
    message: encodeGarlicEnvelope(body, options.messageId ?? randomMessageId(), options.expiration ?? Date.now() + 60_000),
    session,
  };
}

export function unwrapDestNewSessionReply(
  message: I2npMessage,
  pending: NewSessionResult,
  aliceStaticPrivateKey: KeyObject,
): { session: EstablishedDestSession; cloves: GarlicClove[] } {
  const body = decodeGarlicBody(message);
  if (body.length < 8 + 32 + 16 + 16) throw new Error('Destination New Session Reply is truncated');
  const tag = body.subarray(0, 8);
  if (!pending.nsrTags.has(tag.toString('hex'))) throw new Error('New Session Reply tag is unknown');
  const bobEphemeral = decodeElligator2(body.subarray(8, 40));
  const state: NoiseIkState = { h: Buffer.from(pending.state.h), ck: Buffer.from(pending.state.ck), key: Buffer.from(pending.state.key), n: 0 };
  state.h = mixHash(state.h, tag);
  state.h = mixHash(state.h, bobEphemeral);
  applyMixKey(state, x25519SharedSecret(pending.ephemeralPrivateKey, bobEphemeral));
  applyMixKey(state, x25519SharedSecret(aliceStaticPrivateKey, bobEphemeral));
  decryptNoise(state, body.subarray(40), 0);
  state.h = mixHash(state.h, body.subarray(40, 56));
  const split = hkdf(state.ck, ZERO, '', 64);
  const payloadKey = hkdf(split.subarray(32, 64), ZERO, 'AttachPayloadKDF', 32);
  const payloadCipher = body.subarray(56);
  const plaintext = decryptAead(payloadKey, Buffer.alloc(12), state.h, payloadCipher);
  try {
    const parsed = parseGarlicPayloadBlocks(plaintext);
    return { session: splitAndInitSessions(state.ck, pending.bobStaticPublicKey, 'alice'), cloves: parsed.cloves };
  } finally { plaintext.fill(0); }
}

export function wrapDestExistingSession(
  session: EstablishedDestSession,
  cloves: readonly GarlicClove[],
  options: { messageId?: number; expiration?: number } = {},
): I2npMessage {
  const entry = session.send.nextTag();
  const payload = encodeDestGarlicPayload(cloves, false);
  let ciphertext: Buffer;
  try { ciphertext = encryptAead(entry.key, noiseNonce(entry.index), entry.tag, payload); }
  finally { payload.fill(0); }
  return encodeGarlicEnvelope(Buffer.concat([entry.tag, ciphertext]), options.messageId ?? randomMessageId(), options.expiration ?? Date.now() + 60_000);
}

export function unwrapDestExistingSession(message: I2npMessage, session: EstablishedDestSession): GarlicClove[] {
  const body = decodeGarlicBody(message);
  if (body.length < 8 + 16) throw new Error('Existing Session Garlic is truncated');
  const tag = body.subarray(0, 8);
  const entry = session.receiveTags.get(tag.toString('hex'));
  if (!entry) throw new Error('Existing Session tag is unknown');
  session.receiveTags.delete(tag.toString('hex'));
  if (session.receiveTags.size < 16) {
    for (const extra of session.receive.generateWindow(16)) session.receiveTags.set(extra.tag.toString('hex'), extra);
  }
  const plaintext = decryptAead(entry.key, noiseNonce(entry.index), tag, body.subarray(8));
  try { return parseGarlicPayloadBlocks(plaintext).cloves; }
  finally { plaintext.fill(0); }
}

export function tryExistingSessionTag(body: Buffer, sessions: Iterable<EstablishedDestSession>): { session: EstablishedDestSession; cloves: GarlicClove[] } | undefined {
  if (body.length < 24) return undefined;
  const tag = body.subarray(0, 8).toString('hex');
  for (const session of sessions) {
    if (!session.receiveTags.has(tag)) continue;
    return { session, cloves: unwrapDestExistingSession(encodeGarlicEnvelope(body, 1, Date.now() + 60_000), session) };
  }
  return undefined;
}

export function publicKeyFromPrivate(privateKey: KeyObject): Buffer {
  return rawPublicKey(createPublicKey(privateKey));
}
