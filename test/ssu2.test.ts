import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRouterIdentity, type RouterIdentityKeys } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo, type RouterAddress } from '../src/router/protocol/router-info.ts';
import { createSsu2Address, findSsu2Endpoint, findSsu2AddressByStaticKey, hasDialableSsu2 } from '../src/router/transport/ssu2/address.ts';
import {
  ackedPacketNumbers, buildAckBlock, decodeAckBlock, encodeAckBlock, fragmentI2np, decodeBlocks, encodeBlocks, parseTermination,
  BLK_TERMINATION, BLK_ADDRESS, TERMINATION_CLOCK_SKEW,
} from '../src/router/transport/ssu2/blocks.ts';
import {
  createRetry, createSessionConfirmed, createSessionCreated, createSessionRequest, createTokenRequest, decryptDataPacket,
  encryptDataPacket, looksLikeRetry, looksLikeSessionCreated, openSessionConfirmedHeader, parseRetry, parseTokenRequest,
  peekDestConnId, processSessionConfirmed, processSessionCreated, processSessionRequest, randomConnId, SSU2_PROTOCOL_NAME,
} from '../src/router/transport/ssu2/handshake.ts';
import { Ssu2Transport } from '../src/router/transport/ssu2/transport.ts';
import type { Ssu2Session } from '../src/router/transport/ssu2/session.ts';

function ssu2Router(port?: number, host = '127.0.0.1', extra: RouterAddress[] = []): { identity: RouterIdentityKeys; introKey: Buffer; info: Buffer } {
  const identity = createRouterIdentity(); const introKey = randomBytes(32);
  const address = createSsu2Address({
    ...(port === undefined ? {} : { host, port }), staticKey: identity.identity.subarray(0, 32), introKey, caps: '4',
  });
  const info = createRouterInfoRecord(identity, Date.now(), [...extra, address], new Map([['netId', '2'], ['router.version', 'test']]));
  return { identity, introKey, info };
}

async function within<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error(label)), ms); })]); }
  finally { if (timer) clearTimeout(timer); }
}

test('SSU2 address publishes host/port/s/i/v=2 and parses back', () => {
  const router = ssu2Router(12345);
  const info = parseRouterInfo(router.info);
  const endpoint = findSsu2Endpoint(info);
  assert.ok(endpoint);
  assert.equal(endpoint.host, '127.0.0.1'); assert.equal(endpoint.port, 12345);
  assert.ok(endpoint.introKey.equals(router.introKey));
  assert.ok(endpoint.staticKey.equals(router.identity.identity.subarray(0, 32)));
  assert.equal(info.addresses[0]!.transport, 'SSU2');
  assert.equal(info.addresses[0]!.options.get('v'), '2');
  // Unpublished (firewalled) address still exposes s/i for Session Confirmed validation.
  const hidden = parseRouterInfo(ssu2Router().info);
  assert.equal(hasDialableSsu2(hidden), false);
  assert.ok(findSsu2AddressByStaticKey(hidden, hidden.identity.subarray(0, 32)));
});

test('SSU2 protocol name differs from NTCP2', () => {
  assert.equal(SSU2_PROTOCOL_NAME, 'Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256');
});

test('SSU2 Token Request and Retry round-trip with header protection', () => {
  const bobIntro = randomBytes(32); const src = randomConnId(); const dest = randomConnId();
  const request = createTokenRequest({ destConnId: dest, srcConnId: src, netId: 2, introKey: bobIntro });
  assert.ok(peekDestConnId(request, bobIntro).equals(dest));
  const opened = parseTokenRequest(request, bobIntro);
  assert.ok(opened.header.srcConnId.equals(src));
  assert.equal(opened.blocks[0]!.type, 0);
  assert.throws(() => parseTokenRequest(request, randomBytes(32)));
  const token = randomBytes(8);
  const retry = createRetry({ destConnId: src, srcConnId: dest, netId: 2, introKey: bobIntro, token, blocks: [{ type: BLK_ADDRESS, data: Buffer.from([0x30, 0x39, 1, 2, 3, 4]) }] });
  assert.equal(looksLikeRetry(retry, bobIntro, 2), true);
  const parsed = parseRetry(retry, bobIntro);
  assert.ok(parsed.token.equals(token));
  assert.ok(parsed.header.destConnId.equals(src));
  // Rejection: zero token + termination block
  const reject = createRetry({ destConnId: src, srcConnId: dest, netId: 2, introKey: bobIntro, token: Buffer.alloc(8), blocks: [{ type: BLK_TERMINATION, data: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, TERMINATION_CLOCK_SKEW]) }] });
  const rejected = parseRetry(reject, bobIntro);
  assert.ok(rejected.token.every(byte => byte === 0));
  assert.equal(parseTermination(rejected.blocks.find(block => block.type === BLK_TERMINATION)!).reason, TERMINATION_CLOCK_SKEW);
});

test('SSU2 Noise XK handshake and data keys agree (pure functions)', () => {
  const alice = createRouterIdentity(); const bob = createRouterIdentity();
  const bobIntro = randomBytes(32); const src = randomConnId(); const dest = randomConnId(); const token = randomBytes(8);
  const bobStatic = bob.identity.subarray(0, 32);
  const request = createSessionRequest({ destConnId: dest, srcConnId: src, netId: 2, token, bobStaticKey: bobStatic, bobIntroKey: bobIntro });
  const received = processSessionRequest(request.packet, { staticPrivateKey: bob.encryptionPrivateKey, staticPublicKey: bobStatic, introKey: bobIntro });
  assert.ok(received.header.token.equals(token));
  assert.ok(received.noise.h.equals(request.state.noise.h));
  assert.ok(received.noise.ck.equals(request.state.noise.ck));
  const created = createSessionCreated(received.noise, { destConnId: src, srcConnId: dest, netId: 2, bobIntroKey: bobIntro, aliceEphemeralKey: received.ephemeralKey });
  assert.equal(looksLikeSessionCreated(created.packet, request.state), true);
  assert.equal(looksLikeRetry(created.packet, bobIntro, 2), false);
  const aliceCreated = processSessionCreated(created.packet, request.state);
  assert.ok(aliceCreated.noise.h.equals(created.state.noise.h));
  const ri = randomBytes(900);
  const confirmed = createSessionConfirmed(aliceCreated.noise, {
    destConnId: dest, bobIntroKey: bobIntro, bobEphemeralKey: aliceCreated.bobEphemeralKey,
    staticPrivateKey: alice.encryptionPrivateKey, staticPublicKey: alice.identity.subarray(0, 32),
    payloadBlocks: [{ type: 2, data: Buffer.concat([Buffer.from([0, 1]), ri]) }], maxPacketSize: 600,
  });
  assert.ok(confirmed.packets.length >= 2, 'RouterInfo larger than one packet must fragment');
  const headers = confirmed.packets.map(packet => openSessionConfirmedHeader(packet, bobIntro, created.state.confirmedHeaderKey));
  assert.equal(headers[0]!.total, confirmed.packets.length);
  const body = Buffer.concat(confirmed.packets.map(packet => packet.subarray(16)));
  const bobConfirmed = processSessionConfirmed(headers[0]!.headerBytes, body, created.state);
  assert.ok(bobConfirmed.aliceStaticKey.equals(alice.identity.subarray(0, 32)));
  assert.ok(bobConfirmed.blocks[0]!.data.subarray(2).equals(ri));
  assert.ok(bobConfirmed.keys.ab.key.equals(confirmed.keys.ab.key));
  assert.ok(bobConfirmed.keys.ba.headerKey.equals(confirmed.keys.ba.headerKey));
  // Data phase: Alice -> Bob uses Bob's intro key as k_header_1 and ab keys.
  const payload = encodeBlocks([{ type: 3, data: Buffer.concat([Buffer.from([20, 0, 0, 0, 1, 0x70, 0, 0, 0]), Buffer.from('ping')]) }]);
  const data = encryptDataPacket({ destConnId: dest, packetNumber: 1, payload, send: confirmed.keys.ab, remoteIntroKey: bobIntro });
  assert.ok(peekDestConnId(data, bobIntro).equals(dest));
  const decrypted = decryptDataPacket(data, { ownIntroKey: bobIntro, receive: bobConfirmed.keys.ab });
  assert.equal(decrypted.header.packetNumber, 1);
  assert.ok(decrypted.payload.equals(payload));
  assert.throws(() => decryptDataPacket(data, { ownIntroKey: bobIntro, receive: bobConfirmed.keys.ba }));
});

test('SSU2 ACK blocks encode ranges per spec example', () => {
  // ACK 10 9 8 6 5 2 1 0, NACK 7 4 3 => through 10, acnt 2, ranges (1,2) (2,3)
  const ack = buildAckBlock([10, 9, 8, 6, 5, 2, 1, 0])!;
  assert.deepEqual(ack, { ackThrough: 10, acnt: 2, ranges: [[1, 2], [2, 3]] });
  const decoded = decodeAckBlock(encodeAckBlock(ack));
  assert.deepEqual(ackedPacketNumbers(decoded).sort((a, b) => a - b), [0, 1, 2, 5, 6, 8, 9, 10]);
});

test('SSU2 I2NP fragmentation produces First + Follow-on fragments', () => {
  const message = { type: 18, id: 0x01020304, expiration: Date.now() + 60_000, payload: randomBytes(3000) };
  const blocks = fragmentI2np(message, 1000);
  assert.equal(blocks[0]!.type, 4);
  assert.ok(blocks.slice(1).every(block => block.type === 5));
  assert.equal(blocks.at(-1)!.data[0]! & 1, 1);
  assert.deepEqual(decodeBlocks(encodeBlocks(blocks)).map(block => block.type), blocks.map(block => block.type));
});

async function startPair(options: { aliceFilter?: (d: 'in' | 'out', p: Buffer) => boolean } = {}): Promise<{
  alice: Ssu2Transport; bob: Ssu2Transport; bobInfo: Buffer; aliceRouter: ReturnType<typeof ssu2Router>; bobRouter: ReturnType<typeof ssu2Router>;
}> {
  // Reserve ephemeral UDP ports first, then publish them in the RouterInfos.
  const dgram = await import('node:dgram');
  const reserve = async () => {
    const socket = dgram.createSocket('udp4');
    await new Promise<void>(resolve => socket.bind(0, '127.0.0.1', () => resolve()));
    const port = socket.address().port; await new Promise<void>(resolve => socket.close(() => resolve()));
    return port;
  };
  const bobPort = await reserve(); const alicePort = await reserve();
  const bobRouter = ssu2Router(bobPort); const aliceRouter = ssu2Router(alicePort);
  const bob = new Ssu2Transport({ identity: bobRouter.identity, routerInfo: bobRouter.info, introKey: bobRouter.introKey, host: '127.0.0.1', port: bobPort, timeoutMs: 5_000 });
  const alice = new Ssu2Transport({
    identity: aliceRouter.identity, routerInfo: aliceRouter.info, introKey: aliceRouter.introKey, host: '127.0.0.1', port: alicePort, timeoutMs: 8_000,
    ...(options.aliceFilter ? { packetFilter: options.aliceFilter } : {}),
  });
  await bob.start(); await alice.start();
  return { alice, bob, bobInfo: bobRouter.info, aliceRouter, bobRouter };
}

test('SSU2 over loopback UDP: TokenRequest, Retry, XK handshake, I2NP both ways, fragmented I2NP', async () => {
  // Constructor validation happens before the pair is started.
  assert.throws(() => new Ssu2Transport({ identity: createRouterIdentity(), routerInfo: ssu2Router(1).info, introKey: randomBytes(32), port: 0 }), /lacks an SSU2 address/);
  const { alice, bob, bobInfo, aliceRouter, bobRouter } = await startPair();
  try {
    const inbound = new Promise<Ssu2Session>(resolve => bob.once('connection', resolve));
    const learned = new Promise<Buffer>(resolve => bob.once('routerInfo', resolve));
    const session = await within(alice.connect(bobInfo), 8_000, 'SSU2 connect timed out');
    const bobSession = await within(inbound, 3_000, 'Bob did not accept the SSU2 session');
    assert.ok(session.remoteIdentityHash.equals(bobRouter.identity.identityHash));
    assert.ok(bobSession.remoteIdentityHash.equals(aliceRouter.identity.identityHash));
    assert.ok((await learned).equals(aliceRouter.info));
    assert.equal(session.transport, 'SSU2');
    await within(new Promise(resolve => session.isEstablished ? resolve(undefined) : session.once('established', resolve)), 3_000, 'Alice never saw Bob ACK Session Confirmed');
    // Bob sent a New Token block; Alice can skip Token Request next time.
    await within((async () => { while (!alice.hasOutgoingToken('127.0.0.1', bob.address!.port)) await new Promise(r => setTimeout(r, 10)); })(), 2_000, 'no New Token');

    const ping = { type: 20, id: 12345, expiration: Date.now() + 60_000, payload: Buffer.from('ping over SSU2') };
    const gotPing = new Promise<{ type: number; id: number; payload: Buffer }>(resolve => bobSession.once('i2np', resolve));
    await session.sendI2np(ping);
    const received = await within(gotPing, 3_000, 'Bob did not receive I2NP');
    assert.equal(received.type, 20); assert.equal(received.id, 12345); assert.ok(received.payload.equals(ping.payload));

    const big = { type: 18, id: 777, expiration: Date.now() + 60_000, payload: randomBytes(5000) };
    const gotBig = new Promise<{ payload: Buffer }>(resolve => session.once('i2np', resolve));
    await bobSession.sendI2np(big);
    assert.ok((await within(gotBig, 3_000, 'Alice did not receive fragmented I2NP')).payload.equals(big.payload));
    // All data acknowledged
    await within((async () => { while (session.inflightPackets || bobSession.inflightPackets) await new Promise(r => setTimeout(r, 20)); })(), 3_000, 'packets never ACKed');

    const closed = new Promise(resolve => bobSession.once('close', resolve));
    session.close();
    await within(closed, 3_000, 'Termination not propagated');
    assert.equal(bob.activeSessions, 0);
  } finally { await alice.stop(); await bob.stop(); }
});

test('SSU2 retransmits lost data packets and reuses New Token (skips Token Request)', async () => {
  let dropNextData = false; let sentTokenRequests = 0;
  const { alice, bob, bobInfo } = await startPair({
    aliceFilter: (direction, packet) => {
      if (direction !== 'out') return true;
      if (packet.length > 200 && dropNextData) { dropNextData = false; return false; }
      return true;
    },
  });
  try {
    const inbound = new Promise<Ssu2Session>(resolve => bob.once('connection', resolve));
    const session = await within(alice.connect(bobInfo), 8_000, 'connect timed out');
    const bobSession = await inbound;
    await within((async () => { while (!alice.hasOutgoingToken('127.0.0.1', bob.address!.port)) await new Promise(r => setTimeout(r, 10)); })(), 2_000, 'no New Token');
    dropNextData = true;
    const got = new Promise<{ payload: Buffer }>(resolve => bobSession.once('i2np', resolve));
    const payload = randomBytes(400);
    await session.sendI2np({ type: 20, id: 99, expiration: Date.now() + 60_000, payload });
    assert.ok((await within(got, 5_000, 'retransmission never delivered')).payload.equals(payload));
    assert.equal(dropNextData, false);
    session.close();
    await new Promise(r => setTimeout(r, 50));
    // Second connection: token from New Token block => Session Request directly.
    const bobAddress = bob.address!;
    const original = (alice as unknown as { send: (p: Buffer, h: string, port: number) => void }).send.bind(alice);
    (alice as unknown as { send: (p: Buffer, h: string, port: number) => void }).send = (packet, host, port) => {
      if (packet.length < 88 && port === bobAddress.port) sentTokenRequests++;
      original(packet, host, port);
    };
    const inbound2 = new Promise<Ssu2Session>(resolve => bob.once('connection', resolve));
    const second = await within(alice.connect(bobInfo), 8_000, 'second connect timed out');
    await inbound2;
    assert.equal(sentTokenRequests, 0, 'Alice should not send a Token Request when she holds a token');
    second.close();
  } finally { await alice.stop(); await bob.stop(); }
});

test('SSU2 Bob answers a Session Request carrying a bad token with Retry, then accepts', async () => {
  const { alice, bob, bobInfo } = await startPair();
  try {
    // Plant a bogus outgoing token so Alice skips Token Request and uses an invalid token.
    const tokens = (alice as unknown as { outgoingTokens: Map<string, { token: Buffer; expires: number }> }).outgoingTokens;
    tokens.set(`127.0.0.1:${bob.address!.port}`, { token: randomBytes(8), expires: Date.now() + 60_000 });
    const inbound = new Promise<Ssu2Session>(resolve => bob.once('connection', resolve));
    const session = await within(alice.connect(bobInfo), 8_000, 'connect after Retry timed out');
    await inbound;
    session.close();
  } finally { await alice.stop(); await bob.stop(); }
});
