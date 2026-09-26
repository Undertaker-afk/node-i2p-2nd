import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { createRouterIdentity } from '../src/router/identity.ts';
import { decodeI2np, type I2npMessage } from '../src/router/protocol/i2np.ts';
import type { Ntcp2Connection } from '../src/router/transport/ntcp2/connection.ts';
import { preprocessOutboundTunnelMessage, processTunnelDataLayer, removeTunnelDataLayer } from '../src/router/tunnel/data.ts';
import { buildTunnelMessageFragments, parseTunnelMessageFragment } from '../src/router/tunnel/fragments.ts';
import { decodeTunnelDataPayload, decodeTunnelGatewayPayload, encodeTunnelDataPayload, encodeTunnelGatewayPayload } from '../src/router/tunnel/messages.ts';
import {
  decryptShortTunnelBuildReplyRecord, encodeShortBuildRequestPlaintext,
  encryptShortBuildRequestRecord, parseShortBuildReplyPlaintext, parseShortTunnelBuildPayload,
  transformShortBuildReplyCoverRecords,
} from '../src/router/tunnel/short-build.ts';
import { TransitTunnelService } from '../src/router/tunnel/transit.ts';
import { unwrapEciesExistingSessionGarlicMessage, wrapEciesExistingSessionGarlicMessage } from '../src/router/tunnel/garlic.ts';

function fakeConnection(identityHash: Buffer) {
  const sent: I2npMessage[] = [];
  const connection = {
    remoteIdentityHash: Buffer.from(identityHash), isClosed: false,
    sendI2np: async (message: I2npMessage) => { sent.push({ ...message, payload: Buffer.from(message.payload) }); },
  } as unknown as Ntcp2Connection;
  return { connection, sent };
}

test('transit forwards a short build, unwraps its reply, and routes tunnel messages', async () => {
  const local = createRouterIdentity(); const upstreamId = createRouterIdentity();
  const downstreamId = createRouterIdentity();
  const upstream = fakeConnection(upstreamId.identityHash); const downstream = fakeConnection(downstreamId.identityHash);
  const service = new TransitTunnelService({ identity: local, connectPeer: async hash => {
    assert.deepEqual(hash, downstreamId.identityHash); return downstream.connection;
  }});
  const plaintext = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 0x12345678, nextTunnelId: 0x23456789,
    nextIdentityHash: downstreamId.identityHash, flags: 0x80, nextMessageId: 901,
  });
  const encryptedBuildRecord = encryptShortBuildRequestRecord(local.identityHash, local.identity.subarray(0, 32), plaintext);
  const encrypted = encryptedBuildRecord.bytes;
  const cover = randomBytes(218);
  const futurePlaintext = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 0x34567890, nextTunnelId: 0x45678901,
    nextIdentityHash: upstreamId.identityHash, flags: 0, nextMessageId: 902,
  });
  const futureRecord = encryptShortBuildRequestRecord(downstreamId.identityHash, downstreamId.identity.subarray(0, 32), futurePlaintext);
  const request: I2npMessage = { type: 25, id: 17, expiration: Date.now() + 60_000, payload: Buffer.concat([Buffer.from([3]), cover, encrypted, futureRecord.bytes]) };
  await service.handleMessage(upstream.connection, request);
  assert.equal(downstream.sent.length, 1);
  assert.equal(downstream.sent[0]!.type, 25);
  assert.equal(downstream.sent[0]!.id, 901);
  // Transit state is installed before forwarding; build replies use a separate garlic reply tunnel.
  assert.equal(service.activeTunnels, 1);
  assert.equal(upstream.sent.length, 0);
  const forwardedRecords = parseShortTunnelBuildPayload(downstream.sent[0]!.payload);
  const ownReply = decryptShortTunnelBuildReplyRecord(forwardedRecords[1]!, 1, encryptedBuildRecord.replyKey, encryptedBuildRecord.handshakeHash);
  assert.equal(parseShortBuildReplyPlaintext(ownReply).returnCode, 0);
  assert.deepEqual(forwardedRecords[0], cover);
  assert.deepEqual(forwardedRecords[2], futureRecord.bytes);

  const tunnelMessage = randomBytes(1024);
  await service.handleMessage(upstream.connection, { type: 18, id: 18, expiration: Date.now() + 60_000, payload: encodeTunnelDataPayload(0x12345678, tunnelMessage) });
  const forwardedData = downstream.sent.find(message => message.type === 18);
  assert.ok(forwardedData);
  const decoded = decodeTunnelDataPayload(forwardedData.payload);
  assert.equal(decoded.tunnelId, 0x23456789);
  assert.notDeepEqual(decoded.message, tunnelMessage);
  await service.handleMessage(upstream.connection, { type: 18, id: 19, expiration: Date.now() + 60_000, payload: encodeTunnelDataPayload(0x12345678, tunnelMessage) });
  assert.equal(downstream.sent.filter(message => message.type === 18).length, 1);

  const appMessage: I2npMessage = { type: 20, id: 77, expiration: Date.now() + 60_000, payload: Buffer.from('inbound gateway') };
  await service.handleMessage(upstream.connection, {
    type: 19, id: 20, expiration: appMessage.expiration,
    payload: encodeTunnelGatewayPayload(0x12345678, appMessage),
  });
  const gatewayData = downstream.sent.filter(message => message.type === 18)[1]!;
  const gatewayFrame = decodeTunnelDataPayload(gatewayData.payload);
  assert.equal(gatewayFrame.tunnelId, 0x23456789);
  const unlayeredGatewayFrame = removeTunnelDataLayer(gatewayFrame.message, encryptedBuildRecord.layerKey, encryptedBuildRecord.ivKey);
  const innerFragment = parseTunnelMessageFragment(unlayeredGatewayFrame);
  assert.deepEqual(innerFragment.delivery, { type: 'local' });
  assert.deepEqual(decodeI2np(innerFragment.data), appMessage);
  service.stop();
});

test('three-hop short build keeps downstream requests intact and returns all authenticated reply records', async () => {
  const creator = createRouterIdentity(); const hopA = createRouterIdentity(); const hopB = createRouterIdentity();
  const endpoint = createRouterIdentity(); const replyGateway = createRouterIdentity();
  const toB = fakeConnection(hopB.identityHash); const toEndpoint = fakeConnection(endpoint.identityHash);
  const toReplyGateway = fakeConnection(replyGateway.identityHash);
  const serviceA = new TransitTunnelService({ identity: hopA, connectPeer: async hash => {
    assert.deepEqual(hash, hopB.identityHash); return toB.connection;
  }});
  const serviceB = new TransitTunnelService({ identity: hopB, connectPeer: async hash => {
    assert.deepEqual(hash, endpoint.identityHash); return toEndpoint.connection;
  }});
  const serviceEndpoint = new TransitTunnelService({ identity: endpoint, connectPeer: async hash => {
    assert.deepEqual(hash, replyGateway.identityHash); return toReplyGateway.connection;
  }});
  const hops = [hopA, hopB, endpoint];
  const recipients = [hopB, endpoint, replyGateway];
  const nextIds = [0x902, 0x903, 0x904];
  const replyKeys: ReturnType<typeof encryptShortBuildRequestRecord>[] = [];
  const records = hops.map((hop, index) => {
    const plain = encodeShortBuildRequestPlaintext({
      receiveTunnelId: 0x901 + index, nextTunnelId: nextIds[index]!,
      nextIdentityHash: recipients[index]!.identityHash,
      flags: index === hops.length - 1 ? 0x40 : 0,
      nextMessageId: 0x910 + index,
    });
    const encrypted = encryptShortBuildRequestRecord(hop.identityHash, hop.identity.subarray(0, 32), plain);
    replyKeys.push(encrypted);
    return encrypted.bytes;
  });
  const ingress = fakeConnection(creator.identityHash);
  const initialMessage: I2npMessage = {
    type: 25, id: 0x920, expiration: Date.now() + 60_000,
    payload: Buffer.concat([Buffer.from([records.length]), ...records]),
  };
  await serviceA.handleMessage(ingress.connection, initialMessage);
  assert.equal(toB.sent.length, 1);
  const afterA = toB.sent[0]!;
  assert.equal(afterA.type, 25);
  const recordsAtB = parseShortTunnelBuildPayload(afterA.payload);
  assert.deepEqual(recordsAtB[1], records[1]);
  assert.deepEqual(recordsAtB[2], records[2]);
  await serviceB.handleMessage(fakeConnection(hopA.identityHash).connection, afterA);
  assert.equal(toEndpoint.sent.length, 1);
  const afterB = toEndpoint.sent[0]!;
  const recordsAtEndpoint = parseShortTunnelBuildPayload(afterB.payload);
  assert.deepEqual(recordsAtEndpoint[2], records[2]);
  await serviceEndpoint.handleMessage(fakeConnection(hopB.identityHash).connection, afterB);
  assert.equal(toReplyGateway.sent.length, 1);
  const routed = decodeTunnelGatewayPayload(toReplyGateway.sent[0]!.payload);
  assert.equal(routed.tunnelId, nextIds[2]);
  const replyTag = replyKeys[2]!.garlicReplyTag!;
  const garlic = unwrapEciesExistingSessionGarlicMessage(routed.message, replyKeys[2]!.garlicReplyKey!, replyTag);
  assert.equal(garlic.type, 26);
  const endpointReplies = parseShortTunnelBuildPayload(garlic.payload);
  const plainReplies = transformShortBuildReplyCoverRecords(endpointReplies, 2, replyKeys[2]!.replyKey);
  for (let index = 0; index < hops.length; index++) {
    const response = decryptShortTunnelBuildReplyRecord(plainReplies[index]!, index, replyKeys[index]!.replyKey, replyKeys[index]!.handshakeHash);
    assert.equal(parseShortBuildReplyPlaintext(response).returnCode, 0);
  }
  const appMessage: I2npMessage = { type: 20, id: 0x930, expiration: Date.now() + 30_000, payload: Buffer.from('three-hop outbound') };
  const [clearFrame] = buildTunnelMessageFragments(appMessage, { type: 'local' });
  assert.ok(clearFrame);
  const gatewayFrame = preprocessOutboundTunnelMessage(clearFrame, replyKeys.map(({ layerKey, ivKey }) => ({ layerKey, ivKey })));
  const delivered = new Promise<I2npMessage>(resolve => serviceEndpoint.once('localMessage', resolve));
  await serviceA.handleMessage(ingress.connection, {
    type: 18, id: 0x931, expiration: appMessage.expiration,
    payload: encodeTunnelDataPayload(0x901, gatewayFrame),
  });
  const atB = toB.sent.filter(message => message.type === 18).at(-1)!;
  await serviceB.handleMessage(fakeConnection(hopA.identityHash).connection, atB);
  const atEndpoint = toEndpoint.sent.filter(message => message.type === 18).at(-1)!;
  await serviceEndpoint.handleMessage(fakeConnection(hopB.identityHash).connection, atEndpoint);
  assert.deepEqual(await delivered, appMessage);
  clearFrame.fill(0); gatewayFrame.fill(0);
  for (const record of plainReplies) record.fill(0);
  serviceA.stop(); serviceB.stop(); serviceEndpoint.stop();
});

test('a transit router that declines participation still forwards the request with encrypted status 30', async () => {
  const local = createRouterIdentity(); const prior = fakeConnection(randomBytes(32)); const next = fakeConnection(randomBytes(32));
  const nextHash = next.connection.remoteIdentityHash!;
  const service = new TransitTunnelService({ identity: local, allowTransit: false, connectPeer: async () => next.connection });
  const plain = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 300, nextTunnelId: 400, nextIdentityHash: nextHash, flags: 0, nextMessageId: 500,
  });
  const requestRecord = encryptShortBuildRequestRecord(local.identityHash, local.identity.subarray(0, 32), plain);
  await service.handleMessage(prior.connection, {
    type: 25, id: 20, expiration: Date.now() + 60_000,
    payload: Buffer.concat([Buffer.from([1]), requestRecord.bytes]),
  });
  assert.equal(next.sent.length, 1);
  assert.equal(next.sent[0]!.type, 25);
  assert.equal(service.activeTunnels, 0);
  const records = parseShortTunnelBuildPayload(next.sent[0]!.payload);
  const response = decryptShortTunnelBuildReplyRecord(records[0]!, 0, requestRecord.replyKey, requestRecord.handshakeHash);
  assert.equal(parseShortBuildReplyPlaintext(response).returnCode, 30);
  service.stop();
});

test('outbound endpoint registers its layer and returns the encrypted build reply through a garlic TunnelGateway', async () => {
  const local = createRouterIdentity(); const previous = fakeConnection(randomBytes(32));
  const replyGateway = createRouterIdentity(); const downstream = fakeConnection(replyGateway.identityHash);
  const service = new TransitTunnelService({ identity: local, connectPeer: async hash => {
    assert.deepEqual(hash, replyGateway.identityHash); return downstream.connection;
  }});
  const diagnostics: unknown[] = [];
  service.on('buildRejected', (...args: unknown[]) => diagnostics.push(args));
  service.on('tunnelError', error => diagnostics.push(error));
  const buildPlaintext = encodeShortBuildRequestPlaintext({
    receiveTunnelId: 701, nextTunnelId: 702, nextIdentityHash: replyGateway.identityHash,
    flags: 0x40, nextMessageId: 703,
  });
  const requestRecord = encryptShortBuildRequestRecord(local.identityHash, local.identity.subarray(0, 32), buildPlaintext);
  await service.handleMessage(previous.connection, {
    type: 25, id: 704, expiration: Date.now() + 60_000,
    payload: Buffer.concat([Buffer.from([1]), requestRecord.bytes]),
  });
  assert.equal(service.activeTunnels, 1);
  assert.deepEqual(diagnostics, []);
  assert.equal(downstream.sent.length, 1);
  const gateway = downstream.sent[0]!;
  assert.equal(gateway.type, 19);
  const routed = decodeTunnelGatewayPayload(gateway.payload);
  assert.equal(routed.tunnelId, 702);
  assert.equal(routed.message.type, 11);
  const garlicPayload = routed.message.payload;
  assert.equal(garlicPayload.readUInt32BE(0), garlicPayload.length - 4);
  assert.deepEqual(garlicPayload.subarray(4, 12), requestRecord.garlicReplyTag);
  const encryptedGarlic = garlicPayload.subarray(12);
  const decipher = createDecipheriv('chacha20-poly1305', requestRecord.garlicReplyKey!, Buffer.alloc(12), { authTagLength: 16 });
  decipher.setAAD(requestRecord.garlicReplyTag!, { plaintextLength: encryptedGarlic.length - 16 });
  decipher.setAuthTag(encryptedGarlic.subarray(-16));
  const clove = Buffer.concat([decipher.update(encryptedGarlic.subarray(0, -16)), decipher.final()]);
  assert.equal(clove[0], 11);
  assert.equal(clove[3], 0);
  assert.equal(clove[4], 26);
  assert.equal(clove.readUInt32BE(5), 703);
  const replyRecords = parseShortTunnelBuildPayload(clove.subarray(13));
  const replyPlaintext = decryptShortTunnelBuildReplyRecord(replyRecords[0]!, 0, requestRecord.replyKey, requestRecord.handshakeHash);
  assert.equal(parseShortBuildReplyPlaintext(replyPlaintext).returnCode, 0);

  const appMessage: I2npMessage = { type: 20, id: 709, expiration: Date.now() + 30_000, payload: Buffer.from('OBEP delivery') };
  const [outboundFrame] = buildTunnelMessageFragments(appMessage, { type: 'local' });
  assert.ok(outboundFrame);
  const predecryptedAtGateway = removeTunnelDataLayer(outboundFrame, requestRecord.layerKey, requestRecord.ivKey);
  const delivered = new Promise<I2npMessage>(resolve => service.once('localMessage', resolve));
  await service.handleMessage(previous.connection, {
    type: 18, id: 710, expiration: appMessage.expiration,
    payload: encodeTunnelDataPayload(701, predecryptedAtGateway),
  });
  assert.deepEqual(await delivered, appMessage);
  service.stop();
});

test('outbound endpoint uses a local inbound gateway route without garlic wrapping', async () => {
  const local = createRouterIdentity(); const upstream = fakeConnection(randomBytes(32));
  const downstreamId = createRouterIdentity(); const downstream = fakeConnection(downstreamId.identityHash);
  const service = new TransitTunnelService({ identity: local, connectPeer: async () => downstream.connection });
  const gatewayRequest = encryptShortBuildRequestRecord(local.identityHash, local.identity.subarray(0, 32), encodeShortBuildRequestPlaintext({
    receiveTunnelId: 801, nextTunnelId: 802, nextIdentityHash: downstreamId.identityHash,
    flags: 0x80, nextMessageId: 803,
  }));
  await service.handleMessage(upstream.connection, {
    type: 25, id: 804, expiration: Date.now() + 60_000,
    payload: Buffer.concat([Buffer.from([1]), gatewayRequest.bytes]),
  });
  const endpointRecord = encryptShortBuildRequestRecord(local.identityHash, local.identity.subarray(0, 32), encodeShortBuildRequestPlaintext({
    receiveTunnelId: 805, nextTunnelId: 801, nextIdentityHash: local.identityHash,
    flags: 0x40, nextMessageId: 806,
  }));
  await service.handleMessage(upstream.connection, {
    type: 25, id: 807, expiration: Date.now() + 60_000,
    payload: Buffer.concat([Buffer.from([1]), endpointRecord.bytes]),
  });
  const tunnelData = downstream.sent.find(message => message.type === 18);
  assert.ok(tunnelData);
  const frame = decodeTunnelDataPayload(tunnelData.payload);
  assert.equal(frame.tunnelId, 802);
  const clear = removeTunnelDataLayer(frame.message, gatewayRequest.layerKey, gatewayRequest.ivKey);
  const fragment = parseTunnelMessageFragment(clear);
  const reply = decodeI2np(fragment.data);
  assert.equal(reply.type, 26);
  const records = parseShortTunnelBuildPayload(reply.payload);
  const plaintext = decryptShortTunnelBuildReplyRecord(records[0]!, 0, endpointRecord.replyKey, endpointRecord.handshakeHash);
  assert.equal(parseShortBuildReplyPlaintext(plaintext).returnCode, 0);
  service.stop();
});

test('inbound tunnel unwraps a registered one-use garlic build reply', async () => {
  const local = createRouterIdentity(); const unused = fakeConnection(randomBytes(32));
  const service = new TransitTunnelService({ identity: local, connectPeer: async () => unused.connection });
  const keys = { layerKey: randomBytes(32), ivKey: randomBytes(32) };
  const tunnelId = 0x44556678;
  service.registerInboundEndpoint(tunnelId, [keys]);
  const key = randomBytes(32); const tag = randomBytes(8);
  service.registerOutboundBuildReplyKey(key, tag);
  const inner: I2npMessage = { type: 26, id: 555, expiration: Math.floor((Date.now() + 30_000) / 1000) * 1000, payload: Buffer.from([1, 2, 3]) };
  const garlic = wrapEciesExistingSessionGarlicMessage(inner, key, tag);
  const [frame] = buildTunnelMessageFragments(garlic, { type: 'local' });
  assert.ok(frame);
  const encrypted = processTunnelDataLayer(frame, keys.layerKey, keys.ivKey);
  const delivered = new Promise<I2npMessage>(resolve => service.once('outboundBuildReply', resolve));
  await service.handleMessage(unused.connection, {
    type: 18, id: 10, expiration: Date.now() + 30_000,
    payload: encodeTunnelDataPayload(tunnelId, encrypted),
  });
  assert.deepEqual(await delivered, inner);
  service.stop();
});

test('inbound endpoint removes layers, reassembles local messages, and honors its tunnel ID', async () => {
  const local = createRouterIdentity();
  const unused = fakeConnection(randomBytes(32));
  const service = new TransitTunnelService({ identity: local, connectPeer: async () => unused.connection });
  const keys = { layerKey: randomBytes(32), ivKey: randomBytes(32) };
  service.registerInboundEndpoint(0x44556677, [keys]);
  const message: I2npMessage = { type: 20, id: 333, expiration: Date.now() + 60_000, payload: Buffer.from('arrived') };
  const [frame] = buildTunnelMessageFragments(message, { type: 'local' });
  assert.ok(frame);
  const encrypted = processTunnelDataLayer(frame, keys.layerKey, keys.ivKey);
  const delivered = new Promise<I2npMessage>(resolve => service.once('localMessage', resolve));
  await service.handleMessage(unused.connection, {
    type: 18, id: 9, expiration: Date.now() + 60_000,
    payload: encodeTunnelDataPayload(0x44556677, encrypted),
  });
  assert.deepEqual(await delivered, message);
  assert.equal(service.removeInboundEndpoint(0x44556677), true);
  assert.equal(service.activeTunnels, 0);
  service.stop();
});
