import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRouterIdentity } from '../src/router/identity.ts';
import type { I2npMessage } from '../src/router/protocol/i2np.ts';
import type { Ntcp2Connection } from '../src/router/transport/ntcp2/connection.ts';
import { buildTunnelMessageFragments } from '../src/router/tunnel/fragments.ts';
import { wrapEciesExistingSessionGarlicMessage } from '../src/router/tunnel/garlic.ts';
import { decodeTunnelGatewayPayload, encodeTunnelDataPayload } from '../src/router/tunnel/messages.ts';
import { preprocessOutboundTunnelMessage, processTunnelDataLayer } from '../src/router/tunnel/data.ts';
import {
  decryptShortBuildRequestRecord, encodeShortBuildReplyPlaintext, encodeShortTunnelBuildPayload,
  encryptShortTunnelBuildReply, parseShortTunnelBuildPayload,
} from '../src/router/tunnel/short-build.ts';
import { TransitTunnelService } from '../src/router/tunnel/transit.ts';
import { ShortTunnelBuildCreator } from '../src/router/tunnel/builder.ts';

function routedConnection(identityHash: Buffer, onSend?: (message: I2npMessage) => Promise<void>) {
  const sent: I2npMessage[] = [];
  const connection = {
    remoteIdentityHash: Buffer.from(identityHash), isClosed: false,
    sendI2np: async (message: I2npMessage) => {
      sent.push({ ...message, payload: Buffer.from(message.payload) });
      await onSend?.(message);
    },
  } as unknown as Ntcp2Connection;
  return { connection, sent };
}

test('short tunnel creator enforces a concurrent build limit and releases its slot on timeout', async () => {
  const creatorIdentity = createRouterIdentity(); const hop = createRouterIdentity(); const reply = createRouterIdentity();
  const transit = new TransitTunnelService({ identity: creatorIdentity, connectPeer: async () => { throw new Error('unexpected transit connection'); } });
  let notifyStarted!: () => void; const started = new Promise<void>(resolve => { notifyStarted = resolve; });
  let releaseSend!: () => void; const heldSend = new Promise<void>(resolve => { releaseSend = resolve; });
  const peer = routedConnection(hop.identityHash, async () => { notifyStarted(); await heldSend; });
  const builder = new ShortTunnelBuildCreator({
    identity: creatorIdentity, transitTunnels: transit,
    connectPeer: async () => peer.connection, replyTimeoutMs: 1_000, maxConcurrentBuilds: 1,
  });
  const path = [{ identityHash: hop.identityHash, encryptionPublicKey: hop.identity.subarray(0, 32) }];
  const replyTunnel = { gatewayIdentityHash: reply.identityHash, tunnelId: 811 };
  const first = builder.buildOutbound(path, replyTunnel);
  await started;
  await assert.rejects(builder.buildOutbound(path, replyTunnel), /Concurrent tunnel build limit/);
  releaseSend();
  await assert.rejects(first, /build reply timed out/);
  await assert.rejects(builder.buildOutbound([], replyTunnel), /path must contain/);
  transit.stop();
});

test('short tunnel creator sends a direct build and accepts only its authenticated garlic-wrapped reply', async () => {
  const creatorIdentity = createRouterIdentity(); const endpointIdentity = createRouterIdentity();
  const replyGateway = createRouterIdentity(); const inboundReplyKeys = { layerKey: randomBytes(32), ivKey: randomBytes(32) };
  const transit = new TransitTunnelService({ identity: creatorIdentity, connectPeer: async () => { throw new Error('unexpected peer connection'); } });
  transit.registerInboundEndpoint(444, [inboundReplyKeys]);
  const sent: I2npMessage[] = [];
  const endpointConnection = {
    remoteIdentityHash: endpointIdentity.identityHash, isClosed: false,
    sendI2np: async (message: I2npMessage) => {
      sent.push({ ...message, payload: Buffer.from(message.payload) });
      assert.equal(message.type, 25);
      const requestRecords = parseShortTunnelBuildPayload(message.payload);
      assert.equal(requestRecords.length, 4);
      const requestIndex = requestRecords.findIndex(record => record.subarray(0, 16).equals(endpointIdentity.identityHash.subarray(0, 16)));
      assert.notEqual(requestIndex, -1);
      const decoded = decryptShortBuildRequestRecord(
        requestRecords[requestIndex]!, endpointIdentity.identityHash,
        endpointIdentity.encryptionPrivateKey, endpointIdentity.identity.subarray(0, 32),
      );
      assert.equal(decoded.flags, 0x40);
      assert.equal(decoded.nextIdentityHash.toString('hex'), replyGateway.identityHash.toString('hex'));
      assert.equal(decoded.nextTunnelId, 445);
      const replyRecords = encryptShortTunnelBuildReply(
        requestRecords, requestIndex, encodeShortBuildReplyPlaintext(0), decoded.replyKey, decoded.handshakeHash,
      );
      const buildReply: I2npMessage = {
        type: 26, id: decoded.nextMessageId, expiration: Date.now() + 30_000,
        payload: encodeShortTunnelBuildPayload(replyRecords),
      };
      const garlic = wrapEciesExistingSessionGarlicMessage(buildReply, decoded.garlicReplyKey!, decoded.garlicReplyTag!);
      const [frame] = buildTunnelMessageFragments(garlic, { type: 'local' });
      assert.ok(frame);
      const layered = processTunnelDataLayer(frame, inboundReplyKeys.layerKey, inboundReplyKeys.ivKey);
      await transit.handleMessage(endpointConnection, {
        type: 18, id: 901, expiration: Date.now() + 30_000,
        payload: encodeTunnelDataPayload(444, layered),
      });
      decoded.replyKey.fill(0); decoded.handshakeHash.fill(0); decoded.layerKey.fill(0); decoded.ivKey.fill(0);
      decoded.garlicReplyKey?.fill(0); decoded.garlicReplyTag?.fill(0);
      layered.fill(0); frame.fill(0);
    },
  } as unknown as Ntcp2Connection;
  const builder = new ShortTunnelBuildCreator({
    identity: creatorIdentity, transitTunnels: transit,
    connectPeer: async hash => {
      assert.deepEqual(hash, endpointIdentity.identityHash);
      return endpointConnection;
    },
    replyTimeoutMs: 3_000, tunnelId: () => 1001, messageId: (() => { let id = 2000; return () => id++; })(),
  });
  const tunnel = await builder.buildOutbound([{
    identityHash: endpointIdentity.identityHash,
    encryptionPublicKey: endpointIdentity.identity.subarray(0, 32),
  }], { gatewayIdentityHash: replyGateway.identityHash, tunnelId: 445 });
  assert.equal(sent.length, 1);
  assert.equal(tunnel.gatewayIdentityHash.toString('hex'), endpointIdentity.identityHash.toString('hex'));
  assert.equal(tunnel.gatewayTunnelId, 1001);
  assert.equal(tunnel.hops.length, 1);
  assert.equal(tunnel.hops[0]!.receiveTunnelId, 1001);
  assert.equal(tunnel.hops[0]!.layerKey.length, 32);
  assert.ok(tunnel.expiresAt > Date.now());
  transit.stop();
});

test('short outbound build and outbound data traverse a three-router simulated path', async () => {
  const creatorIdentity = createRouterIdentity();
  const hops = [createRouterIdentity(), createRouterIdentity(), createRouterIdentity()];
  const replyRouters = [createRouterIdentity(), createRouterIdentity(), createRouterIdentity()];
  const replyTunnelId = 0x404;
  const replyKeys = replyRouters.map(() => ({ layerKey: randomBytes(32), ivKey: randomBytes(32) }));
  const creatorTransit = new TransitTunnelService({ identity: creatorIdentity, connectPeer: async () => { throw new Error('unexpected creator peer connection'); } });
  creatorTransit.registerInboundEndpoint(replyTunnelId, replyKeys);
  const services: TransitTunnelService[] = [];
  const inbound = hops.map((_, index) => routedConnection(index === 0 ? creatorIdentity.identityHash : hops[index - 1]!.identityHash));
  const replyGateway = routedConnection(replyRouters[0]!.identityHash, async message => {
    assert.equal(message.type, 19);
    const gateway = decodeTunnelGatewayPayload(message.payload);
    assert.equal(gateway.tunnelId, replyTunnelId);
    let frame = buildTunnelMessageFragments(gateway.message, { type: 'local' })[0]!;
    for (const keys of replyKeys) {
      const next = processTunnelDataLayer(frame, keys.layerKey, keys.ivKey);
      frame.fill(0); frame = next;
    }
    await creatorTransit.handleMessage(replyGateway.connection, {
      type: 18, id: 100, expiration: gateway.message.expiration,
      payload: encodeTunnelDataPayload(replyTunnelId, frame),
    });
    frame.fill(0);
  });
  const outboundConnections: ReturnType<typeof routedConnection>[] = [];
  for (let index = 0; index < hops.length; index++) {
    const downstream = index < hops.length - 1 ? hops[index + 1]! : undefined;
    let downstreamConnection: ReturnType<typeof routedConnection> | undefined;
    const current = routedConnection(downstream?.identityHash ?? replyRouters[0]!.identityHash, async message => {
      const nextHopIndex = index + 1;
      if (nextHopIndex < hops.length) await services[nextHopIndex]!.handleMessage(inbound[nextHopIndex]!.connection, message);
      else await replyGateway.connection.sendI2np(message);
    });
    downstreamConnection = current;
    outboundConnections.push(downstreamConnection);
    services[index] = new TransitTunnelService({
      identity: hops[index]!,
      connectPeer: async identityHash => {
        assert.deepEqual(identityHash, downstream?.identityHash ?? replyRouters[0]!.identityHash);
        return current.connection;
      },
    });
  }
  const firstHopConnection = routedConnection(hops[0]!.identityHash, async message => {
    await services[0]!.handleMessage(inbound[0]!.connection, message);
  });
  const builder = new ShortTunnelBuildCreator({
    identity: creatorIdentity, transitTunnels: creatorTransit,
    connectPeer: async hash => { assert.deepEqual(hash, hops[0]!.identityHash); return firstHopConnection.connection; },
    replyTimeoutMs: 3_000,
    tunnelId: (() => { let id = 500; return () => id++; })(),
    messageId: (() => { let id = 600; return () => id++; })(),
  });
  const tunnel = await builder.buildOutbound(hops.map(hop => ({
    identityHash: hop.identityHash, encryptionPublicKey: hop.identity.subarray(0, 32),
  })), { gatewayIdentityHash: replyRouters[0]!.identityHash, tunnelId: replyTunnelId });
  assert.equal(tunnel.hops.length, 3);
  const appMessage: I2npMessage = { type: 20, id: 707, expiration: Date.now() + 30_000, payload: Buffer.from('through built outbound tunnel') };
  const [plainFrame] = buildTunnelMessageFragments(appMessage, { type: 'local' });
  assert.ok(plainFrame);
  const gatewayFrame = preprocessOutboundTunnelMessage(plainFrame, tunnel.hops.map(({ layerKey, ivKey }) => ({ layerKey, ivKey })));
  const delivered = new Promise<I2npMessage>(resolve => services[2]!.once('localMessage', resolve));
  await services[0]!.handleMessage(inbound[0]!.connection, {
    type: 18, id: 708, expiration: appMessage.expiration,
    payload: encodeTunnelDataPayload(tunnel.gatewayTunnelId, gatewayFrame),
  });
  assert.deepEqual(await delivered, appMessage);
  plainFrame.fill(0); gatewayFrame.fill(0);
  for (const service of services) service.stop();
  creatorTransit.stop();
});
