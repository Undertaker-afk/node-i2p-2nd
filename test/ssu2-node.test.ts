import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { createRouterIdentity, type RouterIdentityKeys } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo, type RouterAddress } from '../src/router/protocol/router-info.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { NativeRouterNode } from '../src/router/node.ts';
import { createSsu2Address } from '../src/router/transport/ssu2/address.ts';
import type { PeerConnection } from '../src/router/transport/peer-connection.ts';

function b64(value: Buffer): string { return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~'); }

async function reserveTcp(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', () => resolve()));
  const address = probe.address() as net.AddressInfo;
  await new Promise<void>(resolve => probe.close(() => resolve()));
  return address.port;
}
async function reserveUdp(): Promise<number> {
  const socket = dgram.createSocket('udp4');
  await new Promise<void>(resolve => socket.bind(0, '127.0.0.1', () => resolve()));
  const port = socket.address().port;
  await new Promise<void>(resolve => socket.close(() => resolve()));
  return port;
}
async function within<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error(label)), ms); })]); }
  finally { if (timer) clearTimeout(timer); }
}

type TestRouter = { identity: RouterIdentityKeys; info: Buffer; tcpPort: number; udpPort: number; introKey: Buffer; iv: Buffer };

async function makeRouter(options: { ntcp2: boolean }): Promise<TestRouter> {
  const identity = createRouterIdentity(); const introKey = randomBytes(32); const iv = randomBytes(16);
  const tcpPort = await reserveTcp(); const udpPort = await reserveUdp();
  const addresses: RouterAddress[] = [];
  if (options.ntcp2) {
    addresses.push({ cost: 5, expiration: 0, transport: 'NTCP2', options: new Map([
      ['host', '127.0.0.1'], ['i', b64(iv)], ['port', String(tcpPort)], ['s', b64(identity.identity.subarray(0, 32))], ['v', '2'],
    ]) });
  }
  addresses.push(createSsu2Address({ host: '127.0.0.1', port: udpPort, staticKey: identity.identity.subarray(0, 32), introKey, caps: '4' }));
  const info = createRouterInfoRecord(identity, Date.now(), addresses, new Map([['caps', 'NR'], ['netId', '2'], ['router.version', 'test']]));
  return { identity, info, tcpPort, udpPort, introKey, iv };
}

function makeNode(router: TestRouter, store: VerifiedRouterInfoStore): NativeRouterNode {
  return new NativeRouterNode({
    identity: router.identity, routerInfo: router.info, netDb: store, host: '127.0.0.1', port: router.tcpPort, publishedIv: router.iv,
    timeoutMs: 5_000, autoBootstrap: false, ssu2: { port: router.udpPort, introKey: router.introKey, host: '127.0.0.1' },
  });
}

test('node dials SSU2-only peers, selects them for paths, and builds a 2-hop tunnel over SSU2', async () => {
  const aliceRouter = await makeRouter({ ntcp2: true });
  const bobRouter = await makeRouter({ ntcp2: false });
  const carolRouter = await makeRouter({ ntcp2: false });
  const everyone = [aliceRouter, bobRouter, carolRouter];
  const stores = everyone.map(() => new VerifiedRouterInfoStore());
  for (const store of stores) for (const router of everyone) store.store(parseRouterInfo(router.info));
  const [alice, bob, carol] = everyone.map((router, index) => makeNode(router, stores[index]!)) as [NativeRouterNode, NativeRouterNode, NativeRouterNode];
  try {
    await alice.start(); await bob.start(); await carol.start();
    assert.equal(alice.status().ssu2Listening, true);

    // SSU2-only routers are eligible hops (previously only NTCP2 s/i/v=2 were accepted).
    const path = alice.selectOutboundTunnelPath(2);
    assert.equal(path.length, 2);
    assert.ok(path.every(hash => hash.equals(bobRouter.identity.identityHash) || hash.equals(carolRouter.identity.identityHash)));

    // Direct SSU2 session + netDb exchange over SSU2.
    const bobSawAlice = new Promise<PeerConnection>(resolve => bob.once('peer', (_hash, connection) => resolve(connection as PeerConnection)));
    const connection = await within(alice.connectPeer(bobRouter.identity.identityHash), 8_000, 'SSU2 connectPeer timed out');
    assert.equal(connection.transport, 'SSU2');
    const inbound = await within(bobSawAlice, 3_000, 'Bob did not register the inbound SSU2 peer');
    assert.equal(inbound.transport, 'SSU2');
    assert.equal(alice.status().ssu2Peers, 1);
    // Bob reuses the inbound session instead of dialing back.
    assert.equal(await bob.connectPeer(aliceRouter.identity.identityHash), inbound);

    // 2-hop outbound tunnel Alice -> Bob -> Carol, reply returns to Alice's zero-hop inbound.
    const zeroHop = alice.tunnelPool.startZeroHopInbound();
    const outbound = await within(alice.buildOutboundTunnel(
      [bobRouter.identity.identityHash, carolRouter.identity.identityHash],
      { gatewayIdentityHash: aliceRouter.identity.identityHash, tunnelId: zeroHop },
    ), 15_000, 'outbound tunnel build over SSU2 timed out');
    assert.equal(outbound.hops.length, 2);

    // Inbound tunnel Carol -> Bob -> Alice, build sent through the new outbound tunnel.
    const inboundTunnel = await within(alice.buildInboundTunnel([carolRouter.identity.identityHash, bobRouter.identity.identityHash], outbound), 15_000, 'inbound tunnel build over SSU2 timed out');

    // DeliveryStatus round-trip: out through Bob/Carol, back in through Carol/Bob.
    const probe = alice.tester.create();
    const echoed = alice.tester.wait(probe.id, 8_000);
    await alice.sendThroughOutboundTunnel(outbound, probe, { type: 'tunnel', gatewayHash: inboundTunnel.gatewayIdentityHash, tunnelId: inboundTunnel.gatewayTunnelId });
    const result = await within(echoed, 10_000, 'tunnel test over SSU2 timed out');
    assert.equal(result.messageId, probe.id);
    assert.ok(bob.status().ssu2Peers + carol.status().ssu2Peers >= 1);
  } finally {
    await Promise.all([alice.stop(), bob.stop(), carol.stop()]);
  }
});

test('node without SSU2 rejects SSU2-only peers with a clear error', async () => {
  const aliceRouter = await makeRouter({ ntcp2: true });
  const bobRouter = await makeRouter({ ntcp2: false });
  const store = new VerifiedRouterInfoStore();
  store.store(parseRouterInfo(bobRouter.info));
  const alice = new NativeRouterNode({
    identity: aliceRouter.identity, routerInfo: aliceRouter.info, netDb: store, host: '127.0.0.1', port: aliceRouter.tcpPort,
    publishedIv: aliceRouter.iv, autoBootstrap: false,
  });
  try {
    await alice.start();
    assert.throws(() => alice.selectOutboundTunnelPath(1), /Only 0 eligible NTCP2 routers/);
    await assert.rejects(alice.connectPeer(bobRouter.identity.identityHash), /no dialable NTCP2 address/);
  } finally { await alice.stop(); }
});

test('tunnel hop filter rejects pre-0.9.51 and G-cap routers; routing key rotates daily', async () => {
  const { acceptsShortTunnelBuilds } = await import('../src/router/node.ts');
  const { routingKey, routingKeyDate } = await import('../src/router/netdb/routing-key.ts');
  const info = (options: [string, string][]) => ({ options: new Map(options) }) as unknown as Parameters<typeof acceptsShortTunnelBuilds>[0];
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', '0.9.64'], ['caps', 'XfR']])), true);
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', '0.9.51']])), true);
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', '2.0.0']])), true);
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', '0.9.50']])), false);
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', '0.9.64'], ['caps', 'LGR']])), false);
  assert.equal(acceptsShortTunnelBuilds(info([['router.version', 'test']])), true);
  const day = Date.UTC(2026, 8, 27, 12);
  assert.equal(routingKeyDate(day), '20260927');
  const key = Buffer.alloc(32, 7);
  const expected = (await import('node:crypto')).createHash('sha256').update(Buffer.concat([key, Buffer.from('20260927', 'ascii')])).digest();
  assert.deepEqual(routingKey(key, day), expected);
  assert.notDeepEqual(routingKey(key, day + 24 * 3600 * 1000), expected);
});
