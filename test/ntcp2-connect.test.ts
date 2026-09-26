import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createRouterIdentity } from '../src/router/identity.ts';
import { createRouterInfoRecord, parseRouterInfo, type RouterAddress } from '../src/router/protocol/router-info.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { NativeRouterNode } from '../src/router/node.ts';
import { Ntcp2Connection } from '../src/router/transport/ntcp2/connection.ts';

function b64(value: Buffer): string { return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~'); }
function address(cost: number, transport: string, options: Map<string, string>): RouterAddress { return { cost, expiration: 0, transport, options }; }
async function nextI2np(connection: Ntcp2Connection, type: number): Promise<unknown> {
  return new Promise(resolve => {
    const handler = (message: { type: number }) => { if (message.type === type) { connection.removeListener('i2np', handler); resolve(message); } };
    connection.on('i2np', handler);
  });
}
async function within<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); })]);
  } finally { if (timer) clearTimeout(timer); }
}
async function reservePort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((resolve, reject) => { probe.once('error', reject); probe.listen(0, '127.0.0.1', resolve); });
  const address = probe.address(); assert(address && typeof address !== 'string');
  await new Promise<void>(resolve => probe.close(() => resolve()));
  return address.port;
}

test('native nodes connect, exchange I2NP, and serve direct netDb lookups', async () => {
  const bobIdentity = createRouterIdentity(); const aliceIdentity = createRouterIdentity();
  const bobIv = Buffer.alloc(16, 0x5a); const aliceIv = Buffer.alloc(16, 0x33);
  const bobPort = await reservePort(); const alicePort = await reservePort();
  const bobAddress = address(1, 'NTCP2', new Map([
    ['host', '127.0.0.1'], ['i', b64(bobIv)], ['port', String(bobPort)], ['s', b64(bobIdentity.identity.subarray(0, 32))], ['v', '2'],
  ]));
  const bobInfoBytes = createRouterInfoRecord(bobIdentity, Date.now(), [bobAddress], new Map([['netId', '2'], ['router.version', 'test']]));
  const aliceAddress = address(1, 'NTCP2', new Map([
    ['host', '127.0.0.1'], ['i', b64(aliceIv)], ['port', String(alicePort)], ['s', b64(aliceIdentity.identity.subarray(0, 32))], ['v', '2'],
  ]));
  const aliceInfoBytes = createRouterInfoRecord(aliceIdentity, Date.now(), [aliceAddress], new Map([['netId', '2'], ['router.version', 'test']]));

  const aliceStore = new VerifiedRouterInfoStore(); const bobStore = new VerifiedRouterInfoStore();
  aliceStore.store(parseRouterInfo(bobInfoBytes));
  const thirdIdentity = createRouterIdentity();
  const thirdInfo = createRouterInfoRecord(thirdIdentity, Date.now(), [], new Map([['netId', '2']]));
  bobStore.store(parseRouterInfo(thirdInfo));
  const bobNode = new NativeRouterNode({ identity: bobIdentity, routerInfo: bobInfoBytes, netDb: bobStore, host: '127.0.0.1', port: bobPort, publishedIv: bobIv, timeoutMs: 5000, autoBootstrap: false });
  const aliceNode = new NativeRouterNode({ identity: aliceIdentity, routerInfo: aliceInfoBytes, netDb: aliceStore, host: '127.0.0.1', port: alicePort, publishedIv: aliceIv, timeoutMs: 5000, autoBootstrap: false });
  let aliceConnection: Ntcp2Connection | undefined; let bobConnection: Ntcp2Connection | undefined;
  try {
    await bobNode.start(); await aliceNode.start();
    assert.deepEqual(aliceNode.selectOutboundTunnelPath(1), [bobIdentity.identityHash]);
    assert.throws(() => aliceNode.selectOutboundTunnelPath(1, [bobIdentity.identityHash]), /Only 0 eligible NTCP2 routers/);
    const learnedAlice = new Promise<unknown>(resolve => bobNode.once('routerInfo', resolve));
    const bobPeer = new Promise<Ntcp2Connection>(resolve => bobNode.once('peer', (_hash, connection) => resolve(connection as Ntcp2Connection)));
    const alicePeer = new Promise<Ntcp2Connection>(resolve => aliceNode.once('peer', (_hash, connection) => resolve(connection as Ntcp2Connection)));
    const learnedThird = new Promise<unknown>(resolve => {
      const handler = (info: { identityHash: Buffer }) => {
        if (!info.identityHash.equals(thirdIdentity.identityHash)) return;
        aliceNode.removeListener('routerInfo', handler); resolve(info);
      };
      aliceNode.on('routerInfo', handler);
    });
    assert.equal(await aliceNode.bootstrap(), 1);
    aliceConnection = await within(alicePeer, 5000, 'Alice bootstrap did not connect to a seed peer');
    bobConnection = await within(bobPeer, 5000, 'Bob did not accept Alice');
    assert.equal(aliceNode.activeOutboundConnections, 1); assert.equal(bobNode.listener.activeConnections, 1);
    assert.deepEqual(aliceConnection.remoteIdentityHash, bobIdentity.identityHash);
    assert.deepEqual(bobConnection.remoteIdentityHash, aliceIdentity.identityHash);
    await within(learnedAlice, 3000, 'Bob did not learn Alice RouterInfo from direct announcement');
    await within(learnedThird, 3000, 'Alice did not discover a peer from the DatabaseSearchReply');
    assert.ok(bobStore.get(aliceIdentity.identityHash));
    assert.ok(aliceStore.get(thirdIdentity.identityHash));

    const receivedByAlice = nextI2np(aliceConnection, 20);
    await bobConnection.sendI2np({ type: 20, id: 404, expiration: Date.now() + 60_000, payload: Buffer.from('Bob to Alice') });
    const atAlice = await within(receivedByAlice, 3000, 'Alice did not receive Bob I2NP message') as { type: number; id: number; payload: Buffer };
    assert.equal(atAlice.type, 20); assert.equal(atAlice.id, 404); assert.deepEqual(atAlice.payload, Buffer.from('Bob to Alice'));

    const receivedByBob = nextI2np(bobConnection, 21);
    await aliceConnection.sendI2np({ type: 21, id: 405, expiration: Date.now() + 60_000, payload: Buffer.from('Alice to Bob') });
    const atBob = await within(receivedByBob, 3000, 'Bob did not receive Alice I2NP message') as { type: number; id: number; payload: Buffer };
    assert.equal(atBob.type, 21); assert.equal(atBob.id, 405); assert.deepEqual(atBob.payload, Buffer.from('Alice to Bob'));

    const learnedBob = new Promise<unknown>(resolve => aliceNode.netDbProtocol.once('routerInfo', resolve));
    await aliceNode.netDbProtocol.requestRouterInfo(aliceConnection, bobIdentity.identityHash);
    await within(learnedBob, 3000, 'Alice did not learn Bob RouterInfo through DatabaseLookup/Store');
    assert.ok(aliceStore.get(bobIdentity.identityHash));

    const unknownKey = Buffer.alloc(32, 0xa7);
    const searchReply = new Promise<unknown>(resolve => aliceNode.netDbProtocol.once('searchReply', resolve));
    await aliceNode.netDbProtocol.requestRouterInfo(aliceConnection, unknownKey);
    const search = await within(searchReply, 3000, 'Alice did not receive DatabaseSearchReply') as { key: Buffer; peers: Buffer[] };
    assert.deepEqual(search.key, unknownKey); assert.deepEqual(search.peers, [thirdIdentity.identityHash]);

    const previousPublication = parseRouterInfo(aliceNode.routerInfo).published;
    aliceNode.refreshRouterInfo();
    const refreshed = parseRouterInfo(aliceNode.routerInfo);
    assert.ok(refreshed.published >= previousPublication);
    assert.equal(refreshed.identityHash.toString('hex'), aliceIdentity.identityHash.toString('hex'));
  } finally {
    await Promise.all([aliceNode.stop(), bobNode.stop()]);
  }
});
