import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Ntcp2Connection } from '../src/router/transport/ntcp2/connection.ts';
import { Ntcp2DataCipher } from '../src/router/transport/ntcp2/data-cipher.ts';
import type { SipHashKeys } from '../src/router/transport/ntcp2/siphash.ts';

const lengthKeys = (n: number): SipHashKeys => ({ key1: Buffer.alloc(8, n), key2: Buffer.alloc(8, n + 1), iv: Buffer.alloc(8, n + 2) });
function onceMessage(connection: Ntcp2Connection): Promise<unknown> {
  return new Promise((resolve, reject) => { connection.once('i2np', resolve); connection.once('protocolError', reject); connection.once('transportError', reject); });
}

test('established NTCP2 connections exchange I2NP messages over TCP', async () => {
  const keyAB = Buffer.alloc(32, 0x31); const keyBA = Buffer.alloc(32, 0x42);
  const listener = net.createServer(socket => {
    const cipher = new Ntcp2DataCipher(keyBA, keyAB, lengthKeys(4), lengthKeys(1));
    const connection = new Ntcp2Connection(socket, cipher);
    listener.emit('peer', connection);
  });
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const address = listener.address(); assert(address && typeof address !== 'string');
  try {
    const peerPromise = new Promise<Ntcp2Connection>(resolve => listener.once('peer', resolve));
    const socket = net.createConnection({ host: '127.0.0.1', port: address.port });
    await new Promise<void>(resolve => socket.once('connect', resolve));
    const alice = new Ntcp2Connection(socket, new Ntcp2DataCipher(keyAB, keyBA, lengthKeys(1), lengthKeys(4)));
    const bob = await peerPromise;
    const bobMessage = onceMessage(bob);
    await alice.sendI2np({ type: 20, id: 99, expiration: 1_800_000_000_000, payload: Buffer.from('over the stream') });
    assert.deepEqual(await bobMessage, { type: 20, id: 99, expiration: 1_800_000_000_000, payload: Buffer.from('over the stream') });
    const aliceMessage = onceMessage(alice);
    await bob.sendI2np({ type: 10, id: 100, expiration: 1_800_000_001_000, payload: Buffer.from('response') });
    assert.deepEqual(await aliceMessage, { type: 10, id: 100, expiration: 1_800_000_001_000, payload: Buffer.from('response') });
    alice.close(); bob.close();
  } finally { await new Promise<void>(resolve => listener.close(() => resolve())); }
});
