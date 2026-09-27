import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DestinationSessionManager } from '../src/router/destination-session.ts';
import { parseTunnelsConf } from '../src/router/tunnels-conf.ts';
import { createAckPacket, createDataPacket, parseStreamingPacket, STREAM_MAX_PACKET_SIZE } from '../src/router/streaming.ts';

test('tunnels.conf parses client and server sections', () => {
  const tunnels = parseTunnelsConf(`
[smtp]
type = client
address = 127.0.0.1
port = 7659
destination = smtp.postman.i2p

[http]
type = http
host = 127.0.0.1
port = 8080
`);
  assert.equal(tunnels.length, 2);
  assert.equal(tunnels[0]?.type, 'client');
  assert.equal(tunnels[0]?.destination, 'smtp.postman.i2p');
  assert.equal(tunnels[1]?.type, 'http');
  assert.equal(tunnels[1]?.port, 8080);
});

test('streaming ACK packets encode empty payloads and data packets stay bounded', () => {
  const ack = parseStreamingPacket(createAckPacket(1, 2, 3, 4, [6]));
  assert.equal(ack.ackThrough, 4);
  assert.deepEqual(ack.nacks, [6]);
  assert.equal(ack.payload.length, 0);
  const data = createDataPacket(1, 2, 1, 0, Buffer.alloc(STREAM_MAX_PACKET_SIZE));
  assert.ok(data.length > STREAM_MAX_PACKET_SIZE);
});

test('destination streams reassemble out-of-order packets and honor ACKs', async () => {
  let alice!: DestinationSessionManager;
  const bob = new DestinationSessionManager({
    sendGarlic: async message => { alice.handleGarlic(message); },
  });
  alice = new DestinationSessionManager({
    sendGarlic: async message => { bob.handleGarlic(message); },
  });
  alice.createLeaseSet([{ gatewayHash: randomBytes(32), tunnelId: 3, expiresAtSeconds: Math.floor(Date.now() / 1000) + 600 }]);
  const received: Buffer[] = [];
  bob.on('inboundStream', (stream, nsr) => {
    stream.on('data', (payload: Buffer) => received.push(payload));
    alice.handleGarlic(nsr);
  });
  const stream = await alice.connect({
    gatewayHash: randomBytes(32), tunnelId: 4,
    encryptionPublicKey: bob.local.encryptionPublicKey,
    destination: bob.local.destination, destinationHash: bob.local.destinationHash,
  });
  await stream.write(Buffer.from('one'));
  await stream.write(Buffer.from('two'));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.deepEqual(Buffer.concat(received).toString(), 'onetwo');
  await stream.close();
});
