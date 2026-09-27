import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { encodeDeliveryStatus, parseDeliveryStatus, createDeliveryStatusMessage, I2NP_DELIVERY_STATUS } from '../src/router/protocol/delivery-status.ts';
import { TunnelTester } from '../src/router/tunnel/test.ts';
import { PeerProfiler } from '../src/router/peer-profile.ts';
import { TokenBucket } from '../src/router/util/rate-limit.ts';
import { JUMP_SERVICES, parseAddressHelper, extractHelperDestination, destinationBytesFromHelper } from '../src/router/http-helper.ts';
import { encryptLeaseSet2, parseEncryptedLeaseSet, decryptEncryptedLeaseSet, verifyEncryptedLeaseSet } from '../src/router/protocol/encrypted-leaseset.ts';
import { encodeDatabaseStoreEncryptedLeaseSet, parseDatabaseStore } from '../src/router/netdb/database-store.ts';
import { createDestinationKeys, encodeDestinationBase64 } from '../src/router/protocol/destination.ts';
import { createLeaseSet2 } from '../src/router/protocol/leaseset.ts';
import {
  encodeSsu2LongHeader, decodeSsu2LongHeader, protectSsu2Header, unprotectSsu2Header, SSU2_SESSION_REQUEST,
} from '../src/router/transport/ssu2/header.ts';
import {
  createI2cpServer, encodeI2cpMessage, decodeI2cpMessage, I2CP_PROTOCOL_BYTE, I2CP_GET_DATE, I2CP_SET_DATE,
  I2CP_HOST_LOOKUP, I2CP_HOST_REPLY, I2CP_CREATE_SESSION, I2CP_SESSION_STATUS, I2CP_SESSION_CREATED,
  I2CP_GET_BANDWIDTH_LIMITS, I2CP_BANDWIDTH_LIMITS, parseHostLookup,
} from '../src/router/i2cp.ts';
import { createI2pControlServer } from '../src/router/i2pcontrol.ts';
import { HostsBook } from '../src/router/netdb/hosts.ts';
import { encodeString, encodeDate } from '../src/router/protocol/common.ts';

test('DeliveryStatus payload is 12 bytes and round-trips', () => {
  const encoded = encodeDeliveryStatus({ messageId: 0x89abcdef, timestamp: 1_700_000_000_000 });
  assert.equal(encoded.length, 12);
  const parsed = parseDeliveryStatus(encoded);
  assert.equal(parsed.messageId, 0x89abcdef);
  assert.equal(parsed.timestamp, 1_700_000_000_000);
  const message = createDeliveryStatusMessage(parsed);
  assert.equal(message.type, I2NP_DELIVERY_STATUS);
});

test('tunnel tester correlates DeliveryStatus echoes and times out', async () => {
  const tester = new TunnelTester();
  const message = tester.create(7, Date.now());
  const pending = tester.wait(7, 200);
  assert.equal(tester.handle(message), true);
  const result = await pending;
  assert.equal(result.messageId, 7);
  assert.ok(result.rttMs >= 0);
  const late = tester.wait(8, 20);
  await assert.rejects(late, /timed out/);
  tester.stop();
});

test('peer profiler ranks successes above consecutive failures', () => {
  const profiler = new PeerProfiler();
  const good = randomBytes(32);
  const bad = randomBytes(32);
  profiler.recordSuccess(good, 40);
  profiler.recordFailure(bad);
  profiler.recordFailure(bad);
  profiler.recordFailure(bad);
  assert.ok(profiler.score(good) > profiler.score(bad));
  assert.equal(profiler.isUnusable(bad), true);
  assert.equal(profiler.isUnusable(good), false);
  assert.ok(profiler.rank([bad, good])[0]!.equals(good));
});

test('token bucket admits burst then denies until refill', async () => {
  const bucket = new TokenBucket(1_000_000, 100);
  assert.equal(bucket.tryTake(80), true);
  assert.equal(bucket.tryTake(40), false);
  await bucket.take(10);
  bucket.stop();
  const unlimited = new TokenBucket(0);
  assert.equal(unlimited.tryTake(1_000_000), true);
});

test('addresshelper is stripped from proxy URLs and recovered from jump Location headers', () => {
  const keys = createDestinationKeys();
  const helper = encodeDestinationBase64(keys.destination);
  const url = new URL(`http://example.i2p/foo?x=1&i2paddresshelper=${helper}`);
  const parsed = parseAddressHelper(url);
  assert.equal(parsed.helper, helper);
  assert.equal(parsed.clean.searchParams.has('i2paddresshelper'), false);
  assert.equal(parsed.clean.searchParams.get('x'), '1');
  assert.ok(destinationBytesFromHelper(helper).equals(keys.destination));
  const extracted = extractHelperDestination(`http://example.i2p/?i2paddresshelper=${helper}`);
  assert.equal(extracted, helper);
  assert.equal(JUMP_SERVICES[0]!.pathFor('example.i2p'), '/jump/example.i2p');
});

test('EncryptedLeaseSet wraps a LeaseSet2 and DatabaseStore type 5 round-trips', () => {
  const keys = createDestinationKeys();
  const inner = createLeaseSet2(keys, [{
    gatewayHash: randomBytes(32), tunnelId: 9, expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
  }]);
  const secret = Buffer.from('els2-secret');
  const encoded = encryptLeaseSet2(inner, keys, secret);
  const record = parseEncryptedLeaseSet(encoded);
  assert.equal(verifyEncryptedLeaseSet(record), true);
  assert.ok(decryptEncryptedLeaseSet(record, secret).equals(inner));
  const store = encodeDatabaseStoreEncryptedLeaseSet(encoded);
  const parsed = parseDatabaseStore(store);
  assert.equal(parsed.kind, 'encryptedLeaseSet');
});

test('SSU2 long-header protection round-trips SessionRequest packets', () => {
  const header = encodeSsu2LongHeader({
    destConnId: randomBytes(8), packetNumber: 99, type: SSU2_SESSION_REQUEST, version: 2, netId: 2, flag: 0,
    srcConnId: randomBytes(8), token: randomBytes(8),
  });
  const packet = Buffer.concat([header, randomBytes(32), randomBytes(8), randomBytes(16)]);
  const k1 = randomBytes(32);
  const k2 = randomBytes(32);
  const protectedPacket = protectSsu2Header(packet, k1, k2, 'session-request');
  assert.equal(protectedPacket.subarray(0, 32).equals(packet.subarray(0, 32)), false);
  const clear = unprotectSsu2Header(protectedPacket, k1, k2, 'session-request');
  assert.ok(clear.equals(packet));
  assert.equal(decodeSsu2LongHeader(clear).type, SSU2_SESSION_REQUEST);
  assert.equal(decodeSsu2LongHeader(clear).version, 2);
});

test('I2CP GetDate, HostLookup, CreateSession, and bandwidth limits', async () => {
  const local = createDestinationKeys();
  const router = {
    hosts: new HostsBook(),
    destinations: { local },
    status: () => ({ running: true, peers: 0, netDb: 0, inboundTunnels: 0, outboundTunnels: 0 }),
  };
  const server = createI2cpServer(router, { host: '127.0.0.1', port: 0 });
  const addr = await server.listen();
  const socket = net.connect(addr.port, '127.0.0.1');
  try {
    socket.write(Buffer.from([I2CP_PROTOCOL_BYTE]));
    socket.write(encodeI2cpMessage(I2CP_GET_DATE, encodeString('0.9.64')));
    const setDate = await readI2cp(socket);
    assert.equal(setDate.type, I2CP_SET_DATE);
    const lookupHeader = Buffer.alloc(11);
    lookupHeader.writeUInt16BE(0xffff, 0);
    lookupHeader.writeUInt32BE(1, 2);
    lookupHeader.writeUInt32BE(5_000, 6);
    lookupHeader[10] = 1;
    const lookupBody = Buffer.concat([lookupHeader, encodeString('notbob.i2p')]);
    assert.equal(parseHostLookup(lookupBody).hostname, 'notbob.i2p');
    socket.write(encodeI2cpMessage(I2CP_HOST_LOOKUP, lookupBody));
    const reply = await readI2cp(socket);
    assert.equal(reply.type, I2CP_HOST_REPLY);
    assert.equal(reply.body[6], 0);
    const config = Buffer.concat([local.destination, Buffer.alloc(2), encodeDate(Date.now()), Buffer.alloc(64)]);
    socket.write(encodeI2cpMessage(I2CP_CREATE_SESSION, config));
    const status = await readI2cp(socket);
    assert.equal(status.type, I2CP_SESSION_STATUS);
    assert.equal(status.body[2], I2CP_SESSION_CREATED);
    socket.write(encodeI2cpMessage(I2CP_GET_BANDWIDTH_LIMITS));
    const limits = await readI2cp(socket);
    assert.equal(limits.type, I2CP_BANDWIDTH_LIMITS);
    assert.equal(limits.body.length, 40);
  } finally {
    socket.destroy();
    await server.close();
  }
});

test('I2PControl Authenticate and RouterInfo JSON-RPC', async () => {
  const router = {
    identity: { identityHash: randomBytes(32) },
    status: () => ({ running: true, peers: 3, netDb: 10, inboundTunnels: 1, outboundTunnels: 1 }),
  };
  const server = createI2pControlServer(router, { host: '127.0.0.1', port: 0, password: 'itoopie' });
  await server.listen();
  const addr = server.server.address();
  assert.ok(addr && typeof addr === 'object');
  try {
    const auth = await jsonRpc(addr.port, { id: 1, method: 'Authenticate', params: { API: 1, Password: 'itoopie' } });
    assert.equal(auth.result.API, 1);
    assert.equal(typeof auth.result.Token, 'string');
    const info = await jsonRpc(addr.port, {
      id: 2, method: 'RouterInfo', params: { Token: auth.result.Token, 'i2p.router.status': '' },
    });
    assert.equal(info.result['i2p.router.status'], 'OK');
  } finally {
    await server.close();
  }
});

function readI2cp(socket: net.Socket): Promise<{ type: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const decoded = decodeI2cpMessage(buffer);
        if (!decoded) return;
        cleanup();
        if (decoded.rest.length) socket.unshift(decoded.rest);
        resolve(decoded.message);
      } catch (error) { cleanup(); reject(error); }
    };
    const onError = (error: Error): void => { cleanup(); reject(error); };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

function jsonRpc(port: number, body: object): Promise<{ result: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port, method: 'POST', path: '/', headers: { 'content-type': 'application/json' },
    }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(chunk as Buffer));
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { result: Record<string, unknown> }); }
        catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.end(JSON.stringify(body));
  });
}
