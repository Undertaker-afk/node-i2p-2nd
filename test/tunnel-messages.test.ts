import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeTunnelDataPayload, decodeTunnelGatewayPayload, encodeTunnelDataPayload,
  encodeTunnelGatewayPayload,
} from '../src/router/tunnel/messages.ts';

test('TunnelData payload round-trips its tunnel ID and fixed tunnel message', () => {
  const message = Buffer.alloc(1024, 0x51);
  const encoded = encodeTunnelDataPayload(0x12345678, message);
  assert.equal(encoded.length, 1028);
  assert.deepEqual(decodeTunnelDataPayload(encoded), { tunnelId: 0x12345678, message });
  assert.throws(() => decodeTunnelDataPayload(encoded.subarray(0, -1)), /1024-byte/);
  assert.throws(() => encodeTunnelDataPayload(0, message), /nonzero/);
});

test('TunnelGateway encapsulates exactly one checksummed I2NP message', () => {
  const message = { type: 20, id: 0x87654321, expiration: 1_900_000_000_000, payload: Buffer.from('through a tunnel') };
  const encoded = encodeTunnelGatewayPayload(0x01020304, message);
  assert.deepEqual(decodeTunnelGatewayPayload(encoded), { tunnelId: 0x01020304, message });
  const malformed = Buffer.from(encoded); malformed.writeUInt16BE(malformed.readUInt16BE(4) - 1, 4);
  assert.throws(() => decodeTunnelGatewayPayload(malformed), /length mismatch/);
  assert.throws(() => decodeTunnelGatewayPayload(encoded.subarray(0, 7)), /length mismatch|truncated/);
});
