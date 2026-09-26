import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { preprocessOutboundTunnelMessage, processTunnelDataLayer, removeTunnelDataLayer, TUNNEL_MESSAGE_SIZE } from '../src/router/tunnel/data.ts';

test('AES tunnel participant applies a reversible IV-and-data layer', () => {
  const original = randomBytes(TUNNEL_MESSAGE_SIZE);
  const layerKey = randomBytes(32);
  const ivKey = randomBytes(32);
  const processed = processTunnelDataLayer(original, layerKey, ivKey);
  assert.equal(processed.length, TUNNEL_MESSAGE_SIZE);
  assert.notDeepEqual(processed, original);
  assert.deepEqual(removeTunnelDataLayer(processed, layerKey, ivKey), original);
});

test('tunnel layers compose and peel in reverse order', () => {
  const original = randomBytes(TUNNEL_MESSAGE_SIZE);
  const first = { layer: randomBytes(32), iv: randomBytes(32) };
  const second = { layer: randomBytes(32), iv: randomBytes(32) };
  const twice = processTunnelDataLayer(processTunnelDataLayer(original, first.layer, first.iv), second.layer, second.iv);
  const peeled = removeTunnelDataLayer(removeTunnelDataLayer(twice, second.layer, second.iv), first.layer, first.iv);
  assert.deepEqual(peeled, original);
});

test('outbound gateway pre-decrypts layers in reverse so participants reveal the original payload', () => {
  const original = randomBytes(TUNNEL_MESSAGE_SIZE);
  const keys = Array.from({ length: 3 }, () => ({ layerKey: randomBytes(32), ivKey: randomBytes(32) }));
  const atGateway = preprocessOutboundTunnelMessage(original, keys);
  let atEndpoint: Buffer<ArrayBufferLike> = Buffer.from(atGateway);
  for (const pair of keys) {
    const next = processTunnelDataLayer(atEndpoint, pair.layerKey, pair.ivKey);
    atEndpoint.fill(0); atEndpoint = next;
  }
  assert.deepEqual(atEndpoint, original);
  atGateway.fill(0); atEndpoint.fill(0);
});

test('AES tunnel layer rejects malformed sizes and keys', () => {
  assert.throws(() => processTunnelDataLayer(Buffer.alloc(1023), Buffer.alloc(32), Buffer.alloc(32)), /1024/);
  assert.throws(() => processTunnelDataLayer(Buffer.alloc(1024), Buffer.alloc(31), Buffer.alloc(32)), /32-byte/);
  assert.throws(() => removeTunnelDataLayer(Buffer.alloc(1024), Buffer.alloc(32), Buffer.alloc(33)), /32-byte/);
});
