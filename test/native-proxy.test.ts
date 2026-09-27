import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { EventEmitter } from 'node:events';
import type net from 'node:net';
import { createNativeHttpProxy } from '../src/router/native-proxy.ts';
import type { NativeRouterNode } from '../src/router/node.ts';

/** Minimal stand-in for DestinationStream: answers one HTTP request with a fixed hosts.txt body. */
class FakeStream extends EventEmitter {
  request = '';
  async write(payload: Buffer): Promise<void> {
    this.request += payload.toString('latin1');
    if (!this.request.includes('\r\n\r\n')) return;
    const body = 'mininet.i2p=abc\n';
    setImmediate(() => {
      this.emit('data', Buffer.from(`HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`));
      this.emit('close');
    });
  }
  async close(): Promise<void> { this.emit('close'); }
}

test('native HTTP proxy fetches .i2p URLs over the destination stream without DNS', async () => {
  const streams: FakeStream[] = [];
  const connected: string[] = [];
  const node = {
    connectDestination: async (hostname: string) => {
      connected.push(hostname);
      const stream = new FakeStream(); streams.push(stream);
      return { stream };
    },
    addAddressHelper: async () => undefined,
  } as unknown as NativeRouterNode;
  const proxy = createNativeHttpProxy({ node, host: '127.0.0.1', port: 0 });
  await proxy.listen();
  const port = (proxy.server.address() as net.AddressInfo).port;
  try {
    const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port, method: 'GET', path: 'http://notbob.i2p/hosts.txt', headers: { host: 'notbob.i2p' } }, response => {
        let body = ''; response.setEncoding('utf8');
        response.on('data', chunk => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode ?? 0, body }));
      });
      request.on('error', reject); request.end();
    });
    assert.equal(result.status, 200, result.body);
    assert.equal(result.body, 'mininet.i2p=abc\n');
    assert.deepEqual(connected, ['notbob.i2p']);
    assert.match(streams[0]!.request, /^GET \/hosts\.txt HTTP\/1\.1\r\n/);
    assert.match(streams[0]!.request, /\r\nhost: notbob\.i2p\r\n/i);
  } finally { await proxy.close(); }
});
