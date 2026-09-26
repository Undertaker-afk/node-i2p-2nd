import http from 'node:http';
import type { NativeRouterNode } from './node.ts';
import { b32AddressFromHash } from './util/encoding.ts';

export function createRouterConsole(node: NativeRouterNode, options: { host?: string; port?: number } = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 7070;
  const server = http.createServer((req, res) => {
    const status = node.status();
    const b32 = b32AddressFromHash(node.destinations.local.destinationHash);
    if (req.url === '/json' || req.headers.accept?.includes('application/json')) {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ...status, b32 }, null, 2));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>node-i2p router</title>
<style>body{font-family:sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%}td{padding:.35rem .5rem;border-bottom:1px solid #ddd}
code{font-size:.9em}</style></head><body>
<h1>Native TypeScript I2P router</h1>
<p>This is a local status page, not a claim of i2pd parity. Bind remains loopback by default.</p>
<table>
<tr><td>Running</td><td>${status.running ? 'yes' : 'no'}</td></tr>
<tr><td>Floodfill</td><td>${status.floodfill ? 'yes' : 'no'}</td></tr>
<tr><td>NTCP2 peers</td><td>${status.peers}</td></tr>
<tr><td>netDb RouterInfos</td><td>${status.netDb}</td></tr>
<tr><td>Inbound / outbound tunnels</td><td>${status.inboundTunnels} / ${status.outboundTunnels}</td></tr>
<tr><td>Hosts book</td><td>${status.hosts}</td></tr>
<tr><td>Cached LeaseSets</td><td>${status.leaseSets}</td></tr>
<tr><td>Destination b32</td><td><code>${b32}</code></td></tr>
</table>
<p>HTTP proxy <code>127.0.0.1:4444</code> · SOCKS <code>127.0.0.1:4447</code> · SAM <code>127.0.0.1:7656</code></p>
</body></html>`);
  });
  return {
    server,
    listen: () => new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }),
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}
