'use strict';
const http = require('node:http');
const { SamClient } = require('./sam');

function createProxy({ sam = new SamClient(), host = '0.0.0.0', port = 4444 } = {}) {
  const server = http.createServer(async (req, res) => {
    let upstream;
    try {
      const target = new URL(req.url);
      if (target.protocol !== 'http:' || !target.hostname.endsWith('.i2p')) throw new Error('Proxy supports only http://*.i2p URLs');
      const destination = await sam.lookup(target.hostname);
      upstream = await sam.connect(destination);
      const headers = { ...req.headers, host: target.host, connection: 'close' };
      delete headers['proxy-connection'];
      const outgoing = http.request({ hostname: target.hostname, port: 80, method: req.method, path: `${target.pathname}${target.search}` || '/', headers, agent: false, createConnection: () => upstream });
      outgoing.on('response', response => { res.writeHead(response.statusCode, response.statusMessage, response.headers); response.pipe(res); });
      outgoing.on('error', e => { upstream?.destroy(); if (!res.headersSent) res.writeHead(502); res.end(`I2P stream error: ${e.message}`); });
      req.pipe(outgoing);
      res.on('close', () => upstream?.destroy());
    } catch (e) { upstream?.destroy(); res.writeHead(502, { 'content-type': 'text/plain' }); res.end(`I2P proxy error: ${e.message}\n`); }
  });
  server.on('connect', async (req, client, head) => {
    let upstream;
    try {
      const hostname = req.url.slice(0, req.url.lastIndexOf(':'));
      if (!hostname.endsWith('.i2p')) throw new Error('Only .i2p destinations are supported');
      const destination = await sam.lookup(hostname); upstream = await sam.connect(destination);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      client.pipe(upstream).pipe(client);
      client.on('error', () => upstream.destroy()); upstream.on('error', () => client.destroy());
    } catch (e) { upstream?.destroy(); client.end(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n${e.message}`); }
  });
  return { server, sam, listen: () => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }), close: async () => { server.close(); await sam.close(); } };
}
module.exports = { createProxy };
