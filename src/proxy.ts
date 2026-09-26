import http, { type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type net from 'node:net';
import type { Duplex } from 'node:stream';
import { SamClient } from './sam.ts';

type ProxyOptions = { sam?: SamClient; host?: string; port?: number; requestTimeoutMs?: number };
function respond(res: ServerResponse, status: number, message: string): void {
  if (!res.headersSent) res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'connection': 'close' });
  res.end(`${message}\n`);
}

export function createProxy({ sam = new SamClient(), host = '127.0.0.1', port = 4444, requestTimeoutMs = 120_000 }: ProxyOptions = {}) {
  const server: Server = http.createServer((req, res) => { void handleHttp(req, res); });
  const sockets = new Set<net.Socket>();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  async function handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let upstream: net.Socket | undefined;
    try {
      if (!req.url) throw new Error('Missing proxy request URL');
      const target = new URL(req.url);
      if (target.protocol !== 'http:' || !target.hostname.toLowerCase().endsWith('.i2p')) throw new Error('Only http://*.i2p destinations are supported');
      if (target.username || target.password) throw new Error('Credentials in proxy URLs are not supported');
      const destination = await sam.lookup(target.hostname);
      upstream = await sam.connect(destination);
      const headers: http.OutgoingHttpHeaders = { ...req.headers, host: target.host, connection: 'close' };
      delete headers['proxy-connection']; delete headers['proxy-authorization'];
      const outgoing = http.request({ hostname: target.hostname, port: Number(target.port || 80), method: req.method, path: `${target.pathname}${target.search}` || '/', headers, agent: false, createConnection: () => upstream! });
      const timer = setTimeout(() => outgoing.destroy(new Error('I2P request timed out')), requestTimeoutMs);
      outgoing.once('close', () => clearTimeout(timer));
      outgoing.on('response', response => { res.writeHead(response.statusCode ?? 502, response.statusMessage, response.headers); response.pipe(res); });
      outgoing.on('error', error => { upstream?.destroy(); respond(res, 502, `I2P stream error: ${error.message}`); });
      req.on('aborted', () => outgoing.destroy()); req.pipe(outgoing);
      res.on('close', () => upstream?.destroy());
    } catch (error) { upstream?.destroy(); respond(res, 502, `I2P proxy error: ${error instanceof Error ? error.message : String(error)}`); }
  }
  server.on('connect', (req, client, head) => { void handleConnect(req, client, head); });
  async function handleConnect(req: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    let upstream: net.Socket | undefined;
    try {
      const target = new URL(`http://${req.url}`);
      if (!target.hostname.toLowerCase().endsWith('.i2p') || target.username || target.password) throw new Error('Only .i2p CONNECT destinations are supported');
      const destination = await sam.lookup(target.hostname); upstream = await sam.connect(destination);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      client.pipe(upstream); upstream.pipe(client);
      client.once('close', () => upstream?.destroy()); upstream.once('error', () => client.destroy());
    } catch (error) { upstream?.destroy(); client.end(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n${error instanceof Error ? error.message : String(error)}`); }
  }
  return {
    server, sam,
    listen: () => new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }),
    close: async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); await sam.close(); },
  };
}
