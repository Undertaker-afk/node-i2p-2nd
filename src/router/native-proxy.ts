import http, { type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type net from 'node:net';
import type { Duplex } from 'node:stream';
import { isI2pHostname, wrapDestinationStream } from './http-client.ts';
import { destinationBytesFromHelper, isClearnetHostname, parseAddressHelper } from './http-helper.ts';
import type { NativeRouterNode } from './node.ts';

export type NativeProxyOptions = {
  node: NativeRouterNode;
  host?: string;
  port?: number;
  requestTimeoutMs?: number;
  outproxy?: string;
};

function respond(res: ServerResponse, status: number, message: string): void {
  if (!res.headersSent) res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' });
  res.end(`${message}\n`);
}

/** HTTP proxy: .i2p destinations, i2paddresshelper, optional HTTP outproxy for clearnet. */
export function createNativeHttpProxy({ node, host = '127.0.0.1', port = 4444, requestTimeoutMs = 120_000, outproxy }: NativeProxyOptions) {
  const server: Server = http.createServer((req, res) => { void handleHttp(req, res); });
  const sockets = new Set<net.Socket>();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });

  async function openStream(hostname: string): Promise<Duplex> {
    const { stream } = await node.connectDestination(hostname);
    return wrapDestinationStream(stream);
  }

  async function handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let upstream: Duplex | undefined;
    try {
      if (!req.url) throw new Error('Missing proxy request URL');
      const target = new URL(req.url);
      if (target.protocol !== 'http:') throw new Error('Only http:// destinations are supported');
      const helper = parseAddressHelper(target);
      if (helper.helper) {
        destinationBytesFromHelper(helper.helper);
        await node.addAddressHelper(target.hostname, helper.helper);
        res.writeHead(301, { location: helper.clean.href, 'content-type': 'text/plain; charset=utf-8', connection: 'close' });
        res.end(`Added address helper for ${target.hostname}\n`);
        return;
      }
      if (isI2pHostname(target.hostname)) {
        if (target.username || target.password) throw new Error('Only .i2p destinations are supported');
        upstream = await openStream(target.hostname);
        await proxyRequest(req, res, upstream, target, requestTimeoutMs);
        return;
      }
      if (outproxy && isClearnetHostname(target.hostname)) {
        upstream = await openStream(outproxy);
        await proxyRequest(req, res, upstream, target, requestTimeoutMs, true);
        return;
      }
      throw new Error('Only .i2p destinations are supported (configure --outproxy for clearnet)');
    } catch (error) {
      upstream?.destroy();
      respond(res, 502, `I2P proxy error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  server.on('connect', (req, client, head) => { void handleConnect(req, client, head); });

  async function handleConnect(req: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    let upstream: Duplex | undefined;
    try {
      const target = new URL(`http://${req.url}`);
      if (isI2pHostname(target.hostname)) {
        if (target.username || target.password) throw new Error('Only .i2p destinations are supported');
        upstream = await openStream(target.hostname);
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length) upstream.write(head);
        client.pipe(upstream); upstream.pipe(client);
        client.once('close', () => upstream?.destroy());
        upstream.once('error', () => client.destroy());
        return;
      }
      if (outproxy && isClearnetHostname(target.hostname)) {
        upstream = await openStream(outproxy);
        const connect = Buffer.from(`CONNECT ${target.host} HTTP/1.1\r\nHost: ${target.host}\r\nConnection: close\r\n\r\n`);
        upstream.write(connect);
        if (head.length) upstream.write(head);
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        client.pipe(upstream); upstream.pipe(client);
        client.once('close', () => upstream?.destroy());
        upstream.once('error', () => client.destroy());
        return;
      }
      throw new Error('Only .i2p destinations are supported (configure --outproxy for clearnet)');
    } catch (error) {
      upstream?.destroy();
      client.end(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    server, node,
    listen: () => new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }),
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

function proxyRequest(
  req: IncomingMessage,
  res: ServerResponse,
  upstream: Duplex,
  target: URL,
  requestTimeoutMs: number,
  absoluteForm = false,
): Promise<void> {
  const headers: http.OutgoingHttpHeaders = { ...req.headers, host: target.host, connection: 'close' };
  delete headers['proxy-connection']; delete headers['proxy-authorization'];
  const path = absoluteForm ? target.href : (`${target.pathname}${target.search}` || '/');
  const socket = upstream;
  const outgoing = http.request({
    hostname: target.hostname,
    port: Number(target.port || 80),
    method: req.method,
    path,
    headers,
    agent: false,
    createConnection: () => socket as unknown as net.Socket,
  });
  const timer = setTimeout(() => outgoing.destroy(new Error('I2P request timed out')), requestTimeoutMs);
  outgoing.once('close', () => clearTimeout(timer));
  outgoing.on('response', response => { res.writeHead(response.statusCode ?? 502, response.statusMessage, response.headers); response.pipe(res); });
  outgoing.on('error', error => { upstream.destroy(); respond(res, 502, `I2P stream error: ${error.message}`); });
  req.on('aborted', () => outgoing.destroy());
  req.pipe(outgoing);
  res.on('close', () => upstream.destroy());
  return Promise.resolve();
}
