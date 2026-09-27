import net from 'node:net';
import { isI2pHostname, wrapDestinationStream } from './http-client.ts';
import type { NativeRouterNode } from './node.ts';

export type SocksProxyOptions = { node: NativeRouterNode; host?: string; port?: number };

function fail(socket: net.Socket, socks5: boolean, message: string): void {
  if (!socket.destroyed) {
    if (socks5) socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
    else socket.end(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0]));
  }
  void message;
}

/** SOCKS4a/SOCKS5 proxy restricted to .i2p destinations. */
export function createNativeSocksProxy({ node, host = '127.0.0.1', port = 4447 }: SocksProxyOptions) {
  const server = net.createServer(socket => { void handle(socket).catch(() => socket.destroy()); });
  const sockets = new Set<net.Socket>();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });

  async function handle(socket: net.Socket): Promise<void> {
    const header = await readAtLeast(socket, 2);
    if (header[0] === 0x05) return handleSocks5(socket, header);
    if (header[0] === 0x04) return handleSocks4(socket, header);
    socket.destroy();
  }

  async function handleSocks5(socket: net.Socket, first: Buffer): Promise<void> {
    const nmethods = first[1]!;
    if (nmethods) await readAtLeast(socket, nmethods);
    socket.write(Buffer.from([0x05, 0x00]));
    const req = await readAtLeast(socket, 4);
    if (req[1] !== 0x01) { fail(socket, true, 'only CONNECT is supported'); return; }
    const atyp = req[3]!;
    let hostname: string;
    if (atyp === 0x03) {
      const lengthBuf = await readAtLeast(socket, 1);
      const length = lengthBuf[0]!;
      const rest = await readAtLeast(socket, length + 2);
      hostname = rest.subarray(0, length).toString('utf8');
    } else {
      fail(socket, true, 'only domain names are supported');
      return;
    }
    if (!isI2pHostname(hostname)) { fail(socket, true, 'only .i2p destinations are supported'); return; }
    try {
      const { stream } = await node.connectDestination(hostname);
      const upstream = wrapDestinationStream(stream);
      socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.pipe(upstream); upstream.pipe(socket);
      socket.once('close', () => upstream.destroy());
    } catch {
      fail(socket, true, 'connect failed');
    }
  }

  async function handleSocks4(socket: net.Socket, first: Buffer): Promise<void> {
    const req = await readAtLeast(socket, 8);
    if (first[1] !== 0x01 && req[1] !== 0x01) { fail(socket, false, 'only CONNECT is supported'); return; }
    const body = await readUntilNull(socket, req);
    const userEnd = body.indexOf(0, 8);
    if (userEnd < 0) { socket.destroy(); return; }
    let hostname = '';
    if (body[4] === 0 && body[5] === 0 && body[6] === 0 && body[7] !== 0) {
      const hostStart = userEnd + 1;
      const hostEnd = body.indexOf(0, hostStart);
      hostname = body.subarray(hostStart, hostEnd < 0 ? body.length : hostEnd).toString('utf8');
    }
    if (!isI2pHostname(hostname)) { fail(socket, false, 'only .i2p destinations are supported'); return; }
    try {
      const { stream } = await node.connectDestination(hostname);
      const upstream = wrapDestinationStream(stream);
      socket.write(Buffer.from([0x00, 0x5a, 0, 0, 0, 0, 0, 0]));
      socket.pipe(upstream); upstream.pipe(socket);
      socket.once('close', () => upstream.destroy());
    } catch {
      fail(socket, false, 'connect failed');
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

function readAtLeast(socket: net.Socket, size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk); length += chunk.length;
      if (length >= size) {
        cleanup();
        const all = Buffer.concat(chunks);
        if (all.length > size) socket.unshift(all.subarray(size));
        resolve(all.subarray(0, size));
      }
    };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    };
    const onError = (error: Error): void => { cleanup(); reject(error); };
    const onClose = (): void => { cleanup(); reject(new Error('socket closed')); };
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function readUntilNull(socket: net.Socket, prefix: Buffer): Promise<Buffer> {
  if (prefix.includes(0) && prefix[4] === 0 && prefix[5] === 0 && prefix[6] === 0) {
    /* may still need hostname */
  }
  return new Promise((resolve, reject) => {
    let buffer = prefix;
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      const userEnd = buffer.indexOf(0, 8);
      if (userEnd < 0) return;
      const socks4a = buffer[4] === 0 && buffer[5] === 0 && buffer[6] === 0 && buffer[7] !== 0;
      if (socks4a && buffer.indexOf(0, userEnd + 1) < 0) return;
      cleanup();
      resolve(buffer);
    };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    };
    const onError = (error: Error): void => { cleanup(); reject(error); };
    const onClose = (): void => { cleanup(); reject(new Error('socket closed')); };
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
    onData(Buffer.alloc(0));
  });
}
