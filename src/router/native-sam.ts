import net from 'node:net';
import { decodeDestinationBase64, encodeDestinationBase64, createDestinationKeys } from './protocol/destination.ts';
import { parseB32Hostname } from './util/encoding.ts';
import type { NativeRouterNode } from './node.ts';
import type { DestinationStream } from './destination-session.ts';

function writeLine(socket: net.Socket, line: string): void {
  socket.write(`${line}\n`);
}

type SamSession = { id: string; style: 'STREAM' | 'DATAGRAM' | 'RAW'; destination: string; socket?: net.Socket };

/** Local SAM v3 facade over the native router (STREAM, DATAGRAM, NAMING, DEST). */
export function createNativeSamServer(node: NativeRouterNode, options: { host?: string; port?: number } = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 7656;
  const sessions = new Map<string, SamSession>();
  const acceptWaiters: Array<{ sessionId: string; socket: net.Socket; silent: boolean }> = [];
  const inboundQueue: DestinationStream[] = [];

  node.destinations.on('inboundStream', (stream: DestinationStream) => {
    const waiter = acceptWaiters.shift();
    if (waiter) {
      attachAccept(waiter.socket, stream, waiter.silent);
      return;
    }
    inboundQueue.push(stream);
  });

  node.destinations.on('datagram', (payload: Buffer) => {
    for (const session of sessions.values()) {
      if ((session.style === 'DATAGRAM' || session.style === 'RAW') && session.socket && !session.socket.destroyed) {
        session.socket.write(`DATAGRAM RECEIVED DESTINATION=${session.destination} SIZE=${payload.length}\n`);
        session.socket.write(payload);
      }
    }
  });

  const server = net.createServer(socket => {
    let buffer = Buffer.alloc(0);
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      void consume(socket, buffer).then(rest => { buffer = Buffer.from(rest); }).catch(error => {
        writeLine(socket, `SESSION STATUS RESULT=I2P_ERROR MESSAGE="${String(error).replace(/"/g, '')}"`);
        socket.end();
      });
    });
  });

  async function consume(socket: net.Socket, buffer: Buffer): Promise<Buffer> {
    while (true) {
      const index = buffer.indexOf('\n');
      if (index < 0) return buffer;
      const line = buffer.subarray(0, index).toString('utf8').replace(/\r$/, '');
      buffer = buffer.subarray(index + 1);
      const rest = await handleLine(socket, line, buffer);
      if (rest !== undefined) return rest;
    }
  }

  async function handleLine(socket: net.Socket, line: string, rest: Buffer): Promise<Buffer | undefined> {
    const parts = line.trim().split(/\s+/);
    const cmd = parts[0]?.toUpperCase();
    const sub = parts[1]?.toUpperCase();
    if (cmd === 'HELLO') {
      writeLine(socket, 'HELLO REPLY RESULT=OK VERSION=3.3');
      return undefined;
    }
    if (cmd === 'PING') {
      writeLine(socket, `PONG${parts[1] ? ` ${parts[1]}` : ''}`);
      return undefined;
    }
    if (cmd === 'SESSION' && sub === 'CREATE') {
      const fields = parseFields(parts.slice(2));
      const id = fields.ID;
      if (!id) throw new Error('SESSION CREATE requires ID');
      const style = (fields.STYLE ?? 'STREAM').toUpperCase();
      if (style !== 'STREAM' && style !== 'DATAGRAM' && style !== 'RAW') throw new Error(`Unsupported SESSION STYLE ${style}`);
      const destination = encodeDestinationBase64(node.destinations.local.destination);
      const session: SamSession = { id, style: style as SamSession['style'], destination, socket };
      sessions.set(id, session);
      writeLine(socket, `SESSION STATUS RESULT=OK DESTINATION=${destination}`);
      return undefined;
    }
    if (cmd === 'SESSION' && sub === 'ADD') {
      const fields = parseFields(parts.slice(2));
      if (!fields.ID || !sessions.has(fields.ID)) throw new Error('SESSION ADD requires a created session');
      writeLine(socket, `SESSION STATUS RESULT=OK DESTINATION=${sessions.get(fields.ID)!.destination}`);
      return undefined;
    }
    if (cmd === 'SESSION' && sub === 'REMOVE') {
      const fields = parseFields(parts.slice(2));
      if (fields.ID) sessions.delete(fields.ID);
      writeLine(socket, 'SESSION STATUS RESULT=OK');
      return undefined;
    }
    if (cmd === 'NAMING' && sub === 'LOOKUP') {
      const fields = parseFields(parts.slice(2));
      const name = fields.NAME;
      if (!name) throw new Error('NAMING LOOKUP requires NAME');
      try {
        const dest = await resolveName(name);
        writeLine(socket, `NAMING REPLY RESULT=OK NAME=${name} VALUE=${dest}`);
      } catch (error) {
        writeLine(socket, `NAMING REPLY RESULT=KEY_NOT_FOUND NAME=${name} MESSAGE="${error instanceof Error ? error.message : String(error)}"`);
      }
      return undefined;
    }
    if (cmd === 'DEST' && sub === 'GENERATE') {
      const keys = createDestinationKeys();
      writeLine(socket, `DEST REPLY PUB=${encodeDestinationBase64(keys.destination)} PRIV=${keys.destination.toString('base64')}`);
      return undefined;
    }
    if (cmd === 'STREAM' && sub === 'CONNECT') {
      const fields = parseFields(parts.slice(2));
      if (!fields.ID || !sessions.has(fields.ID)) throw new Error('STREAM CONNECT requires a created session');
      if (!fields.DESTINATION) throw new Error('STREAM CONNECT requires DESTINATION');
      const destValue = fields.DESTINATION;
      const { stream } = destValue.toLowerCase().endsWith('.i2p')
        ? await node.connectDestination(destValue)
        : await node.connectToDestination(decodeDestinationBase64(destValue));
      writeLine(socket, 'STREAM STATUS RESULT=OK');
      pipeStream(socket, stream);
      if (rest.length) void stream.write(rest);
      return Buffer.alloc(0);
    }
    if (cmd === 'STREAM' && sub === 'ACCEPT') {
      const fields = parseFields(parts.slice(2));
      if (!fields.ID || !sessions.has(fields.ID)) throw new Error('STREAM ACCEPT requires a created session');
      const silent = (fields.SILENT ?? 'false').toLowerCase() === 'true';
      const queued = inboundQueue.shift();
      if (queued) {
        attachAccept(socket, queued, silent);
        return Buffer.alloc(0);
      }
      acceptWaiters.push({ sessionId: fields.ID, socket, silent });
      return Buffer.alloc(0);
    }
    if (cmd === 'DATAGRAM' && sub === 'SEND') {
      const fields = parseFields(parts.slice(2));
      if (!fields.DESTINATION) throw new Error('DATAGRAM SEND requires DESTINATION');
      const size = Number(fields.SIZE ?? rest.length);
      if (!Number.isInteger(size) || size < 0 || size > rest.length) throw new Error('DATAGRAM SEND SIZE is invalid');
      const payload = rest.subarray(0, size);
      await node.sendDatagram(fields.DESTINATION, payload);
      return rest.subarray(size);
    }
    writeLine(socket, `${cmd ?? 'SESSION'} STATUS RESULT=I2P_ERROR MESSAGE="Unsupported SAM command"`);
    return undefined;
  }

  function attachAccept(socket: net.Socket, stream: DestinationStream, silent: boolean): void {
    writeLine(socket, 'STREAM STATUS RESULT=OK');
    if (!silent) writeLine(socket, encodeDestinationBase64(node.destinations.local.destination));
    pipeStream(socket, stream);
  }

  function pipeStream(socket: net.Socket, stream: DestinationStream): void {
    socket.removeAllListeners('data');
    stream.on('data', (payload: Buffer) => { socket.write(payload); });
    socket.on('data', (chunk: Buffer) => { void stream.write(chunk); });
    stream.on('close', () => socket.end());
    socket.on('close', () => { void stream.close(); });
  }

  async function resolveName(name: string): Promise<string> {
    const normalized = name.toLowerCase().replace(/\.$/, '');
    if (normalized === 'me') return encodeDestinationBase64(node.destinations.local.destination);
    const known = node.hosts.get(normalized);
    if (known) return encodeDestinationBase64(known);
    const hash = parseB32Hostname(normalized);
    if (hash) {
      const ls = node.getLeaseSet(hash) ?? await node.lookupLeaseSet(hash);
      return encodeDestinationBase64(ls.destination);
    }
    throw new Error(`Unknown name ${name}`);
  }

  return {
    server,
    listen: () => new Promise<net.AddressInfo>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server.address() as net.AddressInfo));
    }),
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}

function parseFields(parts: string[]): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq > 0) fields[part.slice(0, eq).toUpperCase()] = part.slice(eq + 1);
  }
  return fields;
}
