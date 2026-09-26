import net from 'node:net';
import { decodeDestinationBase64, encodeDestinationBase64 } from './protocol/destination.ts';
import { parseB32Hostname } from './util/encoding.ts';
import type { NativeRouterNode } from './node.ts';

function writeLine(socket: net.Socket, line: string): void {
  socket.write(`${line}\n`);
}

/** Local SAM v3 facade over the native router (STREAM + NAMING). */
export function createNativeSamServer(node: NativeRouterNode, options: { host?: string; port?: number } = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 7656;
  const sessions = new Map<string, { destination: string }>();
  const server = net.createServer(socket => {
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index).replace(/\r$/, '');
        buffer = buffer.slice(index + 1);
        void handleLine(socket, line).catch(error => {
          writeLine(socket, `SESSION STATUS RESULT=I2P_ERROR MESSAGE="${String(error).replace(/"/g, '')}"`);
          socket.end();
        });
      }
    });
  });

  async function handleLine(socket: net.Socket, line: string): Promise<void> {
    const parts = line.trim().split(/\s+/);
    const cmd = parts[0]?.toUpperCase();
    if (cmd === 'HELLO') {
      writeLine(socket, 'HELLO REPLY RESULT=OK VERSION=3.3');
      return;
    }
    if (cmd === 'SESSION' && parts[1]?.toUpperCase() === 'CREATE') {
      const fields = parseFields(parts.slice(2));
      const id = fields.ID;
      if (!id) throw new Error('SESSION CREATE requires ID');
      const destination = encodeDestinationBase64(node.destinations.local.destination);
      sessions.set(id, { destination });
      writeLine(socket, `SESSION STATUS RESULT=OK DESTINATION=${destination}`);
      return;
    }
    if (cmd === 'NAMING' && parts[1]?.toUpperCase() === 'LOOKUP') {
      const fields = parseFields(parts.slice(2));
      const name = fields.NAME;
      if (!name) throw new Error('NAMING LOOKUP requires NAME');
      const dest = await resolveName(name);
      writeLine(socket, `NAMING REPLY RESULT=OK NAME=${name} VALUE=${dest}`);
      return;
    }
    if (cmd === 'STREAM' && parts[1]?.toUpperCase() === 'CONNECT') {
      const fields = parseFields(parts.slice(2));
      if (!fields.ID || !sessions.has(fields.ID)) throw new Error('STREAM CONNECT requires a created session');
      if (!fields.DESTINATION) throw new Error('STREAM CONNECT requires DESTINATION');
      const destValue = fields.DESTINATION;
      const { stream } = destValue.endsWith('.i2p')
        ? await node.connectDestination(destValue)
        : await node.connectToDestination(decodeDestinationBase64(destValue));
      writeLine(socket, 'STREAM STATUS RESULT=OK');
      socket.removeAllListeners('data');
      stream.on('data', (payload: Buffer) => { socket.write(payload); });
      socket.on('data', (chunk: Buffer) => { void stream.write(chunk); });
      stream.on('close', () => socket.end());
      socket.on('close', () => stream.emit('close'));
      return;
    }
    writeLine(socket, `${cmd ?? 'SESSION'} STATUS RESULT=I2P_ERROR MESSAGE="Unsupported SAM command"`);
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
