import net from 'node:net';
import { wrapDestinationStream } from './http-client.ts';
import type { NativeRouterNode } from './node.ts';
import type { DestinationStream } from './destination-session.ts';

export type TunnelConfig = {
  name: string;
  type: 'client' | 'server' | 'http' | 'httpclient';
  host: string;
  port: number;
  destination?: string;
  address?: string;
};

/** Parses an i2pd-style tunnels.conf (INI sections). */
export function parseTunnelsConf(text: string): TunnelConfig[] {
  const tunnels: TunnelConfig[] = [];
  let current: Partial<TunnelConfig> & { name?: string } = {};
  const flush = (): void => {
    if (!current.name || !current.type || !current.port) return;
    tunnels.push({
      name: current.name,
      type: current.type,
      host: current.host ?? current.address ?? '127.0.0.1',
      port: current.port,
      ...(current.destination ? { destination: current.destination } : {}),
      ...(current.address ? { address: current.address } : {}),
    });
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const section = /^\[([^\]]+)\]$/.exec(line);
    if (section) {
      flush();
      const name = section[1];
      current = name ? { name } : {};
      continue;
    }
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = line.slice(eq + 1).trim();
    if (key === 'type' && (value === 'client' || value === 'server' || value === 'http' || value === 'httpclient')) current.type = value;
    else if (key === 'host' || key === 'address') current.host = value;
    else if (key === 'port') current.port = Number(value);
    else if (key === 'destination') current.destination = value;
  }
  flush();
  return tunnels;
}

export function startTunnelServices(node: NativeRouterNode, tunnels: readonly TunnelConfig[]): { close: () => Promise<void> } {
  const servers: net.Server[] = [];
  for (const tunnel of tunnels) {
    if (tunnel.type === 'client' || tunnel.type === 'httpclient') {
      if (!tunnel.destination) continue;
      const destination = tunnel.destination;
      const server = net.createServer(socket => {
        void node.connectDestination(destination).then(({ stream }) => {
          const upstream = wrapDestinationStream(stream);
          socket.pipe(upstream); upstream.pipe(socket);
          socket.once('close', () => upstream.destroy());
        }).catch(() => socket.destroy());
      });
      server.listen(tunnel.port, tunnel.address ?? '127.0.0.1');
      servers.push(server);
    }
  }
  const serverTunnels = tunnels.filter(tunnel => tunnel.type === 'server' || tunnel.type === 'http');
  if (serverTunnels.length) {
    node.destinations.on('inboundStream', (stream: DestinationStream) => {
      const tunnel = serverTunnels[0];
      if (!tunnel) return;
      const target = net.connect(tunnel.port, tunnel.host, () => {
        const duplex = wrapDestinationStream(stream);
        duplex.pipe(target); target.pipe(duplex);
      });
      target.on('error', () => { void stream.close(); });
    });
  }
  return {
    close: async () => {
      await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    },
  };
}
