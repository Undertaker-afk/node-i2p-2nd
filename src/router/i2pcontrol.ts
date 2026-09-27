import { randomBytes } from 'node:crypto';
import http from 'node:http';

export const I2PCONTROL_API = 1;
export const I2PCONTROL_DEFAULT_PASSWORD = 'itoopie';

export type I2pControlStatus = {
  running: boolean;
  peers: number;
  netDb: number;
  inboundTunnels: number;
  outboundTunnels: number;
};

export type I2pControlRouter = {
  status(): I2pControlStatus;
  identity: { identityHash: Buffer };
};

type JsonRpcRequest = {
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
};

type TokenRecord = { token: string; expiresAt: number };

/** Local JSON-RPC I2PControl subset (Authenticate, Echo, RouterInfo). Loopback only. */
export function createI2pControlServer(router: I2pControlRouter, options: {
  host?: string;
  port?: number;
  password?: string;
  startedAt?: number;
} = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 7650;
  const password = options.password ?? I2PCONTROL_DEFAULT_PASSWORD;
  const startedAt = options.startedAt ?? Date.now();
  const tokens = new Map<string, TokenRecord>();

  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST', 'content-type': 'text/plain; charset=utf-8' });
      res.end('POST only\n');
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', chunk => {
      chunks.push(Buffer.from(chunk));
      if (chunks.reduce((sum, part) => sum + part.length, 0) > 64 * 1024) req.destroy();
    });
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as JsonRpcRequest;
        const result = dispatch(body);
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ id: body.id ?? null, result }));
      } catch (error) {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          id: null,
          error: { code: -32600, message: error instanceof Error ? error.message : String(error) },
        }));
      }
    });
  });

  function dispatch(body: JsonRpcRequest): Record<string, unknown> {
    const method = body.method;
    const params = body.params ?? {};
    if (method === 'Authenticate') return authenticate(params);
    requireToken(params);
    if (method === 'Echo') return { Result: String(params.Echo ?? params.echo ?? '') };
    if (method === 'RouterInfo') return routerInfo(params);
    if (method === 'NetworkSetting') return networkSetting();
    throw new Error(`Unsupported I2PControl method ${String(method)}`);
  }

  function authenticate(params: Record<string, unknown>): Record<string, unknown> {
    const api = Number(params.API ?? 1);
    if (api !== I2PCONTROL_API) throw new Error('Unsupported I2PControl API version');
    if (String(params.Password ?? '') !== password) throw new Error('Invalid I2PControl password');
    const token = randomBytes(16).toString('hex');
    tokens.set(token, { token, expiresAt: Date.now() + 60 * 60 * 1000 });
    return { API: I2PCONTROL_API, Token: token };
  }

  function requireToken(params: Record<string, unknown>): void {
    const token = String(params.Token ?? '');
    const record = tokens.get(token);
    if (!record || record.expiresAt <= Date.now()) throw new Error('Invalid I2PControl token');
  }

  function routerInfo(params: Record<string, unknown>): Record<string, unknown> {
    const status = router.status();
    const requested = Object.keys(params).filter(key => key.startsWith('i2p.'));
    const all: Record<string, unknown> = {
      'i2p.router.uptime': String(Date.now() - startedAt),
      'i2p.router.version': '0.9.64',
      'i2p.router.status': status.running ? 'OK' : 'STOPPED',
      'i2p.router.net.status': status.running ? '1' : '0',
      'i2p.router.net.tunnels.participating': String(status.inboundTunnels + status.outboundTunnels),
      'i2p.router.netdb.knownpeers': String(status.netDb),
      'i2p.router.netdb.activepeers': String(status.peers),
      'i2p.router.net.bw.inbound.1s': '0',
      'i2p.router.net.bw.outbound.1s': '0',
    };
    if (!requested.length) return all;
    const filtered: Record<string, unknown> = {};
    for (const key of requested) if (key in all) filtered[key] = all[key];
    return filtered;
  }

  function networkSetting(): Record<string, unknown> {
    return {
      'i2p.router.net.ntcp.port': '0',
      'i2p.router.net.ssu.port': '0',
      'i2p.router.net.bw.share': '100',
    };
  }

  return {
    server,
    listen: () => new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, resolve);
    }),
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}
