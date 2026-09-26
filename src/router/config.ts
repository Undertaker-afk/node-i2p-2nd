import path from 'node:path';

export type RouterConfig = {
  listenHost: string;
  listenPort: number;
  stateDir: string;
  maxPeers: number;
  maxTunnels: number;
  startupTimeoutMs: number;
};
export type RouterConfigInput = Partial<RouterConfig>;

const DEFAULTS: RouterConfig = {
  listenHost: '127.0.0.1', listenPort: 7657,
  stateDir: path.resolve(process.cwd(), '.i2p-router'),
  maxPeers: 64, maxTunnels: 32, startupTimeoutMs: 30_000,
};

export function createRouterConfig(input: RouterConfigInput = {}): RouterConfig {
  const config = { ...DEFAULTS, ...input, stateDir: input.stateDir ? path.resolve(input.stateDir) : DEFAULTS.stateDir };
  if (!config.listenHost.trim() || /[\r\n]/.test(config.listenHost)) throw new Error('listenHost must be a non-empty hostname or IP address');
  if (!Number.isInteger(config.listenPort) || config.listenPort < 0 || config.listenPort > 65535) throw new Error('listenPort must be an integer between 0 and 65535');
  if (!Number.isInteger(config.maxPeers) || config.maxPeers < 1 || config.maxPeers > 100_000) throw new Error('maxPeers must be an integer between 1 and 100000');
  if (!Number.isInteger(config.maxTunnels) || config.maxTunnels < 1 || config.maxTunnels > 100_000) throw new Error('maxTunnels must be an integer between 1 and 100000');
  if (!Number.isInteger(config.startupTimeoutMs) || config.startupTimeoutMs < 100 || config.startupTimeoutMs > 300_000) throw new Error('startupTimeoutMs must be between 100 and 300000 ms');
  if (!path.isAbsolute(config.stateDir)) throw new Error('stateDir must be absolute');
  return Object.freeze(config);
}
