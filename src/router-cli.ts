#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { loadOrCreateRouterIdentity } from './router/identity-store.ts';
import { PersistentRouterInfoStore } from './router/netdb/persistent-store.ts';
import { VerifiedRouterInfoStore } from './router/netdb/store.ts';
import { createRouterInfoRecord, type RouterAddress } from './router/protocol/router-info.ts';
import { NativeRouterNode } from './router/node.ts';
import { createNativeSamServer } from './router/native-sam.ts';

function usage(): string {
  return [
    'Usage: npm run router -- --public-host <reachable-ip-or-hostname> [options]',
    '',
    'Options:',
    '  --bind-host <host>   Local bind address (default: 0.0.0.0)',
    '  --port <port>        Published/listen NTCP2 port (default: 12345)',
    '  --state-dir <path>   Identity and netDb directory (default: ~/.i2p-native-ts)',
    '  --net-id <id>        I2P network ID (default: 2)',
    '  --max-transit-tunnels <n> Max active transit tunnels (default: 5000)',
    '  --max-concurrent-tunnel-builds <n> Concurrent short builds (default: 8)',
    '  --no-transit          Decline new transit tunnel builds',
    '  --help                Show this help',
    '',
    'The published address must be reachable from other I2P routers and the port must be allowed through your firewall/NAT.',
  ].join('\n');
}

function parseArgs(argv: string[]): Map<string, string | true> {
  const result = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]!;
    if (!argument.startsWith('--')) throw new Error(`Unexpected argument: ${argument}`);
    const equals = argument.indexOf('=');
    const key = equals < 0 ? argument.slice(2) : argument.slice(2, equals);
    if (!/^[a-z][a-z-]*$/.test(key) || result.has(key)) throw new Error(`Invalid or duplicate option: ${argument}`);
    if (key === 'help' || key === 'no-transit') { result.set(key, true); continue; }
    const value = equals < 0 ? argv[++index] : argument.slice(equals + 1);
    if (!value || value.startsWith('--')) throw new Error(`Option --${key} requires a value`);
    result.set(key, value);
  }
  return result;
}

function b64(value: Buffer): string { return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~'); }

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.has('help')) { process.stdout.write(`${usage()}\n`); return; }
  const publicHost = args.get('public-host');
  if (typeof publicHost !== 'string' || !publicHost.trim() || /[\s\r\n/]/.test(publicHost)) throw new Error('--public-host is required and must be a reachable host/IP (not a URL)');
  const bindHost = args.get('bind-host') ?? '0.0.0.0';
  const port = Number(args.get('port') ?? 12345); const networkId = Number(args.get('net-id') ?? 2);
  const maxTransitTunnels = Number(args.get('max-transit-tunnels') ?? 5000);
  const maxConcurrentTunnelBuilds = Number(args.get('max-concurrent-tunnel-builds') ?? 8);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new RangeError('--port must be 1..65535');
  if (!Number.isInteger(networkId) || networkId < 1 || networkId > 255) throw new RangeError('--net-id must be a uint8');
  if (!Number.isInteger(maxTransitTunnels) || maxTransitTunnels < 1 || maxTransitTunnels > 100_000) throw new RangeError('--max-transit-tunnels must be 1..100000');
  if (!Number.isInteger(maxConcurrentTunnelBuilds) || maxConcurrentTunnelBuilds < 1 || maxConcurrentTunnelBuilds > 256) throw new RangeError('--max-concurrent-tunnel-builds must be 1..256');
  if (typeof bindHost !== 'string' || !bindHost.trim()) throw new Error('--bind-host must not be empty');
  const home = os.homedir(); const defaultState = path.join(home, '.i2p-native-ts');
  const stateValue = args.get('state-dir') ?? defaultState;
  if (typeof stateValue !== 'string') throw new Error('--state-dir must be a path');
  const stateDir = path.resolve(stateValue);

  const identity = await loadOrCreateRouterIdentity(stateDir);
  const persistent = await PersistentRouterInfoStore.open(path.join(stateDir, 'netDb'), { expectedNetId: String(networkId) });
  const netDb = new VerifiedRouterInfoStore(10_000, String(networkId));
  for (const info of persistent.all()) netDb.store(info);
  const publishedIv = randomBytes(16);
  const address: RouterAddress = {
    cost: 5, expiration: 0, transport: 'NTCP2',
    options: new Map([
      ['host', publicHost], ['i', b64(publishedIv)], ['port', String(port)],
      ['s', b64(identity.identity.subarray(0, 32))], ['v', '2'],
    ]),
  };
  const routerInfo = createRouterInfoRecord(identity, Date.now(), [address], new Map([
    ['netId', String(networkId)], ['router.version', '0.9.64'], ['caps', 'NR'],
  ]));
  const nodeOptions = {
    identity, routerInfo, netDb, host: bindHost, port, publishedIv, networkId, maxTransitTunnels, maxConcurrentTunnelBuilds,
    acceptTransitTunnels: !args.has('no-transit'),
  };
  const node = netDb.size < 10
    ? await NativeRouterNode.createFromReseed(nodeOptions)
    : new NativeRouterNode(nodeOptions);
  for (const info of netDb.all()) await persistent.store(info);
  node.on('routerInfo', (info, inserted) => {
    if (inserted) void persistent.store(info).catch(error => process.stderr.write(`netDb persistence error: ${String(error)}\n`));
  });
  node.on('transportError', error => process.stderr.write(`transport error: ${String(error)}\n`));
  node.on('bootstrapError', error => process.stderr.write(`peer bootstrap error: ${String(error)}\n`));
  node.on('netDbError', error => process.stderr.write(`netDb protocol error: ${String(error)}\n`));
  node.on('peer', (peer, _connection, direction) => process.stdout.write(`NTCP2 ${direction} peer ${peer ? Buffer.from(peer).toString('hex') : 'accepted'}\n`));
  const bound = await node.start();
  process.stdout.write(`Native TypeScript I2P router listening on ${bound.address}:${bound.port}; identity ${identity.identityHash.toString('base64')}\n`);
  process.stdout.write('NTCP2, ECIES short tunnels, Garlic-N, LeaseSet2, and destination streaming are enabled.\n');
  const sam = createNativeSamServer(node, { host: '127.0.0.1', port: 7656 });
  const samAddr = await sam.listen();
  process.stdout.write(`Native SAM v3 listening on ${samAddr.address}:${samAddr.port}\n`);
  node.on('bootstrapComplete', stats => {
    process.stdout.write(`Peer bootstrap complete: ${stats.connected} connected, ${stats.attempted} attempted\n`);
    void node.tunnelPool.maintain().then(() => {
      process.stdout.write(`Tunnel pool ready: ${node.tunnelPool.inbound.length} inbound, ${node.tunnelPool.outbound.length} outbound\n`);
    }).catch(error => process.stderr.write(`tunnel pool: ${String(error)}\n`));
  });

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return; stopping = true;
    await sam.close(); await node.stop(); process.exitCode = 0;
  };
  process.once('SIGINT', () => { void shutdown().catch(error => { process.stderr.write(`${String(error)}\n`); process.exitCode = 1; }); });
  process.once('SIGTERM', () => { void shutdown().catch(error => { process.stderr.write(`${String(error)}\n`); process.exitCode = 1; }); });
}

main().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${usage()}\n`);
  process.exitCode = 1;
});
