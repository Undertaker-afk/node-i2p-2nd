#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { createSsu2Address } from './router/transport/ssu2/address.ts';
import { importSu3Reseed, loadReseedSigners } from './router/netdb/reseed.ts';
import { loadOrCreateRouterIdentity } from './router/identity-store.ts';
import { loadOrCreateDestinationKeys } from './router/destination-store.ts';
import { PersistentRouterInfoStore } from './router/netdb/persistent-store.ts';
import { VerifiedRouterInfoStore } from './router/netdb/store.ts';
import { createRouterInfoRecord, type RouterAddress } from './router/protocol/router-info.ts';
import { NativeRouterNode } from './router/node.ts';
import { createNativeSamServer } from './router/native-sam.ts';
import { createNativeHttpProxy } from './router/native-proxy.ts';
import { createNativeSocksProxy } from './router/native-socks.ts';
import { createRouterConsole } from './router/console.ts';
import { parseTunnelsConf, startTunnelServices } from './router/tunnels-conf.ts';
import { encodeDestinationBase64 } from './router/protocol/destination.ts';
import { createI2cpServer } from './router/i2cp.ts';
import { createI2pControlServer } from './router/i2pcontrol.ts';

function usage(): string {
  return [
    'Usage: npm run router -- --public-host <reachable-ip-or-hostname> [options]',
    '',
    'Options:',
    '  --bind-host <host>   Local bind address (default: 0.0.0.0)',
    '  --port <port>        Published/listen NTCP2 (TCP) port (default: 12345)',
    '  --ssu-port <port>    Published/listen SSU2 (UDP) port (default: same number as --port)',
    '  --no-ssu2            Disable the SSU2 UDP transport (NTCP2 only)',
    '  --peers <n>          Direct peers to connect during bootstrap (default: 16)',
    '  --reseed-file <path> Import a signed i2pseeds.su3 instead of downloading one (offline/filtered networks)',
    '  --state-dir <path>   Identity and netDb directory (default: ~/.i2p-native-ts)',
    '  --net-id <id>        I2P network ID (default: 2)',
    '  --max-transit-tunnels <n> Max active transit tunnels (default: 5000)',
    '  --max-concurrent-tunnel-builds <n> Concurrent short builds (default: 8)',
    '  --proxy-host <host>  Native HTTP proxy bind host (default: 127.0.0.1)',
    '  --proxy-port <port>  Native HTTP proxy port (default: 4444)',
    '  --socks-port <port>  Native SOCKS proxy port (default: 4447)',
    '  --console-port <port> Local status page (default: 7070)',
    '  --tunnels <path>     i2pd-style tunnels.conf',
    '  --floodfill          Publish floodfill caps and answer netDb lookups',
    '  --outproxy <host>    HTTP outproxy eepsite for clearnet URLs',
    '  --hop-count <n>      Client tunnel hop count (default: 2)',
    '  --i2cp-port <port>   I2CP listen port (default: 7654)',
    '  --sam-port <port>    SAM v3 listen port (default: 7656)',
    '  --i2pcontrol-port <port> I2PControl JSON-RPC port (default: 7650)',
    '  --no-proxy            Do not start the native HTTP proxy',
    '  --no-socks            Do not start the SOCKS proxy',
    '  --no-console          Do not start the status page',
    '  --no-i2cp             Do not start I2CP',
    '  --no-sam              Do not start SAM',
    '  --no-i2pcontrol       Do not start I2PControl',
    '  --no-transit          Decline new transit tunnel builds',
    '  --help                Show this help',
    '',
    'The published address must be reachable from other I2P routers: allow TCP <port> (NTCP2) and',
    'UDP <ssu-port> (SSU2) through your firewall/NAT. Local APIs (proxy, SOCKS, SAM, I2CP, console)',
    'bind to 127.0.0.1 only.',
  ].join('\n');
}

function parseArgs(argv: string[]): Map<string, string | true> {
  const result = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]!;
    if (!argument.startsWith('--')) throw new Error(`Unexpected argument: ${argument}`);
    const equals = argument.indexOf('=');
    const key = equals < 0 ? argument.slice(2) : argument.slice(2, equals);
    if (!/^[a-z][a-z0-9-]*$/.test(key) || result.has(key)) throw new Error(`Invalid or duplicate option: ${argument}`);
    if (key === 'help' || key === 'no-transit' || key === 'no-proxy' || key === 'no-socks' || key === 'no-console' || key === 'floodfill' || key === 'no-i2cp' || key === 'no-i2pcontrol' || key === 'no-ssu2' || key === 'no-sam') {
      result.set(key, true); continue;
    }
    const value = equals < 0 ? argv[++index] : argument.slice(equals + 1);
    if (!value || value.startsWith('--')) throw new Error(`Option --${key} requires a value`);
    result.set(key, value);
  }
  return result;
}

function b64(value: Buffer): string { return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~'); }

function portArg(args: Map<string, string | true>, key: string, fallback: number): number {
  const value = Number(args.get(key) ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new RangeError(`--${key} must be 1..65535`);
  return value;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.has('help')) { process.stdout.write(`${usage()}\n`); return; }
  const publicHost = args.get('public-host');
  if (typeof publicHost !== 'string' || !publicHost.trim() || /[\s\r\n/]/.test(publicHost)) throw new Error('--public-host is required and must be a reachable host/IP (not a URL)');
  const bindHost = args.get('bind-host') ?? '0.0.0.0';
  const port = portArg(args, 'port', 12345); const networkId = Number(args.get('net-id') ?? 2);
  const ssu2Enabled = !args.has('no-ssu2');
  const ssuPort = portArg(args, 'ssu-port', port);
  const targetOutboundPeers = Number(args.get('peers') ?? 16);
  if (!Number.isInteger(targetOutboundPeers) || targetOutboundPeers < 1 || targetOutboundPeers > 256) throw new RangeError('--peers must be 1..256');
  const maxTransitTunnels = Number(args.get('max-transit-tunnels') ?? 5000);
  const maxConcurrentTunnelBuilds = Number(args.get('max-concurrent-tunnel-builds') ?? 8);
  if (!Number.isInteger(networkId) || networkId < 1 || networkId > 255) throw new RangeError('--net-id must be a uint8');
  if (!Number.isInteger(maxTransitTunnels) || maxTransitTunnels < 1 || maxTransitTunnels > 100_000) throw new RangeError('--max-transit-tunnels must be 1..100000');
  if (!Number.isInteger(maxConcurrentTunnelBuilds) || maxConcurrentTunnelBuilds < 1 || maxConcurrentTunnelBuilds > 256) throw new RangeError('--max-concurrent-tunnel-builds must be 1..256');
  if (typeof bindHost !== 'string' || !bindHost.trim()) throw new Error('--bind-host must not be empty');
  const home = os.homedir(); const defaultState = path.join(home, '.i2p-native-ts');
  const stateValue = args.get('state-dir') ?? defaultState;
  if (typeof stateValue !== 'string') throw new Error('--state-dir must be a path');
  const stateDir = path.resolve(stateValue);
  const floodfill = args.has('floodfill');
  const hopCount = Number(args.get('hop-count') ?? 2);
  if (!Number.isInteger(hopCount) || hopCount < 1 || hopCount > 7) throw new RangeError('--hop-count must be 1..7');
  const outproxy = args.get('outproxy');
  if (outproxy !== undefined && (typeof outproxy !== 'string' || !outproxy.endsWith('.i2p'))) throw new Error('--outproxy must be an .i2p hostname');

  const identity = await loadOrCreateRouterIdentity(stateDir);
  const destination = await loadOrCreateDestinationKeys(stateDir);
  const persistent = await PersistentRouterInfoStore.open(path.join(stateDir, 'netDb'), { expectedNetId: String(networkId) });
  const netDb = new VerifiedRouterInfoStore(10_000, String(networkId));
  for (const info of persistent.all()) netDb.store(info);
  const reseedFile = args.get('reseed-file');
  if (typeof reseedFile === 'string') {
    const result = importSu3Reseed(await readFile(path.resolve(reseedFile)), await loadReseedSigners(), netDb, { minRouterInfos: 1 });
    process.stdout.write(`Imported ${result.imported} RouterInfos from ${reseedFile} (signer ${result.signer}, ${result.rejected} rejected)\n`);
  }
  const publishedIv = randomBytes(16);
  const address: RouterAddress = {
    cost: 5, expiration: 0, transport: 'NTCP2',
    options: new Map([
      ['host', publicHost], ['i', b64(publishedIv)], ['port', String(port)],
      ['s', b64(identity.identity.subarray(0, 32))], ['v', '2'],
    ]),
  };
  const introKey = ssu2Enabled ? await loadOrCreateIntroKey(stateDir) : undefined;
  const addresses: RouterAddress[] = [address];
  // SSU2 static key == router X25519 encryption key (same as NTCP2 "s"); intro key is persisted separately.
  if (introKey) addresses.push(createSsu2Address({ host: publicHost, port: ssuPort, staticKey: identity.identity.subarray(0, 32), introKey, caps: '4', cost: 3 }));
  const routerInfo = createRouterInfoRecord(identity, Date.now(), addresses, new Map([
    ['netId', String(networkId)], ['router.version', '0.9.64'], ['caps', floodfill ? 'fR' : 'NR'],
  ]));
  const nodeOptions = {
    identity, routerInfo, netDb, host: bindHost, port, publishedIv, networkId, maxTransitTunnels, maxConcurrentTunnelBuilds,
    acceptTransitTunnels: !args.has('no-transit'), destination, floodfill, hopCount, targetOutboundPeers,
    ...(introKey ? { ssu2: { port: ssuPort, introKey, host: bindHost } } : {}),
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
  node.on('peer', (peer, connection, direction) => process.stdout.write(`${connection?.transport ?? 'NTCP2'} ${direction} peer ${peer ? Buffer.from(peer).toString('hex').slice(0, 16) : 'accepted'}\n`));
  attachDiagnostics(node);
  const hostsPath = path.join(stateDir, 'hosts.txt');
  try {
    const imported = node.hosts.importHostsTxt(await readFile(hostsPath, 'utf8'));
    process.stdout.write(`Loaded ${imported} additional hosts.txt entries from ${hostsPath}\n`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') process.stderr.write(`hosts.txt load: ${String(error)}\n`);
  }
  const bound = await node.start();
  process.stdout.write(`Native TypeScript I2P router listening on ${bound.address}:${bound.port}/tcp (NTCP2); identity ${identity.identityHash.toString('base64')}\n`);
  if (node.ssu2) process.stdout.write(`SSU2 listening on ${bindHost}:${ssuPort}/udp; published ${publicHost}:${ssuPort}\n`);
  process.stdout.write(`netDb: ${netDb.size} RouterInfos, ${countFloodfills(node)} floodfills; bootstrapping ${targetOutboundPeers} peers\n`);
  process.stdout.write(`Local destination ${encodeDestinationBase64(destination.destination)}\n`);
  process.stdout.write(`${node.ssu2 ? 'SSU2, ' : ''}NTCP2, ECIES short tunnels, Garlic-N, LeaseSet2, reliable streaming, SAM, SOCKS, I2CP, and address-book subscriptions are enabled.\n`);
  const sam = args.has('no-sam') ? undefined : createNativeSamServer(node, { host: '127.0.0.1', port: portArg(args, 'sam-port', 7656) });
  if (sam) {
    const samAddr = await sam.listen();
    process.stdout.write(`Native SAM v3 listening on ${samAddr.address}:${samAddr.port}\n`);
  }
  const proxyHost = args.get('proxy-host') ?? '127.0.0.1';
  if (typeof proxyHost !== 'string' || !proxyHost.trim()) throw new Error('--proxy-host must not be empty');
  const proxy = args.has('no-proxy') ? undefined : createNativeHttpProxy({
    node, host: proxyHost, port: portArg(args, 'proxy-port', 4444),
    ...(typeof outproxy === 'string' ? { outproxy } : {}),
  });
  if (proxy) {
    await proxy.listen();
    const extra = typeof outproxy === 'string' ? `outproxy ${outproxy}` : 'http://*.i2p; addresshelper enabled';
    process.stdout.write(`Native HTTP proxy listening on ${proxyHost}:${portArg(args, 'proxy-port', 4444)} (${extra})\n`);
  }
  const socks = args.has('no-socks') ? undefined : createNativeSocksProxy({ node, host: '127.0.0.1', port: portArg(args, 'socks-port', 4447) });
  if (socks) {
    await socks.listen();
    process.stdout.write(`Native SOCKS proxy listening on 127.0.0.1:${portArg(args, 'socks-port', 4447)}\n`);
  }
  const consoleServer = args.has('no-console') ? undefined : createRouterConsole(node, { host: '127.0.0.1', port: portArg(args, 'console-port', 7070) });
  if (consoleServer) {
    await consoleServer.listen();
    process.stdout.write(`Router console listening on 127.0.0.1:${portArg(args, 'console-port', 7070)}\n`);
  }
  const i2cp = args.has('no-i2cp') ? undefined : createI2cpServer(node, { host: '127.0.0.1', port: portArg(args, 'i2cp-port', 7654) });
  if (i2cp) {
    const addr = await i2cp.listen();
    process.stdout.write(`Native I2CP listening on ${addr.address}:${addr.port}\n`);
  }
  const i2pcontrol = args.has('no-i2pcontrol') ? undefined : createI2pControlServer(node, { host: '127.0.0.1', port: portArg(args, 'i2pcontrol-port', 7650) });
  if (i2pcontrol) {
    await i2pcontrol.listen();
    process.stdout.write(`I2PControl JSON-RPC listening on 127.0.0.1:${portArg(args, 'i2pcontrol-port', 7650)}\n`);
  }
  let tunnelServices: { close: () => Promise<void> } | undefined;
  const tunnelsPath = args.get('tunnels');
  if (typeof tunnelsPath === 'string') {
    const parsed = parseTunnelsConf(await readFile(path.resolve(tunnelsPath), 'utf8'));
    tunnelServices = startTunnelServices(node, parsed);
    process.stdout.write(`Loaded ${parsed.length} tunnels from ${tunnelsPath}\n`);
  }
  node.on('bootstrapComplete', stats => {
    const status = node.status();
    process.stdout.write(`Peer bootstrap complete: ${stats.connected} connected (${status.ntcp2Peers} NTCP2, ${status.ssu2Peers} SSU2), ${stats.attempted} attempted, ${stats.failed} failed\n`);
    node.tunnelPool.start();
    void (async () => {
      // maintain() shares the run start() began; retry until the client pool has both directions.
      for (let attempt = 1; attempt <= 10 && !(node.tunnelPool.inbound.length && node.tunnelPool.outbound.length); attempt++) {
        await node.tunnelPool.maintain();
        if (!(node.tunnelPool.inbound.length && node.tunnelPool.outbound.length)) {
          process.stdout.write(`Tunnel pool incomplete after attempt ${attempt}; retrying in 10s\n`);
          await new Promise(resolve => setTimeout(resolve, 10_000));
        }
      }
    })().then(async () => {
      process.stdout.write(`Tunnel pool ready: ${node.tunnelPool.inbound.length} inbound, ${node.tunnelPool.outbound.length} outbound, ${node.tunnelPool.exploratoryOutbound.length}/${node.tunnelPool.exploratoryInbound.length} exploratory out/in\n`);
      await node.publishLocalLeaseSet();
      process.stdout.write('Published local LeaseSet2 to floodfills\n');
      const results = await node.refreshAddressBook();
      for (const result of results) {
        if (result.error) process.stderr.write(`address book ${result.host}${result.path}: ${result.error}\n`);
        else process.stdout.write(`address book ${result.host}${result.path}: imported ${result.imported} names (${node.hosts.size} total)\n`);
      }
      await writeFile(hostsPath, node.hosts.exportHostsTxt());
    }).catch(error => process.stderr.write(`tunnel pool: ${String(error)}\n`));
  });

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return; stopping = true;
    if (tunnelServices) await tunnelServices.close();
    if (i2pcontrol) await i2pcontrol.close();
    if (i2cp) await i2cp.close();
    if (consoleServer) await consoleServer.close();
    if (socks) await socks.close();
    if (proxy) await proxy.close();
    if (sam) await sam.close();
    await node.stop(); process.exitCode = 0;
  };
  process.once('SIGINT', () => { void shutdown().catch(error => { process.stderr.write(`${String(error)}\n`); process.exitCode = 1; }); });
  process.once('SIGTERM', () => { void shutdown().catch(error => { process.stderr.write(`${String(error)}\n`); process.exitCode = 1; }); });
}

/** 32-byte SSU2 intro key, persisted so the published "i" stays stable across restarts. */
async function loadOrCreateIntroKey(stateDir: string): Promise<Buffer> {
  const file = path.join(stateDir, 'ssu2.intro');
  try {
    const existing = await readFile(file);
    if (existing.length === 32) return existing;
    process.stderr.write(`${file} is not 32 bytes; regenerating\n`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const key = randomBytes(32);
  await writeFile(file, key, { mode: 0o600 });
  return key;
}

function countFloodfills(node: NativeRouterNode): number {
  return node.netDb.all().filter(info => (info.options.get('caps') ?? '').includes('f')).length;
}

function short(hash: Buffer | Uint8Array | undefined): string {
  return hash ? Buffer.from(hash).toString('hex').slice(0, 16) : '?';
}

/** Live-path diagnostics: what failed, where, and over which transport. */
function attachDiagnostics(node: NativeRouterNode): void {
  const log = (line: string): void => { process.stdout.write(`[diag] ${line}\n`); };
  node.on('dialFailure', (peer: Buffer, error: unknown) => log(`dial ${short(peer)} failed: ${error instanceof Error ? error.message : String(error)}`));
  node.on('observedAddress', (address: unknown, transport: string) => log(`${transport} peer observed our address as ${JSON.stringify(address)}`));
  node.on('searchReply', (reply: { key: Buffer; peers: Buffer[]; from: Buffer }) => log(`DatabaseSearchReply for ${short(reply.key)} from ${short(reply.from)}: ${reply.peers.map(short).join(',') || '(none)'}`));
  node.on('lookupSent', (info: { key: Buffer; floodfill: Buffer; outbound: Buffer; replyGateway: Buffer; replyTunnelId?: number }) => log(`LeaseSet lookup ${short(info.key)} -> floodfill ${short(info.floodfill)} via OBGW ${short(info.outbound)}, reply ${short(info.replyGateway)}:${info.replyTunnelId ?? 'direct'}`));
  node.on('tunnelTest', (result: { rttMs: number }) => log(`tunnel test ok rtt=${result.rttMs}ms`));
  node.on('tunnelError', (error: unknown) => log(`tunnel error: ${error instanceof Error ? error.message : String(error)}`));
  node.tunnelPool.on('buildError', (error: unknown) => log(`tunnel build failed: ${error instanceof Error ? error.message : String(error)}`));
  node.tunnelPool.on('testError', (error: unknown) => log(`tunnel test failed: ${error instanceof Error ? error.message : String(error)}`));
  for (const kind of ['outbound', 'inbound', 'exploratoryOutbound', 'exploratoryInbound'] as const) {
    node.tunnelPool.on(kind, (tunnel: { hops: { identityHash: Buffer }[] }) => log(`built ${kind} tunnel ${tunnel.hops.map(hop => short(hop.identityHash)).join(' -> ')}`));
  }
  if (node.ssu2) node.ssu2.on('handshakeError', (error: unknown) => log(`SSU2 handshake error: ${error instanceof Error ? error.message : String(error)}`));
  const timer = setInterval(() => {
    const status = node.status();
    log(`status peers=${status.peers} (ntcp2=${status.ntcp2Peers} ssu2=${status.ssu2Peers}) netDb=${status.netDb} floodfills=${countFloodfills(node)} tunnels in=${status.inboundTunnels} out=${status.outboundTunnels} expl=${node.tunnelPool.exploratoryOutbound.length}/${node.tunnelPool.exploratoryInbound.length} leaseSets=${status.leaseSets}`);
  }, 60_000);
  timer.unref();
}

function describeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause ? ` (cause: ${describeError(error.cause)})` : '';
  if (error instanceof AggregateError) return `${message}${cause}\n${error.errors.map(inner => `  - ${describeError(inner)}`).join('\n')}`;
  return `${message}${cause}`;
}

main().catch(error => {
  // Usage only helps for argument errors; runtime failures (reseed, bind) print their full reason chain.
  const argumentError = error instanceof RangeError || /option|argument|--[a-z]/i.test(error instanceof Error ? error.message : '');
  process.stderr.write(`${describeError(error)}\n${argumentError ? `\n${usage()}\n` : ''}`);
  process.exitCode = 1;
});
