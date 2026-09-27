#!/usr/bin/env node
/**
 * Private SSU2 mini-network for exercising the real router CLI end to end without internet access.
 *
 *   npm run mininet            # run the acceptance request once and exit 0/1
 *   npm run mininet -- --keep  # keep everything running for manual `curl -x http://127.0.0.1:14444 http://notbob.i2p/hosts.txt`
 *
 * Topology (all on 127.0.0.1, netId 2):
 *   - 10 in-process SSU2-only NativeRouterNodes (no NTCP2 address at all), 2 of them floodfills
 *   - CLI router "B": publishes NTCP2+SSU2, serves its local destination via a tunnels.conf server tunnel
 *     pointing at a local HTTP server that returns a hosts.txt body
 *   - CLI router "A": HTTP proxy on 14444, hosts.txt maps notbob.i2p -> B's destination
 * The request goes A proxy -> LeaseSet lookup at a floodfill through exploratory tunnels -> A outbound
 * tunnel -> B inbound tunnel -> streaming -> B's HTTP server, every router-to-router hop over SSU2.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createRouterIdentity } from '../src/router/identity.ts';
import { loadOrCreateDestinationKeys } from '../src/router/destination-store.ts';
import { PersistentRouterInfoStore } from '../src/router/netdb/persistent-store.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { NativeRouterNode } from '../src/router/node.ts';
import { createRouterInfoRecord, parseRouterInfo } from '../src/router/protocol/router-info.ts';
import { encodeDestinationBase64 } from '../src/router/protocol/destination.ts';
import { createSsu2Address } from '../src/router/transport/ssu2/address.ts';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const keep = process.argv.includes('--keep');
const ROUTERS = 10;
const FLOODFILLS = 2;
const BASE_PORT = 24100;
const PROXY_PORT = 14444;
const HTTP_PORT = 18099;
const HOSTS_BODY = 'notbob.i2p=placeholder\nmininet.i2p=served-over-ssu2\n';
const root = path.join(process.env.TMPDIR ?? '/tmp', 'i2p-mininet');

function log(line: string): void { process.stdout.write(`[mininet] ${line}\n`); }

async function startNetwork(): Promise<{ nodes: NativeRouterNode[]; infos: Buffer[] }> {
  const routers = Array.from({ length: ROUTERS }, (_, index) => {
    const identity = createRouterIdentity(); const introKey = randomBytes(32); const port = BASE_PORT + index;
    const floodfill = index < FLOODFILLS;
    const address = createSsu2Address({ host: '127.0.0.1', port, staticKey: identity.identity.subarray(0, 32), introKey, caps: '4' });
    const info = createRouterInfoRecord(identity, Date.now(), [address], new Map([
      ['caps', floodfill ? 'fR' : 'NR'], ['netId', '2'], ['router.version', '0.9.64'],
    ]));
    return { identity, introKey, port, floodfill, info };
  });
  const nodes: NativeRouterNode[] = [];
  for (const router of routers) {
    const store = new VerifiedRouterInfoStore();
    for (const other of routers) store.store(parseRouterInfo(other.info));
    const node = new NativeRouterNode({
      identity: router.identity, routerInfo: router.info, netDb: store, host: '127.0.0.1',
      // NTCP2 listener still binds (node requirement) but is not published: peers can only use SSU2.
      port: router.port + 1000, publishedIv: randomBytes(16), autoBootstrap: false, floodfill: router.floodfill,
      ssu2: { port: router.port, introKey: router.introKey, host: '127.0.0.1' },
    });
    node.on('tunnelError', () => undefined); node.on('netDbError', () => undefined); node.on('transportError', () => undefined);
    await node.start();
    nodes.push(node);
  }
  log(`${ROUTERS} SSU2-only routers up on udp ${BASE_PORT}..${BASE_PORT + ROUTERS - 1} (${FLOODFILLS} floodfills)`);
  return { nodes, infos: routers.map(router => router.info) };
}

async function seedState(dir: string, infos: Buffer[]): Promise<void> {
  await mkdir(dir, { recursive: true });
  const store = await PersistentRouterInfoStore.open(path.join(dir, 'netDb'), { expectedNetId: '2' });
  for (const info of infos) await store.store(parseRouterInfo(info));
}

function spawnCli(name: string, args: string[], onLine: (line: string) => void): ChildProcess {
  const child = spawn(process.execPath, ['--experimental-strip-types', path.join(repo, 'src/router-cli.ts'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  for (const stream of [child.stdout!, child.stderr!]) {
    let buffered = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
      buffered += chunk;
      let newline: number;
      while ((newline = buffered.indexOf('\n')) >= 0) {
        const line = buffered.slice(0, newline); buffered = buffered.slice(newline + 1);
        process.stdout.write(`  ${name} | ${line}\n`);
        onLine(line);
      }
    });
  }
  return child;
}

function waitFor(predicate: () => boolean, ms: number, label: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      if (predicate()) { clearInterval(timer); resolve(); }
      else if (Date.now() - started > ms) { clearInterval(timer); reject(new Error(`timed out waiting for ${label}`)); }
    }, 250);
  });
}

function proxyGet(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = http.request({ host: '127.0.0.1', port: PROXY_PORT, method: 'GET', path: url, headers: { host: target.host } }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode ?? 0, body }));
    });
    request.setTimeout(90_000, () => request.destroy(new Error('proxy request timed out')));
    request.on('error', reject);
    request.end();
  });
}

async function main(): Promise<void> {
  await rm(root, { recursive: true, force: true });
  const dirA = path.join(root, 'A'); const dirB = path.join(root, 'B');
  const { nodes, infos } = await startNetwork();
  await seedState(dirA, infos); await seedState(dirB, infos);

  const site = http.createServer((request, response) => {
    log(`B's web server got ${request.method} ${request.url}`);
    response.writeHead(request.url === '/hosts.txt' ? 200 : 404, { 'content-type': 'text/plain' });
    response.end(request.url === '/hosts.txt' ? HOSTS_BODY : 'not found\n');
  });
  await new Promise<void>(resolve => site.listen(HTTP_PORT, '127.0.0.1', () => resolve()));

  const destinationB = await loadOrCreateDestinationKeys(dirB);
  await writeFile(path.join(dirA, 'hosts.txt'), `notbob.i2p=${encodeDestinationBase64(destinationB.destination)}\n`);
  await writeFile(path.join(dirB, 'tunnels.conf'), `[notbob]\ntype = http\nhost = 127.0.0.1\nport = ${HTTP_PORT}\n`);

  const common = ['--public-host', '127.0.0.1', '--peers', String(ROUTERS), '--no-console', '--no-i2cp', '--no-i2pcontrol', '--no-socks'];
  let bPublished = false; let aReady = false;
  const children: ChildProcess[] = [];
  children.push(spawnCli('B', [...common, '--port', '24201', '--state-dir', dirB, '--no-proxy', '--no-sam', '--tunnels', path.join(dirB, 'tunnels.conf')], line => {
    if (line.includes('Published local LeaseSet2')) bPublished = true;
  }));
  children.push(spawnCli('A', [...common, '--port', '24202', '--state-dir', dirA, '--proxy-port', String(PROXY_PORT), '--sam-port', '17656'], line => {
    if (line.includes('Tunnel pool ready')) aReady = true;
  }));

  let exitCode = 1;
  const shutdown = async (): Promise<void> => {
    for (const child of children) child.kill('SIGTERM');
    await new Promise(resolve => setTimeout(resolve, 500));
    for (const node of nodes) await node.stop().catch(() => undefined);
    site.close();
  };
  try {
    await waitFor(() => bPublished && aReady, 120_000, 'B LeaseSet publish and A tunnel pool');
    log('both CLI routers ready; requesting http://notbob.i2p/hosts.txt through A\'s proxy');
    const started = Date.now();
    const result = await proxyGet('http://notbob.i2p/hosts.txt');
    log(`HTTP ${result.status} in ${Date.now() - started}ms, body ${JSON.stringify(result.body)}`);
    exitCode = result.status === 200 && result.body === HOSTS_BODY ? 0 : 1;
    log(exitCode === 0 ? 'PASS: acceptance request succeeded over the SSU2 mini-network' : 'FAIL: unexpected response');
  } catch (error) {
    log(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (keep) {
    log(`--keep: running. Try: curl -x http://127.0.0.1:${PROXY_PORT} http://notbob.i2p/hosts.txt  (Ctrl-C to stop)`);
    process.once('SIGINT', () => { void shutdown().then(() => process.exit(exitCode)); });
    process.once('SIGTERM', () => { void shutdown().then(() => process.exit(exitCode)); });
    return;
  }
  await shutdown();
  process.exit(exitCode);
}

main().catch(error => { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exit(1); });
