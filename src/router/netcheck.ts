#!/usr/bin/env node
/**
 * Network reachability check for running a public I2P router.
 *
 *   npm run netcheck [-- --port 12345 --ssu-port 12345]
 *
 * Probes, in order:
 *   1. DNS + HTTPS to the reseed servers (bootstrap needs one signed i2pseeds.su3)
 *   2. UDP egress via STUN binding requests (SSU2 needs outbound UDP and replies)
 *   3. TCP interception: a connect to TEST-NET-1 192.0.2.1:9 must NOT succeed; if it does,
 *      a transparent proxy is terminating TCP and NTCP2 handshakes cannot reach real peers
 *   4. Local bind of the NTCP2 TCP port and SSU2 UDP port on 0.0.0.0
 * Exit code 0 = no blocker found, 2 = at least one blocker.
 */
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { DEFAULT_RESEED_URLS } from './netdb/reseed.ts';

type Probe = { name: string; ok: boolean; detail: string };

const TIMEOUT_MS = 6_000;

function httpsProbe(url: string): Promise<Probe> {
  return new Promise(resolve => {
    const started = Date.now();
    const request = https.request(url, { method: 'HEAD', timeout: TIMEOUT_MS, headers: { 'user-agent': 'Wget/1.11.4' } }, response => {
      response.resume();
      resolve({ name: `HTTPS ${url}`, ok: true, detail: `HTTP ${response.statusCode} in ${Date.now() - started}ms` });
    });
    request.on('timeout', () => request.destroy(new Error(`timeout after ${TIMEOUT_MS}ms`)));
    request.on('error', error => resolve({ name: `HTTPS ${url}`, ok: false, detail: error.message }));
    request.end();
  });
}

function stunProbe(host: string, port: number): Promise<Probe> {
  return new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    const transaction = randomBytes(12);
    const request = Buffer.concat([Buffer.from([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]), transaction]);
    const name = `UDP STUN ${host}:${port}`;
    const timer = setTimeout(() => { socket.close(); resolve({ name, ok: false, detail: `no reply in ${TIMEOUT_MS}ms (outbound UDP filtered?)` }); }, TIMEOUT_MS);
    socket.on('message', message => {
      if (message.length < 20 || !message.subarray(8, 20).equals(transaction)) return;
      clearTimeout(timer); socket.close();
      resolve({ name, ok: true, detail: `reply; mapped address ${parseMappedAddress(message) ?? 'unparsed'}` });
    });
    socket.on('error', error => { clearTimeout(timer); socket.close(); resolve({ name, ok: false, detail: error.message }); });
    socket.send(request, port, host);
  });
}

function parseMappedAddress(message: Buffer): string | undefined {
  let offset = 20;
  while (offset + 4 <= message.length) {
    const type = message.readUInt16BE(offset); const length = message.readUInt16BE(offset + 2);
    const value = message.subarray(offset + 4, offset + 4 + length);
    if ((type === 0x0020 || type === 0x0001) && value.length >= 8 && value[1] === 1) {
      const xor = type === 0x0020;
      const port = value.readUInt16BE(2) ^ (xor ? 0x2112 : 0);
      const ip = [...value.subarray(4, 8)].map((byte, index) => byte ^ (xor ? [0x21, 0x12, 0xa4, 0x42][index]! : 0));
      return `${ip.join('.')}:${port}`;
    }
    offset += 4 + length + ((4 - (length % 4)) % 4);
  }
  return undefined;
}

function tcpInterceptProbe(): Promise<Probe> {
  return new Promise(resolve => {
    const name = 'TCP interception (192.0.2.1:9 must be unreachable)';
    const started = Date.now();
    const socket = net.connect({ host: '192.0.2.1', port: 9, timeout: 3_000 });
    socket.once('connect', () => {
      socket.destroy();
      resolve({ name, ok: false, detail: `connected in ${Date.now() - started}ms to a non-routable address: a transparent proxy terminates outbound TCP, NTCP2 cannot reach peers` });
    });
    socket.once('timeout', () => { socket.destroy(); resolve({ name, ok: true, detail: 'timed out as expected (no interception)' }); });
    socket.once('error', error => resolve({ name, ok: true, detail: `refused/unreachable as expected (${(error as NodeJS.ErrnoException).code ?? error.message})` }));
  });
}

function bindProbe(kind: 'tcp' | 'udp', port: number): Promise<Probe> {
  return new Promise(resolve => {
    const name = `bind 0.0.0.0:${port}/${kind}`;
    if (kind === 'tcp') {
      const server = net.createServer();
      server.once('error', error => resolve({ name, ok: false, detail: error.message }));
      server.listen(port, '0.0.0.0', () => server.close(() => resolve({ name, ok: true, detail: 'ok (inbound reachability must still be allowed by firewall/NAT)' })));
    } else {
      const socket = dgram.createSocket('udp4');
      socket.once('error', error => { socket.close(); resolve({ name, ok: false, detail: error.message }); });
      socket.bind(port, '0.0.0.0', () => socket.close(() => resolve({ name, ok: true, detail: 'ok (inbound reachability must still be allowed by firewall/NAT)' })));
    }
  });
}

async function dnsProbe(host: string): Promise<Probe> {
  try {
    const addresses = await dns.lookup(host, { all: true });
    return { name: `DNS ${host}`, ok: true, detail: addresses.map(entry => entry.address).join(', ') };
  } catch (error) {
    return { name: `DNS ${host}`, ok: false, detail: error instanceof Error ? error.message : String(error) };
  }
}

function argPort(argv: string[], key: string, fallback: number): number {
  const index = argv.indexOf(`--${key}`);
  const value = index >= 0 ? Number(argv[index + 1]) : fallback;
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new RangeError(`--${key} must be 1..65535`);
  return value;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const port = argPort(argv, 'port', 12345);
  const ssuPort = argPort(argv, 'ssu-port', port);
  const reseeds = DEFAULT_RESEED_URLS.slice(0, 4);
  const probes: Probe[] = [];
  const print = (probe: Probe): void => { probes.push(probe); process.stdout.write(`${probe.ok ? 'PASS' : 'FAIL'}  ${probe.name}: ${probe.detail}\n`); };

  for (const url of reseeds) print(await dnsProbe(new URL(url).hostname));
  for (const probe of await Promise.all(reseeds.map(url => httpsProbe(url)))) print(probe);
  for (const probe of await Promise.all([stunProbe('stun.l.google.com', 19302), stunProbe('stun.cloudflare.com', 3478)])) print(probe);
  print(await tcpInterceptProbe());
  print(await bindProbe('tcp', port));
  print(await bindProbe('udp', ssuPort));

  const reseedOk = probes.some(probe => probe.name.startsWith('HTTPS') && probe.ok);
  const udpOk = probes.some(probe => probe.name.startsWith('UDP') && probe.ok);
  const tcpOk = probes.find(probe => probe.name.startsWith('TCP interception'))!.ok;
  const blockers: string[] = [];
  if (!reseedOk) blockers.push('no reseed server reachable over HTTPS (use --reseed-file <i2pseeds.su3> or a persisted netDb)');
  if (!udpOk) blockers.push('outbound UDP gets no replies: SSU2 cannot work');
  if (!tcpOk) blockers.push('outbound TCP is intercepted: NTCP2 cannot work');
  if (!udpOk && !tcpOk) blockers.push('neither transport can reach I2P peers from this network');
  process.stdout.write(blockers.length ? `\nBLOCKED:\n${blockers.map(line => `  - ${line}`).join('\n')}\n` : '\nNo blocker detected. Remember to allow inbound TCP and UDP on the published ports.\n');
  process.exitCode = blockers.length ? 2 : 0;
}

main().catch(error => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
