#!/usr/bin/env node
import { SamClient } from './sam.ts';
import { createProxy } from './proxy.ts';

async function main(): Promise<void> {
  const sam = new SamClient({ host: process.env.I2P_SAM_HOST || '127.0.0.1', port: Number(process.env.I2P_SAM_PORT || 7656) });
  const proxy = createProxy({ sam, host: process.env.I2P_PROXY_HOST || '127.0.0.1', port: Number(process.env.I2P_PROXY_PORT || 4444) });
  await sam.start(); await proxy.listen();
  console.log(`I2P HTTP proxy listening on ${process.env.I2P_PROXY_HOST || '127.0.0.1'}:${process.env.I2P_PROXY_PORT || 4444}`);
  console.log(`SAM router: ${process.env.I2P_SAM_HOST || '127.0.0.1'}:${process.env.I2P_SAM_PORT || 7656}`);
  console.log('Restricted to .i2p destinations. Keep this proxy bound to loopback unless access is controlled.');
  let stopping = false;
  const stop = async () => { if (stopping) return; stopping = true; await proxy.close(); };
  process.once('SIGINT', () => { void stop(); }); process.once('SIGTERM', () => { void stop(); });
}
main().catch(error => { console.error(`Unable to start I2P client: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
