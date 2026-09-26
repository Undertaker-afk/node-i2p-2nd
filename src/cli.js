'use strict';
const { SamClient } = require('./sam');
const { createProxy } = require('./proxy');
async function main() {
  const sam = new SamClient({ host: process.env.I2P_SAM_HOST || '127.0.0.1', port: Number(process.env.I2P_SAM_PORT || 7656) });
  const proxy = createProxy({ sam, host: process.env.I2P_PROXY_HOST || '0.0.0.0', port: Number(process.env.I2P_PROXY_PORT || 4444) });
  await sam.start(); await proxy.listen();
  console.log(`I2P HTTP proxy listening on ${process.env.I2P_PROXY_HOST || '0.0.0.0'}:${process.env.I2P_PROXY_PORT || 4444}`);
  console.log(`SAM router: ${process.env.I2P_SAM_HOST || '127.0.0.1'}:${process.env.I2P_SAM_PORT || 7656}`);
  console.log('Configure your browser HTTP proxy to this address; requests are restricted to .i2p destinations.');
  const stop = async () => { await proxy.close(); process.exit(0); }; process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
main().catch(e => { console.error(`Unable to start I2P client: ${e.message}`); process.exitCode = 1; });
