import net from 'node:net';
import type { RouterAddress, RouterInfo } from '../../protocol/router-info.ts';

/** Dialable SSU2 endpoint extracted from a RouterInfo. */
export type Ssu2Endpoint = {
  host: string;
  port: number;
  /** Bob's SSU2 static X25519 key (`s`). Not necessarily the RouterIdentity encryption key. */
  staticKey: Buffer;
  /** Bob's 32-byte SSU2 intro key (`i`); used for header protection and Token Request/Retry AEAD. */
  introKey: Buffer;
  mtu: number;
};

export const SSU2_DEFAULT_MTU = 1500;
export const SSU2_MIN_MTU = 1280;

export function i2pBase64Encode(value: Buffer): string {
  return value.toString('base64').replace(/\+/g, '-').replace(/\//g, '~');
}

export function i2pBase64Decode(value: string, expectedLength?: number): Buffer {
  if (!/^[A-Za-z0-9~-]+={0,2}$/.test(value)) throw new Error('Invalid I2P base64');
  const raw = value.replace(/=+$/, '');
  if (raw.length % 4 === 1) throw new Error('Invalid I2P base64 length');
  const result = Buffer.from(raw.replace(/-/g, '+').replace(/~/g, '/') + '='.repeat((4 - raw.length % 4) % 4), 'base64');
  if (expectedLength !== undefined && result.length !== expectedLength) throw new Error(`I2P base64 value must decode to ${expectedLength} bytes`);
  return result;
}

/** SSU2 is published as transport "SSU2"; older Java routers published "SSU" with v=2 during rollout. */
export function isSsu2Address(address: RouterAddress): boolean {
  if (address.transport === 'SSU2') return true;
  return address.transport === 'SSU' && address.options.get('v')?.split(',').includes('2') === true;
}

function decodeKey(address: RouterAddress, key: 's' | 'i'): Buffer | undefined {
  const value = address.options.get(key);
  if (!value) return undefined;
  try { return i2pBase64Decode(value, 32); } catch { return undefined; }
}

/** Returns the static and intro key of an SSU2 address even when it is unpublished (no host/port). */
export function ssu2Keys(address: RouterAddress): { staticKey: Buffer; introKey: Buffer } | undefined {
  if (!isSsu2Address(address)) return undefined;
  const staticKey = decodeKey(address, 's'); const introKey = decodeKey(address, 'i');
  if (!staticKey || !introKey) return undefined;
  return { staticKey, introKey };
}

/** Finds the SSU2 address whose `s` equals the static key Alice proved in Session Confirmed. */
export function findSsu2AddressByStaticKey(info: RouterInfo, staticKey: Buffer): { staticKey: Buffer; introKey: Buffer } | undefined {
  for (const address of info.addresses) {
    const keys = ssu2Keys(address);
    if (keys && keys.staticKey.equals(staticKey)) return keys;
  }
  return undefined;
}

/** Dialable IPv4 SSU2 endpoint (this implementation binds a udp4 socket). */
export function findSsu2Endpoint(info: RouterInfo, now = Date.now()): Ssu2Endpoint | undefined {
  const ordered = [...info.addresses].sort((a, b) => a.cost - b.cost);
  for (const address of ordered) {
    if (!isSsu2Address(address)) continue;
    if (address.expiration !== 0 && address.expiration <= now) continue;
    const host = address.options.get('host'); const port = Number(address.options.get('port'));
    if (!host || !net.isIPv4(host) || !Number.isInteger(port) || port < 1 || port > 65535) continue;
    const keys = ssu2Keys(address);
    if (!keys) continue;
    const mtuValue = Number(address.options.get('mtu') ?? SSU2_DEFAULT_MTU);
    const mtu = Number.isInteger(mtuValue) ? Math.max(SSU2_MIN_MTU, Math.min(SSU2_DEFAULT_MTU, mtuValue)) : SSU2_DEFAULT_MTU;
    return { host, port, staticKey: keys.staticKey, introKey: keys.introKey, mtu };
  }
  return undefined;
}

export function hasDialableSsu2(info: RouterInfo, now = Date.now()): boolean {
  return findSsu2Endpoint(info, now) !== undefined;
}

/** True when the RouterInfo has a published NTCP2 address we can dial (host, port, s, i, v=2). */
export function hasDialableNtcp2(info: RouterInfo, now = Date.now()): boolean {
  return info.addresses.some(address => {
    if (!['NTCP2', 'NTCP'].includes(address.transport) || (address.expiration !== 0 && address.expiration <= now)) return false;
    const options = address.options;
    const port = Number(options.get('port'));
    return Boolean(options.get('host')) && Boolean(options.get('s')) && Boolean(options.get('i'))
      && options.get('v')?.split(',').includes('2') === true && Number.isInteger(port) && port >= 1 && port <= 65535;
  });
}

export type Ssu2AddressOptions = {
  host?: string;
  port?: number;
  staticKey: Buffer;
  introKey: Buffer;
  cost?: number;
  mtu?: number;
  /** "4" (IPv4), "6", "B" (peer test), "C" (introducer). Only publish what is implemented. */
  caps?: string;
};

/** Builds the RouterAddress published in the local RouterInfo for SSU2. */
export function createSsu2Address(options: Ssu2AddressOptions): RouterAddress {
  if (options.staticKey.length !== 32 || options.introKey.length !== 32) throw new Error('SSU2 static and intro keys must be 32 bytes');
  const map = new Map<string, string>();
  if (options.caps) map.set('caps', options.caps);
  if (options.host !== undefined) {
    if (options.port === undefined || !Number.isInteger(options.port) || options.port < 1 || options.port > 65535) throw new RangeError('SSU2 port must be 1..65535');
    map.set('host', options.host);
  }
  map.set('i', i2pBase64Encode(options.introKey));
  if (options.mtu !== undefined && options.mtu !== SSU2_DEFAULT_MTU) map.set('mtu', String(options.mtu));
  if (options.host !== undefined) map.set('port', String(options.port));
  map.set('s', i2pBase64Encode(options.staticKey));
  map.set('v', '2');
  return { cost: options.cost ?? 3, expiration: 0, transport: 'SSU2', options: map };
}
