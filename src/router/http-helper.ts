import { isI2pHostname } from './http-client.ts';
import { decodeI2pBase64 } from './util/encoding.ts';

export type JumpService = {
  host: string;
  pathFor: (hostname: string) => string;
};

/** Jump destinations already present in the bootstrap hosts book. */
export const JUMP_SERVICES: readonly JumpService[] = [
  { host: 'i2pjump.i2p', pathFor: hostname => `/jump/${encodeURIComponent(hostname)}` },
  { host: 'notbob.i2p', pathFor: hostname => `/cgi-bin/jump.cgi?q=${encodeURIComponent(hostname)}` },
];

export type AddressHelperResult = {
  helper?: string;
  clean: URL;
};

/** Pulls `i2paddresshelper=` out of a proxy URL and returns the URL without that parameter. */
export function parseAddressHelper(url: URL): AddressHelperResult {
  const helper = url.searchParams.get('i2paddresshelper') ?? undefined;
  const clean = new URL(url.href);
  clean.searchParams.delete('i2paddresshelper');
  if (helper !== undefined && helper.length === 0) return { clean };
  return helper ? { helper, clean } : { clean };
}

export function destinationBytesFromHelper(helper: string): Buffer {
  const trimmed = helper.trim();
  if (!trimmed) throw new Error('Empty i2paddresshelper');
  const bytes = decodeI2pBase64(trimmed, undefined, 'i2paddresshelper');
  if (bytes.length < 387) throw new Error('i2paddresshelper destination is truncated');
  const certificateLength = bytes.readUInt16BE(385);
  if (certificateLength > 16_384 || bytes.length !== 387 + certificateLength) throw new Error('i2paddresshelper destination length is invalid');
  return bytes;
}

const HELPER_IN_QUERY = /(?:\?|&)i2paddresshelper=([A-Za-z0-9~=-]+)/i;
const HELPER_IN_BODY = /i2paddresshelper=([A-Za-z0-9~=-]+)/i;

/** Reads an addresshelper dest from a jump-service Location header or HTML body. */
export function extractHelperDestination(locationOrBody: string): string | undefined {
  const fromQuery = HELPER_IN_QUERY.exec(locationOrBody);
  if (fromQuery?.[1]) return fromQuery[1];
  const fromBody = HELPER_IN_BODY.exec(locationOrBody);
  return fromBody?.[1];
}

export function isClearnetHostname(hostname: string): boolean {
  if (!hostname) return false;
  return !isI2pHostname(hostname) && hostname.toLowerCase() !== 'localhost';
}
