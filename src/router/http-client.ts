import { EventEmitter } from 'node:events';
import { Duplex } from 'node:stream';
import type { DestinationStream } from './destination-session.ts';

export type HttpResponse = {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: Buffer;
  raw: Buffer;
};

const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

export type StreamLike = {
  write(payload: Buffer): Promise<void>;
  on(event: string, listener: (...args: any[]) => void): unknown;
  off(event: string, listener: (...args: any[]) => void): unknown;
};

function headerValue(headers: Map<string, string>, name: string): string | undefined {
  return headers.get(name.toLowerCase());
}

function parseHeaders(headerBlock: string): { status: number; statusText: string; headers: Map<string, string> } {
  const lines = headerBlock.split('\r\n');
  const statusLine = lines[0] ?? '';
  const match = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(statusLine);
  if (!match) throw new Error(`Invalid HTTP status line: ${statusLine.slice(0, 80)}`);
  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 1) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    const existing = headers.get(name);
    headers.set(name, existing ? `${existing}, ${value}` : value);
  }
  return { status: Number(match[1]), statusText: match[2]?.trim() ?? '', headers };
}

function decodeChunked(body: Buffer): { complete: boolean; decoded: Buffer } {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const end = body.indexOf('\r\n', offset);
    if (end < 0) return { complete: false, decoded: Buffer.concat(chunks) };
    const sizeLine = body.subarray(offset, end).toString('ascii');
    const size = Number.parseInt(sizeLine.split(';', 1)[0] ?? '', 16);
    if (!Number.isInteger(size) || size < 0) throw new Error('Invalid HTTP chunk size');
    const dataStart = end + 2;
    if (size === 0) {
      const trailerEnd = body.indexOf('\r\n', dataStart);
      if (trailerEnd < 0) return { complete: false, decoded: Buffer.concat(chunks) };
      return { complete: true, decoded: Buffer.concat(chunks) };
    }
    if (dataStart + size + 2 > body.length) return { complete: false, decoded: Buffer.concat(chunks) };
    chunks.push(body.subarray(dataStart, dataStart + size));
    if (body[dataStart + size] !== 13 || body[dataStart + size + 1] !== 10) throw new Error('Invalid HTTP chunk terminator');
    offset = dataStart + size + 2;
  }
  return { complete: false, decoded: Buffer.concat(chunks) };
}

/** Returns a parsed response when headers and body are complete; otherwise undefined. */
export function tryParseHttpResponse(raw: Buffer): HttpResponse | undefined {
  if (!Buffer.isBuffer(raw) || raw.length === 0) return undefined;
  const split = raw.indexOf('\r\n\r\n');
  if (split < 0) return undefined;
  const headerBlock = raw.subarray(0, split).toString('latin1');
  const body = raw.subarray(split + 4);
  const parsed = parseHeaders(headerBlock);
  const encoding = headerValue(parsed.headers, 'transfer-encoding')?.toLowerCase() ?? '';
  if (encoding.includes('chunked')) {
    const chunked = decodeChunked(body);
    if (!chunked.complete) return undefined;
    return { ...parsed, body: chunked.decoded, raw };
  }
  const lengthHeader = headerValue(parsed.headers, 'content-length');
  if (lengthHeader !== undefined) {
    const length = Number(lengthHeader);
    if (!Number.isInteger(length) || length < 0) throw new Error('Invalid Content-Length');
    if (body.length < length) return undefined;
    return { ...parsed, body: body.subarray(0, length), raw };
  }
  return undefined;
}

export function parseHttpResponse(raw: Buffer, { allowClose = true } = {}): HttpResponse {
  const complete = tryParseHttpResponse(raw);
  if (complete) return complete;
  const split = raw.indexOf('\r\n\r\n');
  if (split < 0) throw new Error('HTTP response is missing a header terminator');
  if (!allowClose) throw new Error('HTTP response body is incomplete');
  const parsed = parseHeaders(raw.subarray(0, split).toString('latin1'));
  return { ...parsed, body: raw.subarray(split + 4), raw };
}

export async function httpGetOverStream(
  stream: StreamLike,
  options: { host: string; path: string; extraHeaders?: Record<string, string>; timeoutMs?: number },
): Promise<HttpResponse> {
  const path = options.path.startsWith('/') ? options.path : `/${options.path}`;
  const headerLines = [
    `GET ${path} HTTP/1.1`,
    `Host: ${options.host}`,
    'User-Agent: node-i2p-native/1.1',
    'Accept: */*',
    'Connection: close',
  ];
  for (const [name, value] of Object.entries(options.extraHeaders ?? {})) headerLines.push(`${name}: ${value}`);
  const request = Buffer.from(`${headerLines.join('\r\n')}\r\n\r\n`);
  const timeoutMs = options.timeoutMs ?? 120_000;
  const chunks: Buffer[] = [];
  return new Promise<HttpResponse>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('close', onClose);
      stream.off('error', onError);
      try { fn(); } catch (error) { reject(error instanceof Error ? error : new Error(String(error))); }
    };
    const onData = (payload: Buffer) => {
      chunks.push(payload);
      const raw = Buffer.concat(chunks);
      if (raw.length > MAX_RESPONSE_BYTES) {
        finish(() => { throw new Error('HTTP response exceeds 16 MiB'); });
        return;
      }
      try {
        const parsed = tryParseHttpResponse(raw);
        if (parsed) finish(() => resolve(parsed));
      } catch (error) { finish(() => { throw error; }); }
    };
    const onClose = () => {
      finish(() => resolve(parseHttpResponse(Buffer.concat(chunks))));
    };
    const onError = (error: Error) => {
      finish(() => { throw error; });
    };
    const timer = setTimeout(() => finish(() => { throw new Error(`HTTP GET ${options.host}${path} timed out`); }), timeoutMs);
    stream.on('data', onData);
    stream.on('close', onClose);
    stream.on('error', onError);
    void stream.write(request).catch(error => onError(error instanceof Error ? error : new Error(String(error))));
  });
}

type HttpSocket = Duplex & {
  setTimeout(ms: number, callback?: () => void): HttpSocket;
  setNoDelay(value?: boolean): HttpSocket;
  setKeepAlive(enable?: boolean, initialDelay?: number): HttpSocket;
};

/** Adapts a destination stream so Node's HTTP client can treat it like a socket. */
export function wrapDestinationStream(stream: DestinationStream): HttpSocket {
  const duplex = new Duplex({
    allowHalfOpen: false,
    write(chunk, encoding, callback) {
      const payload = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string, encoding as BufferEncoding);
      stream.write(payload).then(() => callback(), error => callback(error instanceof Error ? error : new Error(String(error))));
    },
    final(callback) {
      stream.close().then(() => callback(), error => callback(error instanceof Error ? error : new Error(String(error))));
    },
    read() { /* push-driven from destination data events */ },
  }) as HttpSocket;
  const onData = (payload: Buffer): void => { duplex.push(payload); };
  const onClose = (): void => { duplex.push(null); };
  const onError = (error: Error): void => { duplex.destroy(error); };
  stream.on('data', onData);
  stream.on('close', onClose);
  stream.on('error', onError);
  duplex.setTimeout = (ms: number, callback?: () => void) => {
    if (ms > 0 && callback) duplex.once('timeout', callback);
    return duplex;
  };
  duplex.setNoDelay = () => duplex;
  duplex.setKeepAlive = () => duplex;
  duplex.once('close', () => {
    stream.off('data', onData);
    stream.off('close', onClose);
    stream.off('error', onError);
  });
  return duplex;
}

export function isI2pHostname(hostname: string): boolean {
  return hostname.toLowerCase().endsWith('.i2p');
}
