import { createHash } from 'node:crypto';
import net from 'node:net';
import { ByteReader, encodeDate, encodeString } from './protocol/common.ts';
import { parseDestination, type DestinationKeys } from './protocol/destination.ts';
import type { HostsBook } from './netdb/hosts.ts';

export const I2CP_PROTOCOL_BYTE = 0x2a;
export const I2CP_VERSION = '0.9.64';
export const I2CP_NO_SESSION = 0xffff;

export const I2CP_CREATE_SESSION = 1;
export const I2CP_DESTROY_SESSION = 3;
export const I2CP_GET_BANDWIDTH_LIMITS = 8;
export const I2CP_SESSION_STATUS = 20;
export const I2CP_BANDWIDTH_LIMITS = 23;
export const I2CP_DISCONNECT = 30;
export const I2CP_GET_DATE = 32;
export const I2CP_SET_DATE = 33;
export const I2CP_DEST_LOOKUP = 34;
export const I2CP_DEST_REPLY = 35;
export const I2CP_HOST_LOOKUP = 38;
export const I2CP_HOST_REPLY = 39;

export const I2CP_SESSION_DESTROYED = 0;
export const I2CP_SESSION_CREATED = 1;
export const I2CP_SESSION_UPDATED = 2;
export const I2CP_SESSION_INVALID = 3;
export const I2CP_SESSION_REFUSED = 4;

export const I2CP_HOST_SUCCESS = 0;
export const I2CP_HOST_FAILURE = 1;

export type I2cpMessage = { type: number; body: Buffer };

export type I2cpRouter = {
  hosts: HostsBook;
  destinations: { local: DestinationKeys };
  status(): { running: boolean; peers: number; netDb: number; inboundTunnels: number; outboundTunnels: number };
  resolveName?(hostname: string, timeoutMs?: number): Promise<{ destination: Buffer; hash: Buffer }>;
};

const MAX_I2CP_BODY = 64 * 1024;

export function encodeI2cpMessage(type: number, body: Buffer = Buffer.alloc(0)): Buffer {
  if (!Number.isInteger(type) || type < 0 || type > 255) throw new RangeError('I2CP type must be a byte');
  if (!Buffer.isBuffer(body) || body.length > MAX_I2CP_BODY) throw new RangeError('I2CP body exceeds 64 KiB');
  const header = Buffer.allocUnsafe(5);
  header.writeUInt32BE(body.length, 0);
  header[4] = type;
  return Buffer.concat([header, body]);
}

export function decodeI2cpMessage(packet: Buffer): { message: I2cpMessage; rest: Buffer } | undefined {
  if (!Buffer.isBuffer(packet) || packet.length < 5) return undefined;
  const length = packet.readUInt32BE(0);
  if (length > MAX_I2CP_BODY) throw new Error('I2CP body exceeds 64 KiB');
  if (packet.length < 5 + length) return undefined;
  return {
    message: { type: packet[4]!, body: Buffer.from(packet.subarray(5, 5 + length)) },
    rest: Buffer.from(packet.subarray(5 + length)),
  };
}

export function encodeSetDate(now = Date.now(), version = I2CP_VERSION): Buffer {
  return encodeI2cpMessage(I2CP_SET_DATE, Buffer.concat([encodeDate(now), encodeString(version)]));
}

export function encodeSessionStatus(sessionId: number, status: number): Buffer {
  if (!Number.isInteger(sessionId) || sessionId < 0 || sessionId > 0xffff) throw new RangeError('sessionId must be a uint16');
  if (!Number.isInteger(status) || status < 0 || status > 255) throw new RangeError('status must be a byte');
  const body = Buffer.allocUnsafe(3);
  body.writeUInt16BE(sessionId, 0);
  body[2] = status;
  return encodeI2cpMessage(I2CP_SESSION_STATUS, body);
}

export function encodeHostReply(sessionId: number, requestId: number, result: number, destination?: Buffer): Buffer {
  const header = Buffer.allocUnsafe(7);
  header.writeUInt16BE(sessionId & 0xffff, 0);
  header.writeUInt32BE(requestId >>> 0, 2);
  header[6] = result;
  const dest = result === I2CP_HOST_SUCCESS && destination ? destination : Buffer.alloc(0);
  return encodeI2cpMessage(I2CP_HOST_REPLY, Buffer.concat([header, dest]));
}

export function encodeDestReply(destinationOrHash: Buffer): Buffer {
  return encodeI2cpMessage(I2CP_DEST_REPLY, destinationOrHash);
}

export function encodeDisconnect(reason: string): Buffer {
  return encodeI2cpMessage(I2CP_DISCONNECT, encodeString(reason));
}

export function encodeBandwidthLimits(inboundKBps = 512, outboundKBps = 512): Buffer {
  const body = Buffer.alloc(40);
  body.writeUInt32BE(inboundKBps >>> 0, 0);
  body.writeUInt32BE(outboundKBps >>> 0, 4);
  body.writeUInt32BE(inboundKBps >>> 0, 8);
  body.writeUInt32BE(10, 12);
  body.writeUInt32BE(outboundKBps >>> 0, 16);
  body.writeUInt32BE(10, 20);
  body.writeUInt32BE(0, 24);
  body.writeUInt32BE(0, 28);
  body.writeUInt32BE(inboundKBps >>> 0, 32);
  body.writeUInt32BE(outboundKBps >>> 0, 36);
  return encodeI2cpMessage(I2CP_BANDWIDTH_LIMITS, body);
}

export function parseGetDate(body: Buffer): { version?: string } {
  if (!body.length) return {};
  const reader = new ByteReader(body, MAX_I2CP_BODY);
  const version = reader.readString();
  return { version };
}

export function parseHostLookup(body: Buffer): { sessionId: number; requestId: number; timeoutMs: number; kind: number; hash?: Buffer; hostname?: string } {
  const reader = new ByteReader(body, MAX_I2CP_BODY);
  const sessionId = reader.readUInt16();
  const requestId = reader.readUInt32();
  const timeoutMs = reader.readUInt32();
  const kind = reader.readUInt8();
  if (kind === 0 || kind === 2) return { sessionId, requestId, timeoutMs, kind, hash: Buffer.from(reader.readHash()) };
  if (kind === 1 || kind === 3) return { sessionId, requestId, timeoutMs, kind, hostname: reader.readString() };
  throw new Error(`Unsupported HostLookup type ${kind}`);
}

export function parseDestLookup(body: Buffer): Buffer {
  if (!Buffer.isBuffer(body) || body.length !== 32) throw new Error('DestLookup hash must be 32 bytes');
  return Buffer.from(body);
}

export function parseDestroySession(body: Buffer): number {
  if (!Buffer.isBuffer(body) || body.length < 2) throw new Error('DestroySession is truncated');
  return body.readUInt16BE(0);
}

export function parseCreateSessionDestination(body: Buffer): Buffer {
  if (!Buffer.isBuffer(body) || body.length < 387) throw new Error('CreateSession config is truncated');
  const certificateLength = body.readUInt16BE(385);
  const destLength = 387 + certificateLength;
  if (body.length < destLength + 2 + 8 + 64) throw new Error('CreateSession config is truncated');
  return parseDestination(body.subarray(0, destLength)).destination;
}

/** Loopback I2CP subset: GetDate, HostLookup, DestLookup, CreateSession (local dest), bandwidth, disconnect. */
export function createI2cpServer(router: I2cpRouter, options: { host?: string; port?: number } = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 7654;
  const sockets = new Set<net.Socket>();
  let nextSessionId = 1;
  let sessionId: number | undefined;

  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    let buffer = Buffer.alloc(0);
    let sawProtocol = false;
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      void consume().catch(error => {
        socket.end(encodeDisconnect(error instanceof Error ? error.message : String(error)));
      });
    });

    async function consume(): Promise<void> {
      if (!sawProtocol) {
        if (!buffer.length) return;
        if (buffer[0] !== I2CP_PROTOCOL_BYTE) {
          socket.destroy();
          return;
        }
        sawProtocol = true;
        buffer = buffer.subarray(1);
      }
      while (true) {
        const decoded = decodeI2cpMessage(buffer);
        if (!decoded) return;
        buffer = Buffer.from(decoded.rest);
        const reply = await handle(decoded.message);
        if (reply) socket.write(reply);
      }
    }
  });

  async function handle(message: I2cpMessage) {
    switch (message.type) {
      case I2CP_GET_DATE:
        parseGetDate(message.body);
        return encodeSetDate();
      case I2CP_GET_BANDWIDTH_LIMITS:
        return encodeBandwidthLimits();
      case I2CP_DISCONNECT:
        return undefined;
      case I2CP_DESTROY_SESSION: {
        parseDestroySession(message.body);
        const id = sessionId ?? I2CP_NO_SESSION;
        sessionId = undefined;
        return encodeSessionStatus(id, I2CP_SESSION_DESTROYED);
      }
      case I2CP_CREATE_SESSION: {
        const destination = parseCreateSessionDestination(message.body);
        if (!destination.equals(router.destinations.local.destination)) {
          return encodeSessionStatus(I2CP_NO_SESSION, I2CP_SESSION_REFUSED);
        }
        sessionId = nextSessionId++ & 0xfffe || 1;
        return encodeSessionStatus(sessionId, I2CP_SESSION_CREATED);
      }
      case I2CP_DEST_LOOKUP: {
        const hash = parseDestLookup(message.body);
        const dest = lookupLocal(hash);
        return encodeDestReply(dest ?? hash);
      }
      case I2CP_HOST_LOOKUP: {
        const lookup = parseHostLookup(message.body);
        const found = await resolveLookup(lookup);
        return encodeHostReply(lookup.sessionId, lookup.requestId, found ? I2CP_HOST_SUCCESS : I2CP_HOST_FAILURE, found);
      }
      default:
        return encodeDisconnect(`Unsupported I2CP message type ${message.type}`);
    }
  }

  function lookupLocal(hash: Buffer): Buffer | undefined {
    if (hash.equals(router.destinations.local.destinationHash)) return router.destinations.local.destination;
    for (const name of router.hosts.namesList()) {
      const dest = router.hosts.get(name);
      if (dest && createHash('sha256').update(dest).digest().equals(hash)) return dest;
    }
    return undefined;
  }

  async function resolveLookup(lookup: { hash?: Buffer; hostname?: string; timeoutMs: number }): Promise<Buffer | undefined> {
    if (lookup.hash) return lookupLocal(lookup.hash);
    if (!lookup.hostname) return undefined;
    const known = router.hosts.resolve(lookup.hostname);
    if (known?.destination) return known.destination;
    if (router.resolveName) {
      try {
        const resolved = await router.resolveName(lookup.hostname, Math.min(lookup.timeoutMs || 8_000, 30_000));
        return resolved.destination;
      } catch {
        return undefined;
      }
    }
    return undefined;
  }

  return {
    server,
    listen: () => new Promise<net.AddressInfo>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server.address() as net.AddressInfo));
    }),
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}
