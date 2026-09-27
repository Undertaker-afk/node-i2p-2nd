import { chacha20 } from '../../crypto/x25519.ts';

/** SSU2 long header is 32 bytes; short header is 16 bytes. See https://i2p.net/en/docs/specs/ssu2/ */
export const SSU2_LONG_HEADER_LENGTH = 32;
export const SSU2_SHORT_HEADER_LENGTH = 16;
export const SSU2_VERSION = 2;
export const SSU2_MAC_LENGTH = 16;
export const SSU2_EPHEMERAL_LENGTH = 32;
export const SSU2_MIN_PACKET = 40;

export const SSU2_SESSION_REQUEST = 0;
export const SSU2_SESSION_CREATED = 1;
export const SSU2_SESSION_CONFIRMED = 2;
export const SSU2_DATA = 6;
export const SSU2_PEER_TEST = 7;
export const SSU2_RETRY = 9;
export const SSU2_TOKEN_REQUEST = 10;
export const SSU2_HOLE_PUNCH = 11;

export type Ssu2LongHeader = {
  destConnId: Buffer;
  packetNumber: number;
  type: number;
  version: number;
  netId: number;
  flag: number;
  srcConnId: Buffer;
  token: Buffer;
};

export type Ssu2ShortHeader = {
  destConnId: Buffer;
  packetNumber: number;
  type: number;
  flag: number;
  moreFlags: number;
};

export type Ssu2HeaderProtectionKind = 'session-request' | 'retry' | 'short';

function assertConnId(value: Buffer, name: string): void {
  if (!Buffer.isBuffer(value) || value.length !== 8) throw new Error(`${name} must be 8 bytes`);
}

function assertPacketNumber(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new RangeError('packet number must be a uint32');
}

function assertKey(key: Buffer, name: string): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error(`${name} must be 32 bytes`);
}

/** Encodes the 32-byte cleartext long header used before a session exists. */
export function encodeSsu2LongHeader(header: Ssu2LongHeader): Buffer {
  assertConnId(header.destConnId, 'destConnId');
  assertConnId(header.srcConnId, 'srcConnId');
  if (!Buffer.isBuffer(header.token) || header.token.length !== 8) throw new Error('token must be 8 bytes');
  assertPacketNumber(header.packetNumber);
  if (!Number.isInteger(header.type) || header.type < 0 || header.type > 255) throw new RangeError('type must be a byte');
  if (header.version !== SSU2_VERSION) throw new RangeError('SSU2 version must be 2');
  if (!Number.isInteger(header.netId) || header.netId < 1 || header.netId > 255) throw new RangeError('netId must be a uint8');
  if (!Number.isInteger(header.flag) || header.flag < 0 || header.flag > 255) throw new RangeError('flag must be a byte');
  const bytes = Buffer.allocUnsafe(SSU2_LONG_HEADER_LENGTH);
  header.destConnId.copy(bytes, 0);
  bytes.writeUInt32BE(header.packetNumber >>> 0, 8);
  bytes[12] = header.type;
  bytes[13] = header.version;
  bytes[14] = header.netId;
  bytes[15] = header.flag;
  header.srcConnId.copy(bytes, 16);
  header.token.copy(bytes, 24);
  return bytes;
}

export function decodeSsu2LongHeader(bytes: Buffer): Ssu2LongHeader {
  if (!Buffer.isBuffer(bytes) || bytes.length < SSU2_LONG_HEADER_LENGTH) throw new Error('SSU2 long header must be 32 bytes');
  const version = bytes[13]!;
  if (version !== SSU2_VERSION) throw new Error(`Unsupported SSU2 version ${version}`);
  return {
    destConnId: Buffer.from(bytes.subarray(0, 8)),
    packetNumber: bytes.readUInt32BE(8),
    type: bytes[12]!,
    version,
    netId: bytes[14]!,
    flag: bytes[15]!,
    srcConnId: Buffer.from(bytes.subarray(16, 24)),
    token: Buffer.from(bytes.subarray(24, 32)),
  };
}

export function encodeSsu2ShortHeader(header: Ssu2ShortHeader): Buffer {
  assertConnId(header.destConnId, 'destConnId');
  assertPacketNumber(header.packetNumber);
  if (!Number.isInteger(header.type) || header.type < 0 || header.type > 255) throw new RangeError('type must be a byte');
  if (!Number.isInteger(header.flag) || header.flag < 0 || header.flag > 255) throw new RangeError('flag must be a byte');
  if (!Number.isInteger(header.moreFlags) || header.moreFlags < 0 || header.moreFlags > 0xffff) throw new RangeError('moreFlags must be a uint16');
  const bytes = Buffer.allocUnsafe(SSU2_SHORT_HEADER_LENGTH);
  header.destConnId.copy(bytes, 0);
  bytes.writeUInt32BE(header.packetNumber >>> 0, 8);
  bytes[12] = header.type;
  bytes[13] = header.flag;
  bytes.writeUInt16BE(header.moreFlags, 14);
  return bytes;
}

export function decodeSsu2ShortHeader(bytes: Buffer): Ssu2ShortHeader {
  if (!Buffer.isBuffer(bytes) || bytes.length < SSU2_SHORT_HEADER_LENGTH) throw new Error('SSU2 short header must be 16 bytes');
  return {
    destConnId: Buffer.from(bytes.subarray(0, 8)),
    packetNumber: bytes.readUInt32BE(8),
    type: bytes[12]!,
    flag: bytes[13]!,
    moreFlags: bytes.readUInt16BE(14),
  };
}

/**
 * Applies SSU2 header protection in place-copy.
 * SessionRequest/Created also ChaCha the 16-byte remainder of the long header plus the 32-byte ephemeral key.
 */
export function protectSsu2Header(packet: Buffer, kHeader1: Buffer, kHeader2: Buffer, kind: Ssu2HeaderProtectionKind): Buffer {
  assertKey(kHeader1, 'k_header_1');
  assertKey(kHeader2, 'k_header_2');
  if (!Buffer.isBuffer(packet) || packet.length < SSU2_MIN_PACKET) throw new Error('SSU2 packet is truncated');
  const out = Buffer.from(packet);
  if (kind === 'session-request') {
    if (out.length < 64 + SSU2_MAC_LENGTH) throw new Error('SessionRequest packet must include header, ephemeral key, payload, and MAC');
    chacha20(kHeader2, Buffer.alloc(12), out.subarray(16, 64), 0).copy(out, 16);
  } else if (kind === 'retry') {
    chacha20(kHeader2, Buffer.alloc(12), out.subarray(16, 32), 0).copy(out, 16);
  }
  xorHeaderMasks(out, kHeader1, kHeader2);
  return out;
}

export function unprotectSsu2Header(packet: Buffer, kHeader1: Buffer, kHeader2: Buffer, kind: Ssu2HeaderProtectionKind): Buffer {
  assertKey(kHeader1, 'k_header_1');
  assertKey(kHeader2, 'k_header_2');
  if (!Buffer.isBuffer(packet) || packet.length < SSU2_MIN_PACKET) throw new Error('SSU2 packet is truncated');
  const out = Buffer.from(packet);
  xorHeaderMasks(out, kHeader1, kHeader2);
  if (kind === 'session-request') {
    if (out.length < 64 + SSU2_MAC_LENGTH) throw new Error('SessionRequest packet must include header, ephemeral key, payload, and MAC');
    chacha20(kHeader2, Buffer.alloc(12), out.subarray(16, 64), 0).copy(out, 16);
  } else if (kind === 'retry') {
    chacha20(kHeader2, Buffer.alloc(12), out.subarray(16, 32), 0).copy(out, 16);
  }
  return out;
}

function xorHeaderMasks(packet: Buffer, kHeader1: Buffer, kHeader2: Buffer): void {
  const len = packet.length;
  const iv1 = packet.subarray(len - 24, len - 12);
  const mask1 = chacha20(kHeader1, iv1, Buffer.alloc(8), 0);
  const iv2 = packet.subarray(len - 12, len);
  const mask2 = chacha20(kHeader2, iv2, Buffer.alloc(8), 0);
  for (let index = 0; index < 8; index++) {
    packet[index]! ^= mask1[index]!;
    packet[8 + index]! ^= mask2[index]!;
  }
}

export function isLongHeaderType(type: number): boolean {
  return type === SSU2_SESSION_REQUEST || type === SSU2_SESSION_CREATED || type === SSU2_PEER_TEST
    || type === SSU2_RETRY || type === SSU2_TOKEN_REQUEST || type === SSU2_HOLE_PUNCH;
}
