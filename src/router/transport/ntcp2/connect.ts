import net from 'node:net';
import { randomBytes, randomInt } from 'node:crypto';
import type { RouterIdentityKeys } from '../../identity.ts';
import { parseRouterInfo, verifyRouterInfoSignature, type RouterInfo } from '../../protocol/router-info.ts';
import { createSessionConfirmed, createSessionRequest, processSessionCreated, readSessionCreatedPaddingLength } from './handshake.ts';
import { Ntcp2Connection } from './connection.ts';
import { Ntcp2DataCipher } from './data-cipher.ts';

export type Ntcp2ConnectOptions = { networkId?: number; timeoutMs?: number; maxClockSkewSeconds?: number; initialPadding?: Buffer };
type PeerEndpoint = { host: string; port: number; staticKey: Buffer; iv: Buffer };

function decodeI2pBase64(value: string, expectedLength: number, field: string): Buffer {
  const match = /^([A-Za-z0-9~-]+)(={0,2})$/.exec(value);
  if (!match) throw new Error(`Invalid ${field} I2P base64`);
  const raw = match[1]!; const suppliedPadding = match[2]!.length;
  const requiredPadding = (4 - raw.length % 4) % 4;
  if (requiredPadding === 3 || (suppliedPadding !== 0 && suppliedPadding !== requiredPadding)) throw new Error(`Invalid ${field} I2P base64 padding`);
  const normalized = raw.replace(/-/g, '+').replace(/~/g, '/') + '='.repeat(requiredPadding);
  const result = Buffer.from(normalized, 'base64');
  if (result.length !== expectedLength) throw new Error(`${field} must decode to ${expectedLength} bytes`);
  return result;
}

function normalizeHost(value: string): string {
  if (net.isIP(value)) return value;
  const raw = decodeI2pBase64(value, 16, 'IPv6 host');
  const groups: string[] = [];
  for (let index = 0; index < 16; index += 2) groups.push(raw.readUInt16BE(index).toString(16));
  return groups.join(':');
}

function findNtcp2Endpoint(info: RouterInfo): PeerEndpoint {
  const ordered = [...info.addresses].sort((a, b) => (a.transport === 'NTCP2' ? 0 : 1) - (b.transport === 'NTCP2' ? 0 : 1));
  for (const address of ordered) {
    const options = address.options;
    if (address.transport !== 'NTCP2' && address.transport !== 'NTCP') continue;
    if (!options.get('v')?.split(',').includes('2')) continue;
    const hostValue = options.get('host'); const portValue = options.get('port');
    const staticValue = options.get('s'); const ivValue = options.get('i');
    if (!hostValue || !portValue || !staticValue || !ivValue) continue;
    const port = Number(portValue);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    return { host: normalizeHost(hostValue), port, staticKey: decodeI2pBase64(staticValue, 32, 'NTCP2 static key'), iv: decodeI2pBase64(ivValue, 16, 'NTCP2 IV') };
  }
  throw new Error('RouterInfo contains no usable NTCP2 address');
}

async function writeAll(socket: net.Socket, data: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => socket.write(data, error => error ? reject(error) : resolve()));
}

async function readExactly(socket: net.Socket, length: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let received = 0; let settled = false;
    const finish = (error?: Error, result?: Buffer) => {
      if (settled) return; settled = true; clearTimeout(timer);
      socket.removeListener('data', onData); socket.removeListener('error', onError); socket.removeListener('end', onEnd); socket.removeListener('close', onClose);
      if (error) reject(error); else resolve(result!);
    };
    const onError = (error: Error) => finish(error);
    const onEnd = () => finish(new Error('NTCP2 peer ended during handshake'));
    const onClose = () => finish(new Error('NTCP2 peer closed during handshake'));
    const onData = (chunk: Buffer) => {
      const needed = length - received;
      if (chunk.length < needed) { chunks.push(Buffer.from(chunk)); received += chunk.length; return; }
      const selected = Buffer.from(chunk.subarray(0, needed));
      const result = Buffer.concat([...chunks, selected], length);
      const extra = chunk.subarray(needed);
      socket.pause();
      if (extra.length) socket.unshift(extra);
      finish(undefined, result);
    };
    const timer = setTimeout(() => finish(new Error('Timed out waiting for NTCP2 handshake bytes')), timeoutMs);
    socket.on('data', onData); socket.once('error', onError); socket.once('end', onEnd); socket.once('close', onClose);
    socket.resume();
  });
}

/** Opens an outbound TCP connection and performs the NTCP2 XK initiator handshake. */
export async function connectNtcp2(
  remoteRouterInfoBytes: Buffer,
  localIdentity: RouterIdentityKeys,
  localRouterInfoBytes: Buffer,
  options: Ntcp2ConnectOptions = {},
): Promise<Ntcp2Connection> {
  const remoteInfo = parseRouterInfo(remoteRouterInfoBytes);
  if (!verifyRouterInfoSignature(remoteInfo)) throw new Error('Remote RouterInfo signature is invalid');
  const networkId = options.networkId ?? 2;
  if (remoteInfo.options.get('netId') !== String(networkId)) throw new Error('Remote RouterInfo belongs to another or unspecified network');
  const endpoint = findNtcp2Endpoint(remoteInfo);
  const localInfo = parseRouterInfo(localRouterInfoBytes);
  if (!verifyRouterInfoSignature(localInfo) || !localInfo.identity.equals(localIdentity.identity) || !localInfo.identityHash.equals(localIdentity.identityHash)) throw new Error('Local RouterInfo does not match the local identity');
  if (localInfo.options.get('netId') !== String(networkId)) throw new Error('Local RouterInfo network ID does not match configured network');
  const timeoutMs = options.timeoutMs ?? 15_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000) throw new RangeError('timeoutMs must be between 100 and 300000');
  const part2Length = localRouterInfoBytes.length + 4 + 16;
  const padding = options.initialPadding ?? randomBytes(randomInt(0, 65));
  const state = createSessionRequest({
    networkId, publishedRouterHash: remoteInfo.identityHash, publishedIv: endpoint.iv,
    publishedStaticKey: endpoint.staticKey, message3Part2Length: part2Length, padding,
  });

  const socket = net.createConnection({ host: endpoint.host, port: endpoint.port });
  socket.setNoDelay(true); socket.setTimeout(timeoutMs, () => socket.destroy(new Error('NTCP2 connection timed out')));
  try {
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    await writeAll(socket, state.message);
    const responseHeader = await readExactly(socket, 64, timeoutMs);
    const paddingLength = readSessionCreatedPaddingLength(state, responseHeader);
    const responsePadding = paddingLength ? await readExactly(socket, paddingLength, timeoutMs) : Buffer.alloc(0);
    const afterMessage2 = processSessionCreated(state, Buffer.concat([responseHeader, responsePadding]), options.maxClockSkewSeconds === undefined ? {} : { maxClockSkewSeconds: options.maxClockSkewSeconds });
    const established = createSessionConfirmed(afterMessage2, localIdentity, localRouterInfoBytes);
    await writeAll(socket, established.sessionConfirmedCiphertext!);
    if (!established.sendKey || !established.receiveKey || !established.sendLengthKeys || !established.receiveLengthKeys) throw new Error('NTCP2 data keys were not established');
    const cipher = new Ntcp2DataCipher(established.sendKey, established.receiveKey, established.sendLengthKeys, established.receiveLengthKeys);
    established.sendKey.fill(0); established.receiveKey.fill(0);
    for (const keys of [established.sendLengthKeys, established.receiveLengthKeys]) { keys.key1.fill(0); keys.key2.fill(0); keys.iv.fill(0); }
    socket.setTimeout(0);
    return new Ntcp2Connection(socket, cipher, undefined, remoteInfo.identityHash);
  } catch (error) {
    socket.destroy();
    throw error;
  }
}
