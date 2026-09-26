import net from 'node:net';
import { randomUUID } from 'node:crypto';

export type SamOptions = { host?: string; port?: number; sessionId?: string; nickname?: string; timeoutMs?: number };
export type SamReply = { parts: string[]; fields: Record<string, string> };

export class LineSocket {
  private buffer = Buffer.alloc(0);
  private waiters: Array<{ resolve: (line: string) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }> = [];
  private error: Error | null = null;
  private readonly onData: (chunk: Buffer) => void;
  readonly socket: net.Socket;
  constructor(socket: net.Socket) {
    this.socket = socket;
    this.onData = chunk => { this.buffer = Buffer.concat([this.buffer, chunk]); this.flush(); };
    socket.on('data', this.onData);
    socket.on('error', error => { this.error = error; this.flush(); });
    socket.on('close', () => { this.error ??= new Error('SAM connection closed'); this.flush(); });
  }
  private flush(): void {
    while (this.waiters.length && (this.buffer.includes(10) || this.error)) {
      const waiter = this.waiters.shift()!;
      if (this.buffer.includes(10)) {
        const index = this.buffer.indexOf(10);
        const line = this.buffer.subarray(0, index).toString('utf8').replace(/\r$/, '');
        this.buffer = this.buffer.subarray(index + 1); clearTimeout(waiter.timer); waiter.resolve(line);
      } else { clearTimeout(waiter.timer); waiter.reject(this.error!); }
    }
  }
  readLine(timeoutMs = 15_000): Promise<string> {
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: setTimeout(() => { this.waiters = this.waiters.filter(item => item !== waiter); reject(new Error('Timed out waiting for SAM response')); }, timeoutMs) };
      this.waiters.push(waiter); this.flush();
    });
  }
  detach(): void { this.socket.removeListener('data', this.onData); if (this.buffer.length) this.socket.unshift(this.buffer); this.buffer = Buffer.alloc(0); }
}

export function parseReply(line: string): SamReply {
  const parts = line.trim().split(/\s+/); const fields: Record<string, string> = {};
  for (const item of parts.slice(2)) { const index = item.indexOf('='); if (index > 0) fields[item.slice(0, index)] = item.slice(index + 1); }
  return { parts, fields };
}
function checkReply(line: string, command: string): SamReply {
  const reply = parseReply(line);
  if (reply.parts[0] !== command || reply.fields.RESULT !== 'OK') throw new Error(`SAM ${command} failed: ${line}`);
  return reply;
}
function token(value: string): string {
  if (!value || /[\s\r\n"\\]/.test(value)) throw new Error('Invalid SAM token');
  return value;
}

export class SamClient {
  readonly host: string; readonly port: number; readonly sessionId: string; readonly nickname: string; readonly timeoutMs: number;
  private session: net.Socket | null = null; private lines: LineSocket | null = null; private started = false;
  destination: string | undefined;
  constructor(options: SamOptions = {}) {
    this.host = options.host ?? '127.0.0.1'; this.port = options.port ?? 7656;
    this.sessionId = options.sessionId ?? `node-${process.pid}-${randomUUID().slice(0, 8)}`;
    this.nickname = options.nickname ?? 'NodeI2P'; this.timeoutMs = options.timeoutMs ?? 15_000;
    if (!Number.isInteger(this.port) || this.port < 1 || this.port > 65535) throw new Error('SAM port must be between 1 and 65535');
  }
  private async open(): Promise<net.Socket> {
    const socket = net.createConnection({ host: this.host, port: this.port });
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    return socket;
  }
  async start(): Promise<this> {
    if (this.started) return this;
    const socket = await this.open(); this.session = socket; this.lines = new LineSocket(socket);
    socket.write('HELLO VERSION MIN=3.0 MAX=3.3\n');
    const hello = await this.lines.readLine(this.timeoutMs);
    if (!hello.startsWith('HELLO REPLY') || !hello.includes('RESULT=OK')) { socket.destroy(); throw new Error(`SAM handshake failed: ${hello}`); }
    socket.write(`SESSION CREATE STYLE=STREAM ID=${token(this.sessionId)} DESTINATION=TRANSIENT\n`);
    const reply = checkReply(await this.lines.readLine(this.timeoutMs), 'SESSION');
    this.destination = reply.fields.DESTINATION; this.started = true; return this;
  }
  async lookup(name: string): Promise<string> {
    const normalized = name.toLowerCase().replace(/\.$/, '');
    if (!/^(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)*\.i2p$/.test(normalized)) throw new Error('Only valid .i2p hostnames are supported');
    const socket = await this.open(); const lines = new LineSocket(socket);
    try {
      socket.write(`NAMING LOOKUP NAME=${token(normalized)}\n`);
      const reply = checkReply(await lines.readLine(this.timeoutMs), 'NAMING'); const destination = reply.fields.VALUE;
      if (!destination || destination === 'TRANSIENT' || destination === 'ME') throw new Error(`SAM returned no destination for ${normalized}`);
      return destination;
    } finally { socket.destroy(); }
  }
  async connect(destination: string): Promise<net.Socket> {
    if (!this.started) throw new Error('SAM client is not started');
    const socket = await this.open(); const lines = new LineSocket(socket);
    socket.write(`STREAM CONNECT ID=${token(this.sessionId)} DESTINATION=${token(destination)} SILENT=false\n`);
    try { checkReply(await lines.readLine(this.timeoutMs), 'STREAM'); lines.detach(); return socket; }
    catch (error) { socket.destroy(); throw error; }
  }
  async close(): Promise<void> {
    if (!this.session) return;
    const session = this.session; this.session = null; this.started = false;
    session.write(`SESSION REMOVE ID=${token(this.sessionId)}\n`); session.end(); this.lines = null;
  }
}
