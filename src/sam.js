'use strict';
const net = require('node:net');
const { randomUUID } = require('node:crypto');

class LineSocket {
  constructor(socket) { this.socket = socket; this.buffer = Buffer.alloc(0); this.waiters = []; this.error = null;
    this.onData = chunk => { this.buffer = Buffer.concat([this.buffer, chunk]); this._flush(); };
    socket.on('data', this.onData);
    socket.on('error', err => { this.error = err; this._flush(); });
    socket.on('close', () => { this.error ||= new Error('SAM connection closed'); this._flush(); });
  }
  _flush() { while (this.waiters.length && (this.buffer.includes(10) || this.error)) {
    const w = this.waiters.shift();
    if (this.buffer.includes(10)) { const i = this.buffer.indexOf(10); const line = this.buffer.subarray(0, i).toString('utf8').replace(/\r$/, ''); this.buffer = this.buffer.subarray(i + 1); w.resolve(line); }
    else w.reject(this.error);
  } }
  detach() { this.socket.removeListener('data', this.onData); if (this.buffer.length) this.socket.unshift(this.buffer); this.buffer = Buffer.alloc(0); }
  readLine(timeout = 15000) { return new Promise((resolve, reject) => { const timer = setTimeout(() => { this.waiters = this.waiters.filter(x => x !== w); reject(new Error('Timed out waiting for SAM response')); }, timeout); const w = { resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); } }; this.waiters.push(w); this._flush(); }); }
}
function parseReply(line) { const parts = line.trim().split(/\s+/); const fields = {}; for (const p of parts.slice(2)) { const i = p.indexOf('='); if (i > 0) fields[p.slice(0, i)] = p.slice(i + 1); } return { parts, fields }; }
function checkReply(line, command) { const r = parseReply(line); if (r.parts[0] !== command || r.fields.RESULT !== 'OK') throw new Error(`SAM ${command} failed: ${line}`); return r; }
function quote(v) { return String(v).replace(/[\\"\r\n]/g, ''); }

class SamClient {
  constructor({ host = '127.0.0.1', port = 7656, sessionId = `node-${process.pid}-${randomUUID().slice(0, 8)}`, nickname = 'NodeI2P' } = {}) { this.host = host; this.port = port; this.sessionId = sessionId; this.nickname = nickname; }
  async _connect() { const socket = net.createConnection({ host: this.host, port: this.port }); await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); }); return socket; }
  async start() {
    this.session = await this._connect(); this.lines = new LineSocket(this.session);
    this.session.write('HELLO VERSION MIN=3.0 MAX=3.3\n');
    const hello = await this.lines.readLine(); if (!hello.startsWith('HELLO REPLY') || !hello.includes('RESULT=OK')) throw new Error(`SAM handshake failed: ${hello}`);
    this.session.write(`SESSION CREATE STYLE=STREAM ID=${quote(this.sessionId)} DESTINATION=TRANSIENT
`);
    const reply = checkReply(await this.lines.readLine(), 'SESSION'); this.destination = reply.fields.DESTINATION;
    return this;
  }
  async lookup(name) {
    if (!name.endsWith('.i2p')) throw new Error('Only .i2p destinations are supported');
    const socket = await this._connect(); const lines = new LineSocket(socket);
    try { socket.write(`NAMING LOOKUP NAME=${quote(name)}\n`); const r = checkReply(await lines.readLine(), 'NAMING'); const dest = r.fields.VALUE;
      if (!dest || dest === 'TRANSIENT' || dest === 'ME') throw new Error(`SAM returned no destination for ${name}`); return dest;
    } finally { socket.destroy(); }
  }
  async connect(destination, options = {}) {
    const socket = await this._connect(); const lines = new LineSocket(socket);
    socket.write(`STREAM CONNECT ID=${quote(this.sessionId)} DESTINATION=${quote(destination)} SILENT=false${options.from ? ` FROM_PORT=${options.from}` : ''}\n`);
    try { const r = checkReply(await lines.readLine(), 'STREAM'); lines.detach(); return socket; } catch (e) { socket.destroy(); throw e; }
  }
  async close() { if (this.session) { this.session.write(`SESSION REMOVE ID=${quote(this.sessionId)}\n`); this.session.end(); this.session = null; } }
}
module.exports = { SamClient, LineSocket, parseReply };
