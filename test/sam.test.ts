import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { LineSocket, parseReply, SamClient } from '../src/sam.ts';

test('parses SAM reply fields', () => {
  assert.deepEqual(parseReply('NAMING REPLY RESULT=OK VALUE=abc\n').fields, { RESULT: 'OK', VALUE: 'abc' });
});
test('LineSocket preserves bytes received beyond protocol line', async () => {
  const server = net.createServer(socket => socket.write(Buffer.concat([Buffer.from('STREAM STATUS RESULT=OK\n'), Buffer.from([0, 255, 10])])));
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert(address && typeof address !== 'string');
  const socket = net.createConnection(address.port, '127.0.0.1'); await new Promise<void>(resolve => socket.once('connect', resolve));
  const lines = new LineSocket(socket); assert.equal(await lines.readLine(), 'STREAM STATUS RESULT=OK'); lines.detach();
  const payload = await new Promise<Buffer>((resolve, reject) => { socket.once('data', resolve); socket.once('error', reject); });
  assert.deepEqual(payload, Buffer.from([0, 255, 10])); socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve()));
});
test('rejects invalid hostnames, prevents SAM command injection', async () => {
  const sam = new SamClient();
  await assert.rejects(sam.lookup('example.com'), /valid .i2p/);
  await assert.rejects(sam.lookup('x.i2p\nSESSION REMOVE'), /valid .i2p/);
  assert.throws(() => new SamClient({ port: 70000 }), /port/);
});
test('SAM startup, lookup and stream connection use expected protocol', async () => {
  const server = net.createServer(socket => {
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString();
      while (buffer.includes('\n')) {
        const index = buffer.indexOf('\n'); const line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
        if (line.startsWith('HELLO')) socket.write('HELLO REPLY RESULT=OK VERSION=3.3\n');
        else if (line.startsWith('SESSION CREATE')) socket.write('SESSION STATUS RESULT=OK DESTINATION=local-dest\n');
        else if (line.startsWith('NAMING LOOKUP')) socket.write('NAMING REPLY RESULT=OK VALUE=remote-dest\n');
        else if (line.startsWith('STREAM CONNECT')) socket.write('STREAM STATUS RESULT=OK\n');
        else if (line.startsWith('SESSION REMOVE')) socket.end();
      }
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert(address && typeof address !== 'string');
  const sam = new SamClient({ host: '127.0.0.1', port: address.port });
  try {
    await sam.start(); assert.equal(sam.destination, 'local-dest');
    assert.equal(await sam.lookup('Example.i2p'), 'remote-dest');
    const stream = await sam.connect('remote-dest'); stream.destroy();
  } finally { await sam.close(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
