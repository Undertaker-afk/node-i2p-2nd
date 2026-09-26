const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { LineSocket, parseReply } = require('../src/sam');

test('parses SAM reply fields', () => {
  assert.deepEqual(parseReply('NAMING REPLY RESULT=OK VALUE=abc\n').fields, { RESULT: 'OK', VALUE: 'abc' });
});
test('LineSocket preserves bytes received beyond protocol line', async () => {
  const server = net.createServer(s => s.write(Buffer.concat([Buffer.from('STREAM STATUS RESULT=OK\n'), Buffer.from([0, 255, 10])])));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const s = net.createConnection(server.address().port, '127.0.0.1');
  await new Promise(r => s.once('connect', r));
  const lines = new LineSocket(s);
  assert.equal(await lines.readLine(), 'STREAM STATUS RESULT=OK');
  lines.detach();
  const payload = await new Promise((resolve, reject) => { s.once('data', resolve); s.once('error', reject); });
  assert.deepEqual(payload, Buffer.from([0, 255, 10])); s.destroy(); server.close();
});
