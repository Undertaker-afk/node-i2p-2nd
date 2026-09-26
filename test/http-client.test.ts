import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { httpGetOverStream, parseHttpResponse, tryParseHttpResponse } from '../src/router/http-client.ts';
import { ADDRESS_BOOK_SUBSCRIPTIONS, BOOTSTRAP_HOSTS, HostsBook } from '../src/router/netdb/hosts.ts';
import { encodeI2pBase64 } from '../src/router/util/encoding.ts';

test('HTTP parser handles Content-Length and chunked bodies', () => {
  const length = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloTRAILING');
  const parsed = parseHttpResponse(length);
  assert.equal(parsed.status, 200);
  assert.equal(parsed.body.toString(), 'hello');
  assert.equal(tryParseHttpResponse(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel')), undefined);
  const chunked = Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n');
  assert.equal(parseHttpResponse(chunked).body.toString(), 'hello');
  assert.equal(tryParseHttpResponse(Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel')), undefined);
});

test('httpGetOverStream writes a GET and parses the response', async () => {
  const stream = new EventEmitter() as EventEmitter & { write(payload: Buffer): Promise<void> };
  let request: Buffer | undefined;
  stream.write = async (payload: Buffer) => {
    request = payload;
    queueMicrotask(() => {
      stream.emit('data', Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nnotbob=hello'));
    });
  };
  const response = await httpGetOverStream(stream, { host: 'notbob.i2p', path: '/hosts.txt' });
  assert.ok(request?.includes(Buffer.from('GET /hosts.txt HTTP/1.1')));
  assert.ok(request?.includes(Buffer.from('Host: notbob.i2p')));
  assert.equal(response.status, 200);
  assert.equal(response.body.toString(), 'notbob=hello');
});

test('bootstrap hosts include notbob, identiguy, stats, and subscription URLs', () => {
  const book = new HostsBook();
  for (const name of ['notbob.i2p', 'identiguy.i2p', 'stats.i2p', 'i2p-projekt.i2p', 'inr.i2p']) {
    const dest = book.get(name);
    assert.ok(dest, name);
    assert.ok(dest!.length >= 387, name);
    assert.equal(BOOTSTRAP_HOSTS[name], encodeI2pBase64(dest!));
  }
  assert.ok(ADDRESS_BOOK_SUBSCRIPTIONS.some(item => item.host === 'notbob.i2p' && item.path === '/hosts.txt'));
  assert.ok(ADDRESS_BOOK_SUBSCRIPTIONS.some(item => item.host === 'identiguy.i2p'));
  const exported = book.exportHostsTxt();
  const other = new HostsBook();
  assert.ok(other.importHostsTxt(exported) >= 0);
  assert.deepEqual(other.get('notbob.i2p'), book.get('notbob.i2p'));
});
