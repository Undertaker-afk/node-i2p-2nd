import test from 'node:test';
import assert from 'node:assert/strict';
import { createRouterConfig } from '../src/router/config.ts';
import { RouterCore, type RouterComponent } from '../src/router/core.ts';

function component(name: string, events: string[], failStart = false): RouterComponent {
  return {
    name,
    async start() { events.push(`start:${name}`); if (failStart) throw new Error(`failed ${name}`); },
    async stop() { events.push(`stop:${name}`); },
  };
}

test('router config applies safe defaults and rejects invalid limits', () => {
  const config = createRouterConfig();
  assert.equal(config.listenHost, '127.0.0.1');
  assert.equal(config.listenPort, 7657);
  assert.ok(config.stateDir.startsWith('/'));
  assert.throws(() => createRouterConfig({ listenPort: 65536 }), /listenPort/);
  assert.throws(() => createRouterConfig({ maxPeers: 0 }), /maxPeers/);
  assert.throws(() => createRouterConfig({ listenHost: '0.0.0.0\nunsafe' }), /listenHost/);
});

test('router lifecycle starts in order and stops in reverse order idempotently', async () => {
  const events: string[] = [];
  const router = new RouterCore(createRouterConfig(), [component('transport', events), component('netdb', events)]);
  await Promise.all([router.start(), router.start()]);
  assert.equal(router.status().state, 'running');
  await router.stop(); await router.stop();
  assert.deepEqual(events, ['start:transport', 'start:netdb', 'stop:netdb', 'stop:transport']);
  assert.equal(router.status().state, 'stopped');
});

test('startup failure rolls back already started components', async () => {
  const events: string[] = [];
  const router = new RouterCore(createRouterConfig(), [component('transport', events), component('tunnel', events, true)]);
  await assert.rejects(router.start(), /failed tunnel/);
  assert.deepEqual(events, ['start:transport', 'start:tunnel', 'stop:transport']);
  assert.equal(router.status().state, 'failed');
});
