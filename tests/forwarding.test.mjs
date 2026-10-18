import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { createWebhookForwarder, MAX_WEBHOOK_BYTES } from '../src/commands/listen.ts';
import { fixture, json } from './helpers.mjs';

async function forwarder(t, destination) {
  const forwarder = createWebhookForwarder(destination);
  const server = createServer(forwarder.handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    await forwarder.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

test('forwarding preserves signed body bytes and verification headers without forwarding authorization', async t => {
  const body = '{ "type": "recording.uploaded",\n "data": {"name":"音声"} }\n';
  const timestamp = '1792285200';
  const signature = createHmac('sha256', 'fixture-secret').update(`${timestamp}.${body}`).digest('hex');
  const destination = await fixture(t, (req, res) => {
    assert.equal(req.body, body);
    assert.equal(req.headers['x-bota-signature'], `v1=${signature}`);
    assert.equal(req.headers['x-bota-timestamp'], timestamp);
    assert.equal(req.headers['x-bota-event-id'], 'evt_fixture');
    assert.equal(req.headers.authorization, undefined);
    const expected = createHmac('sha256', 'fixture-secret').update(`${req.headers['x-bota-timestamp']}.${req.body}`).digest('hex');
    assert.equal(req.headers['x-bota-signature'], `v1=${expected}`);
    json(res, { accepted: true });
  });
  const url = await forwarder(t, destination.url);
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bota-Signature': `v1=${signature}`, 'X-Bota-Timestamp': timestamp, 'X-Bota-Event-Id': 'evt_fixture', Authorization: 'Bearer sk_test_not_for_receiver' }, body });
  assert.equal(response.status, 200);
  assert.equal(destination.requests.length, 1);
});

test('forwarding propagates receiver failure as a failed delivery without retrying', async t => {
  const destination = await fixture(t, (_req, res) => json(res, { error: 'signature rejected' }, 403));
  const url = await forwarder(t, destination.url);
  const response = await fetch(url, { method: 'POST', body: '{"type":"recording.uploaded"}' });
  assert.equal(response.status, 502);
  assert.equal(destination.requests.length, 1);
});

test('forwarding rejects oversized bodies and non-POST requests without contacting the receiver', async t => {
  const destination = await fixture(t, (_req, res) => json(res, { accepted: true }));
  const url = await forwarder(t, destination.url);
  const response = await fetch(url, { method: 'POST', body: 'x'.repeat(MAX_WEBHOOK_BYTES + 1) });
  assert.equal(response.status, 413);
  assert.equal((await fetch(url)).status, 405);
  assert.equal(destination.requests.length, 0);
});

test('forwarding does not follow receiver redirects', async t => {
  const redirected = await fixture(t, (_req, res) => json(res, { accepted: true }));
  const destination = await fixture(t, (_req, res) => { res.writeHead(307, { Location: redirected.url }); res.end(); });
  const url = await forwarder(t, destination.url);
  assert.equal((await fetch(url, { method: 'POST', body: '{}' })).status, 502);
  assert.equal(destination.requests.length, 1);
  assert.equal(redirected.requests.length, 0);
});
