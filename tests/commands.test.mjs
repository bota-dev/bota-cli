import assert from 'node:assert/strict';
import test from 'node:test';
import { fixture, json, runCli } from './helpers.mjs';

test('summarize maps the existing template alias to the backend template_id', async t => {
  const api = await fixture(t, (req, res) => {
    if (req.url.startsWith('/v1/transcriptions?')) return json(res, { data: [{ id: 'txn_one', status: 'completed' }] });
    assert.equal(req.url, '/v1/summaries');
    assert.deepEqual(JSON.parse(req.body), { transcription_id: 'txn_one', template_id: 'tmpl_general_notes', provider: 'openai' });
    json(res, { id: 'sum_one', status: 'pending' }, 201);
  });
  const result = await runCli(t, api.url, ['recordings', 'summarize', 'rec_one', '--template', 'general_notes', '--provider', 'openai', '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { id: 'sum_one', status: 'pending' });
  assert.equal(api.requests.filter(req => req.method === 'POST').length, 1);
});

test('summarize accepts a custom prompt and rejects ambiguous/missing selection before a request', async t => {
  const api = await fixture(t, (req, res) => {
    if (req.method === 'GET') return json(res, { data: [{ id: 'txn_one' }] });
    assert.deepEqual(JSON.parse(req.body), { transcription_id: 'txn_one', prompt: 'Summarize the agreed next steps.' });
    json(res, { id: 'sum_one', status: 'pending' }, 201);
  });
  const valid = await runCli(t, api.url, ['recordings', 'summarize', 'rec_one', '--prompt', 'Summarize the agreed next steps.', '--json']);
  assert.equal(valid.code, 0, valid.stderr);
  const count = api.requests.length;
  for (const flags of [[], ['--template', 'general_notes', '--prompt', 'Summarize the agreed next steps.']]) {
    const invalid = await runCli(t, api.url, ['recordings', 'summarize', 'rec_one', ...flags]);
    assert.equal(invalid.code, 1);
    assert.match(invalid.stderr, /exactly one/i);
    assert.equal(api.requests.length, count);
  }
});

test('device listing displays backend health fields and supports cursor plus the documented inspect alias', async t => {
  const device = { id: 'dev_one', name: 'Fixture', model: 'bota_pin', status: 'bound', battery_percent: 73, last_heartbeat_at: '2026-10-18T01:02:03.000Z' };
  const api = await fixture(t, (req, res) => {
    if (req.url === '/v1/devices/dev_one') return json(res, device);
    assert.equal(new URL(req.url, 'http://fixture').searchParams.get('cursor'), 'cursor-one');
    json(res, { data: [device], has_more: true, next_cursor: 'cursor-two' });
  });
  const result = await runCli(t, api.url, ['devices', 'list', '--cursor', 'cursor-one']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /battery_percent/);
  assert.match(result.stdout, /73/);
  assert.match(result.stdout, /2026-10-18T01:02:03/);
  assert.match(result.stderr, /--cursor cursor-two/);
  const inspect = await runCli(t, api.url, ['devices', 'inspect', 'dev_one', '--json']);
  assert.equal(inspect.code, 0, inspect.stderr);
  assert.deepEqual(JSON.parse(inspect.stdout), device);
});

test('recording list accepts the published end-user-id flag and exposes continuation without polluting JSON', async t => {
  const page = { data: [], has_more: true, next_cursor: 'cursor-two' };
  const api = await fixture(t, (req, res) => {
    const url = new URL(req.url, 'http://fixture');
    assert.equal(url.pathname, '/v1/recordings');
    assert.equal(url.searchParams.get('end_user_id'), 'eu_one');
    assert.equal(url.searchParams.get('cursor'), 'cursor-one');
    json(res, page);
  });
  const result = await runCli(t, api.url, ['recordings', 'list', '--end-user-id', 'eu_one', '--cursor', 'cursor-one', '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), page);
});

test('end-user tables expose the backend continuation and retain the supplied cursor', async t => {
  const api = await fixture(t, (req, res) => {
    assert.equal(new URL(req.url, 'http://fixture').searchParams.get('cursor'), 'cursor-one');
    json(res, { data: [], has_more: true, next_cursor: 'cursor-two' });
  });
  const result = await runCli(t, api.url, ['end-users', 'list', '--cursor', 'cursor-one']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stderr, /--cursor cursor-two/);
});

test('JSON command failures preserve backend details on stderr and return failure', async t => {
  const api = await fixture(t, (_req, res) => json(res, { error: { code: 'insufficient_permissions', message: 'Fixture read denied', request_id: 'req_fixture' } }, 403));
  const result = await runCli(t, api.url, ['devices', 'list', '--json']);
  assert.equal(result.code, 1);
  assert.equal(result.stdout, '');
  assert.deepEqual(JSON.parse(result.stderr), { error: { message: 'Fixture read denied', status: 403, code: 'insufficient_permissions', request_id: 'req_fixture' } });
});

test('Platform-only webhook commands fail before network or tunnel setup', async t => {
  const api = await fixture(t, (_req, res) => json(res, { error: { message: 'unexpected request' } }, 500));
  for (const args of [['webhooks', 'list'], ['webhooks', 'get', 'wh_one'], ['listen', '--forward-to', 'http://127.0.0.1:1'], ['trigger', 'recording.uploaded']]) {
    const result = await runCli(t, api.url, args);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Platform/);
  }
  assert.equal(api.requests.length, 0);
});

test('trigger exits nonzero for failed delivery instead of printing success', async t => {
  const api = await fixture(t, (req, res) => {
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const rpc = JSON.parse(req.body);
    if (rpc.method === 'initialize') return json(res, { jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } } });
    if (rpc.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
    json(res, { jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: JSON.stringify({ success: false, status_code: 502, error: 'Fixture delivery rejected' }) }] } });
  });
  const result = await runCli(t, api.url, ['trigger', 'recording.uploaded', '--webhook', 'wh_one']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Fixture delivery rejected/);
  assert.doesNotMatch(result.stdout, /Triggered/);
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 1);
});
