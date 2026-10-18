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

test('recording list forwards the public creation-date filters with the cursor and existing filters intact', async t => {
  const api = await fixture(t, (req, res) => {
    const url = new URL(req.url, 'http://fixture');
    assert.equal(url.pathname, '/v1/recordings');
    assert.deepEqual(Object.fromEntries(url.searchParams), {
      limit: '7', cursor: 'cursor-one', end_user_id: 'eu_one', device_id: 'dev_one', status: 'uploaded',
      start_date: '2026-10-01T00:00:00+08:00', end_date: '2026-10-18T00:00:00Z',
    });
    json(res, { data: [], has_more: false });
  });
  const result = await runCli(t, api.url, ['recordings', 'list', '--limit', '7', '--cursor', 'cursor-one', '--end-user', 'eu_one', '--device', 'dev_one', '--status', 'uploaded', '--start-date', '2026-10-01T00:00:00+08:00', '--end-date', '2026-10-18T00:00:00Z', '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { data: [], has_more: false });
  assert.equal(api.requests.length, 1);
});

for (const stage of ['transcriptions', 'summaries']) {
  test(`recording get reports a failed ${stage} read instead of a complete-looking success`, async t => {
    const api = await fixture(t, (req, res) => {
      const path = new URL(req.url, 'http://fixture').pathname;
      assert.equal(req.method, 'GET');
      if (path === '/v1/recordings/rec_one') return json(res, { id: 'rec_one', status: 'uploaded' });
      if (path === `/v1/${stage}`) return json(res, { error: { code: 'insufficient_permissions', message: `Fixture ${stage} denied`, request_id: 'req_enrichment' } }, 403);
      assert.equal(path, '/v1/transcriptions');
      json(res, { data: [{ id: 'txn_one', status: 'completed' }] });
    });
    const result = await runCli(t, api.url, ['recordings', 'get', 'rec_one', '--json']);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.deepEqual(JSON.parse(result.stderr), { error: { message: `Fixture ${stage} denied`, status: 403, code: 'insufficient_permissions', request_id: 'req_enrichment' } });
    assert.equal(api.requests.length, stage === 'transcriptions' ? 2 : 3);
  });

  test(`recording get retains success when the ${stage} list is legitimately empty`, async t => {
    const api = await fixture(t, (req, res) => {
      const path = new URL(req.url, 'http://fixture').pathname;
      if (path === '/v1/recordings/rec_one') return json(res, { id: 'rec_one', status: 'uploaded' });
      if (path === `/v1/${stage}`) return json(res, { data: [], has_more: false });
      assert.equal(path, '/v1/transcriptions');
      json(res, { data: [{ id: 'txn_one', status: 'completed' }] });
    });
    const result = await runCli(t, api.url, ['recordings', 'get', 'rec_one', '--json']);
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { id: 'rec_one', status: 'uploaded', ...(stage === 'summaries' && { transcription_status: 'completed', transcription_id: 'txn_one' }) });
    assert.equal(api.requests.length, stage === 'transcriptions' ? 2 : 3);
  });
}

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

test('human and JSON diagnostics retain header-only request IDs and retry advice without raw response content', async t => {
  const rateLimit = { 'ratelimit-reset': '1', 'x-ratelimit-reset': '1792347000' };
  const api = await fixture(t, (_req, res) => {
    res.setHeader('X-Request-Id', 'req_rate_fixture');
    res.setHeader('Retry-After', '60');
    for (const [name, value] of Object.entries(rateLimit)) res.setHeader(name, value);
    json(res, { error: { code: 'rate_limit_exceeded', message: 'Fixture limit reached', param: 'limit' }, debug: 'BODY_SECRET' }, 429);
  });
  const human = await runCli(t, api.url, ['devices', 'list']);
  assert.equal(human.code, 1);
  assert.equal(human.stdout, '');
  for (const detail of ['Fixture limit reached', '429', 'rate_limit_exceeded', 'limit', 'req_rate_fixture', '60', 'ratelimit-reset: 1', 'x-ratelimit-reset: 1792347000']) assert.ok(human.stderr.includes(detail), human.stderr);
  const structured = await runCli(t, api.url, ['devices', 'list', '--json']);
  assert.equal(structured.code, 1);
  assert.deepEqual(JSON.parse(structured.stderr), { error: { message: 'Fixture limit reached', status: 429, code: 'rate_limit_exceeded', param: 'limit', request_id: 'req_rate_fixture', retry_after: '60', rate_limit: rateLimit } });
  assert.doesNotMatch(human.stderr + structured.stderr, /BODY_SECRET|sk_test_fixture/);
  assert.equal(api.requests.length, 2);
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
