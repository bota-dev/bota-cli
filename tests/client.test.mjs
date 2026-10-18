import assert from 'node:assert/strict';
import test from 'node:test';
import { BotaClient, callMcpTool } from '../src/client.ts';
import { fixture, json } from './helpers.mjs';

test('REST errors retain status, code, parameter and request ID', async t => {
  const api = await fixture(t, (_req, res) => json(res, { error: { code: 'validation_error', message: 'Select a template', param: 'template_id', request_id: 'req_fixture' } }, 400));
  const client = new BotaClient({ apiKey: 'sk_test_fixture', apiUrl: api.url });
  await assert.rejects(client.post('/v1/summaries', {}), error => {
    assert.equal(error.message, 'Select a template');
    assert.equal(error.status, 400);
    assert.equal(error.code, 'validation_error');
    assert.equal(error.param, 'template_id');
    assert.equal(error.requestId, 'req_fixture');
    return true;
  });
});

test('REST handles 204 and non-JSON errors without losing the HTTP status', async t => {
  const api = await fixture(t, (req, res) => {
    res.writeHead(req.method === 'DELETE' ? 204 : 502, { 'Content-Type': 'text/plain' });
    res.end(req.method === 'DELETE' ? undefined : 'upstream unavailable');
  });
  const client = new BotaClient({ apiKey: 'sk_test_fixture', apiUrl: api.url });
  assert.equal(await client.delete('/v1/end-users/eu_one'), undefined);
  await assert.rejects(client.get('/v1/devices'), /HTTP 502/);
});

test('REST refuses redirects without forwarding a credential to another origin', async t => {
  const target = await fixture(t, (_req, res) => json(res, { unexpected: true }));
  const api = await fixture(t, (_req, res) => {
    res.writeHead(307, { Location: target.url });
    res.end();
  });
  const client = new BotaClient({ apiKey: 'sk_test_fixture', apiUrl: api.url });
  await assert.rejects(client.post('/v1/transcriptions', { recording_id: 'rec_one' }));
  assert.equal(api.requests.length, 1);
  assert.equal(target.requests.length, 0);
});

for (const failure of ['http', 'rpc', 'tool']) {
  test(`MCP rejects ${failure} failure with one attempted tool invocation`, async t => {
    const api = await fixture(t, (req, res) => {
      if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
      const rpc = JSON.parse(req.body);
      if (failure === 'http') return json(res, { error: { message: 'Fixture unauthorized' } }, 401);
      if (rpc.method === 'initialize') return json(res, { jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } } });
      if (rpc.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
      if (failure === 'rpc') return json(res, { jsonrpc: '2.0', id: rpc.id, error: { code: -32602, message: 'Fixture RPC denied' } });
      json(res, { jsonrpc: '2.0', id: rpc.id, result: { isError: true, content: [{ type: 'text', text: 'Fixture tool denied' }] } });
    });
    await assert.rejects(callMcpTool(api.url, 'sk_test_fixture', 'trigger_webhook_event', { webhook_id: 'wh_one' }), failure === 'http' ? /401|unauthoriz/i : /Fixture .*denied/);
    const calls = api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call');
    assert.equal(calls.length, failure === 'http' ? 0 : 1);
  });
}

test('MCP handles split SSE, comments, unrelated notifications and multiline data', async t => {
  const api = await fixture(t, (req, res) => {
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const rpc = JSON.parse(req.body);
    if (rpc.method === 'initialize') return json(res, { jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } } });
    if (rpc.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write(': heartbeat\r\n\r\nevent: message\r\ndata: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"fixture"}}\r\n\r\n');
    const event = `event: message\r\ndata: {"jsonrpc":"2.0","id":${JSON.stringify(rpc.id)},\r\ndata: "result":{"content":[{"type":"text","text":"{\\"success\\":true}"}]}}\r\n\r\n`;
    res.write(event.slice(0, 31));
    res.end(event.slice(31));
  });
  assert.equal(await callMcpTool(api.url, 'sk_test_fixture', 'trigger_webhook_event', {}), '{"success":true}');
});
