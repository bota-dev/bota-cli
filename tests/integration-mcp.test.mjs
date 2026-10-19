import assert from 'node:assert/strict';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fixture, isolatedEnvironment, json, workspace } from './helpers.mjs';

const metadata = {
  id: '11111111-1111-4111-8111-111111111111', project_id: '22222222-2222-4222-8222-222222222222',
  provider_type: 'asr', provider_name: 'deepgram', is_enabled: true, has_error: true,
  last_used_at: null, created_at: '2026-10-18T00:00:00.000Z', updated_at: '2026-10-19T00:00:00.000Z',
};

async function connect(t, url) {
  const transport = new StdioClientTransport({ command: process.execPath,
    args: ['--import', 'tsx', 'src/index.ts', '--api-url', url, 'mcp'], cwd: workspace,
    env: await isolatedEnvironment(t, url), stderr: 'pipe' });
  const client = new Client({ name: 'integration-fixture', version: '1' });
  t.after(() => client.close()); await client.connect(transport); return client;
}

function hosted(t, reply) {
  return fixture(t, (req, res) => {
    assert.equal(req.url, '/mcp'); assert.equal(req.headers.authorization, 'Bearer sk_test_fixture');
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const rpc = JSON.parse(req.body);
    if (rpc.method === 'initialize') return json(res, { jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'hosted-fixture', version: '1' } } });
    if (rpc.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
    assert.equal(rpc.method, 'tools/call');
    const result = reply(rpc.params);
    json(res, { jsonrpc: '2.0', id: rpc.id, result });
  });
}

test('new local integration tools forward exactly once to hosted tools and preserve safe failure results', async t => {
  const failure = { success: false, code: 'credential_rejected', message: 'The provider rejected the stored credential.' };
  const entries = [
    ['list_integrations', {}, { data: [metadata] }],
    ['get_integration', { provider_type: 'asr', provider_name: 'deepgram' }, metadata],
    ['test_integration', { provider_type: 'asr', provider_name: 'deepgram' }, failure],
    ['update_integration', { id: metadata.id, is_enabled: false }, { ...metadata, is_enabled: false }],
    ['delete_integration', { id: metadata.id }, { deleted: true }],
  ];
  const expected = [...entries];
  const api = await hosted(t, params => {
    const [name, args, result] = expected.shift();
    assert.equal(params.name, name); assert.deepEqual(params.arguments, args);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
  const client = await connect(t, api.url);
  const tools = (await client.listTools()).tools;
  for (const [name, args, result] of entries) {
    const tool = tools.find(tool => tool.name === name);
    assert.ok(tool); assert.equal(tool.inputSchema.additionalProperties, false);
    assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), Object.keys(args).sort());
    const actual = await client.callTool({ name, arguments: args });
    assert.equal(actual.isError, undefined);
    assert.equal(actual.content[0].text, JSON.stringify(result, null, 2));
  }
  assert.equal(expected.length, 0);
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 5);
});

test('local integration schemas reject credentials and malformed input without echoing values or unknown property names', async t => {
  const api = await hosted(t, () => { throw new Error('must not forward'); });
  const client = await connect(t, api.url);
  const invalid = [
    ['list_integrations', { api_key: 'MCP_SECRET' }],
    ['list_integrations', { MCP_SECRET_PROPERTY: true }],
    ['get_integration', { provider_type: 'MCP_SECRET', provider_name: 'deepgram' }],
    ['test_integration', { provider_type: 'asr', provider_name: 'deepgram', api_key: 'MCP_SECRET' }],
    ['update_integration', { id: metadata.id, is_enabled: 'MCP_SECRET' }],
    ['update_integration', { id: metadata.id, is_enabled: true, api_key: 'MCP_SECRET' }],
    ['delete_integration', { id: metadata.id, MCP_SECRET_PROPERTY: true }],
  ];
  for (const [name, args] of invalid) {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true);
    assert.doesNotMatch(JSON.stringify(result), /MCP_SECRET/);
  }
  assert.equal(api.requests.length, 0);
});

test('local integration forwarding strips unexpected material and sanitizes hosted failures', async t => {
  let fail = false;
  const api = await hosted(t, () => fail
    ? { isError: true, content: [{ type: 'text', text: 'Provider URL?key=MCP_SECRET' }] }
    : { content: [{ type: 'text', text: JSON.stringify({ ...metadata, api_key: 'MCP_SECRET', last_error: 'MCP_SECRET' }) }] });
  const client = await connect(t, api.url);
  const result = await client.callTool({ name: 'get_integration', arguments: { provider_type: 'asr', provider_name: 'deepgram' } });
  assert.deepEqual(JSON.parse(result.content[0].text), metadata);
  fail = true;
  const failed = await client.callTool({ name: 'get_integration', arguments: { provider_type: 'asr', provider_name: 'deepgram' } });
  assert.equal(failed.isError, true);
  assert.doesNotMatch(JSON.stringify(failed), /MCP_SECRET/);
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 2);
});

test('local integration forwarding retains safe hosted policy codes and status without raw messages', async t => {
  const cases = [
    { code: 'provider_route_not_approved', status: 409, message: 'Credential testing is not approved for this project.' },
    { code: 'rate_limit_exceeded', status: 429, message: 'The integration operation is rate limited. Retry after the limit resets.' },
  ];
  let current;
  const api = await hosted(t, () => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: { ...current, message: 'HIPAA URL?key=MCP_SECRET', detail: 'MCP_SECRET' } }) }] }));
  const client = await connect(t, api.url);
  for (const expected of cases) {
    current = expected;
    const result = await client.callTool({ name: 'test_integration', arguments: { provider_type: 'asr', provider_name: 'deepgram' } });
    assert.equal(result.isError, true);
    assert.deepEqual(JSON.parse(result.content[0].text), { error: expected });
    assert.doesNotMatch(JSON.stringify(result), /MCP_SECRET|HIPAA URL/);
  }
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 2);
});
