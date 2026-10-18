import assert from 'node:assert/strict';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fixture, isolatedEnvironment, json, workspace } from './helpers.mjs';

async function localMcp(t, apiUrl) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--import', 'tsx', 'src/index.ts', '--api-url', apiUrl, 'mcp'],
    cwd: workspace,
    env: await isolatedEnvironment(t, apiUrl),
    stderr: 'pipe',
  });
  const client = new Client({ name: 'compatibility-fixture', version: '1' });
  t.after(() => client.close());
  await client.connect(transport);
  return client;
}

function content(result) {
  assert.equal(result.isError, undefined);
  return JSON.parse(result.content[0].text);
}

test('local MCP retains external-ID list envelope, flattened recording and omitted language default', async t => {
  const userPage = { data: [{ id: 'eu_one', external_id: 'fixture-user' }], has_more: false };
  const api = await fixture(t, (req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/v1/end-users') return json(res, userPage);
    if (url.pathname === '/v1/recordings/rec_one') return json(res, { id: 'rec_one', status: 'uploaded' });
    if (req.method === 'GET' && url.pathname === '/v1/transcriptions') return json(res, { data: [{ id: 'txn_one', status: 'completed' }] });
    if (url.pathname === '/v1/summaries') return json(res, { data: [{ id: 'sum_one', status: 'completed' }] });
    assert.equal(req.method, 'POST');
    assert.equal(url.pathname, '/v1/transcriptions');
    assert.deepEqual(JSON.parse(req.body), { recording_id: 'rec_one' });
    json(res, { id: 'txn_new', status: 'pending' }, 201);
  });
  const client = await localMcp(t, api.url);
  assert.deepEqual(content(await client.callTool({ name: 'get_end_user', arguments: { id: 'fixture-user' } })), userPage);
  assert.deepEqual(content(await client.callTool({ name: 'get_recording', arguments: { id: 'rec_one' } })), { id: 'rec_one', status: 'uploaded', transcription: { id: 'txn_one', status: 'completed' }, summary: { id: 'sum_one', status: 'completed' } });
  assert.deepEqual(content(await client.callTool({ name: 'create_transcription', arguments: { recording_id: 'rec_one' } })), { id: 'txn_new', status: 'pending' });
});

test('local MCP device/recording cursors reach the backend and webhook listing fails locally', async t => {
  const api = await fixture(t, (req, res) => {
    const url = new URL(req.url, 'http://fixture');
    assert.ok(['/v1/devices', '/v1/recordings'].includes(url.pathname));
    assert.equal(url.searchParams.get('cursor'), 'cursor-one');
    json(res, { data: [], has_more: false });
  });
  const client = await localMcp(t, api.url);
  for (const name of ['list_devices', 'list_recordings']) {
    assert.deepEqual(content(await client.callTool({ name, arguments: { cursor: 'cursor-one' } })), { data: [], has_more: false });
  }
  const result = await client.callTool({ name: 'list_webhooks', arguments: {} });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /Bota Platform/);
  assert.equal(api.requests.length, 2);
});
