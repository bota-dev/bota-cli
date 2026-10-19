import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, CallToolResultSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { closeHostedTransport } from '../src/commands/hosted-mcp.ts';
import { fixture, isolatedEnvironment, json, workspace } from './helpers.mjs';

const tick = ms => new Promise(resolve => setTimeout(resolve, ms));
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
const tool = name => ({ name, description: `Canonical ${name}`, inputSchema: { type: 'object', properties: { id: { type: 'string' } }, additionalProperties: false }, annotations: { readOnlyHint: !name.startsWith('create'), destructiveHint: name.startsWith('create'), openWorldHint: true }, _meta: { version: 'fixture-1' } });

async function connect(t, apiUrl, key = 'sk_test_fixture') {
  const env = await isolatedEnvironment(t, apiUrl); env.BOTA_API_KEY = key;
  const transport = new StdioClientTransport({ command: process.execPath,
    args: ['--import', 'tsx', 'src/index.ts', '--api-url', apiUrl, 'mcp', '--mode', 'hosted'], cwd: workspace, env, stderr: 'pipe' });
  let stderr = '';
  const client = new Client({ name: 'hosted-bridge-fixture', version: '1' });
  t.after(() => client.close());
  await client.connect(transport);
  transport.stderr?.on('data', chunk => { stderr += chunk; });
  return { client, stderr: () => stderr };
}

// The same per-HTTP-request official SDK Server/transport shape as a stateless
// hosted server. Every request gets the current principal's inventory/authority.
async function sdkHost(t, handlers) {
  const requests = [];
  const http = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const rpc = body ? JSON.parse(body) : undefined;
    requests.push({ method: req.method, path: req.url, auth: req.headers.authorization, rpc });
    assert.equal(req.url, '/mcp');
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const server = new Server({ name: 'canonical-fixture', version: '2026.10' }, { capabilities: { tools: { listChanged: true } } });
    server.setRequestHandler(ListToolsRequestSchema, request => handlers.list(request.params, req.headers.authorization));
    server.setRequestHandler(CallToolRequestSchema, request => handlers.call(request.params, req.headers.authorization));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    res.once('close', () => { void server.close(); });
    await transport.handleRequest(req, res, rpc);
  });
  http.listen(0, '127.0.0.1'); await once(http, 'listening');
  t.after(() => new Promise(resolve => { http.closeAllConnections(); http.close(resolve); }));
  return { url: `http://127.0.0.1:${http.address().port}`, requests };
}

async function rpcHost(t, operation, options = {}) {
  return fixture(t, async (req, res) => {
    assert.equal(req.url, '/mcp');
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const rpc = JSON.parse(req.body);
    if (rpc.method === 'initialize') {
      if (options.initializeDelay) await tick(options.initializeDelay);
      return json(res, { jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } } });
    }
    if (rpc.method === 'notifications/initialized') {
      if (options.initialized) return options.initialized(req, res);
      res.writeHead(202); res.end(); return;
    }
    if (!rpc.method) { res.writeHead(202); res.end(); return; }
    return operation(rpc, res, req);
  });
}

async function rawBridge(t, apiUrl, { key = 'sk_test_fixture', mode = 'hosted' } = {}) {
  const env = await isolatedEnvironment(t, apiUrl);
  if (key === undefined) delete env.BOTA_API_KEY; else env.BOTA_API_KEY = key;
  const child = spawn(process.execPath, ['--import', 'tsx', '--import', './tests/fixtures/signal-relay.mjs', 'src/index.ts', '--api-url', apiUrl, 'mcp', '--mode', mode], {
    cwd: workspace, env, stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
  });
  const events = new EventEmitter(); const messages = [];
  let buffer = '', stdout = '', stderr = '', invalid = false, closed = false;
  child.stdout.on('data', chunk => {
    stdout += chunk; buffer += chunk;
    let boundary;
    while ((boundary = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 1);
      try { messages.push(JSON.parse(line)); } catch { invalid = true; }
      events.emit('message');
    }
  });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.on('error', () => undefined);
  // On Windows, parent-side IPC disconnect can suppress ChildProcess 'close'
  // even after exit0 and both pipes close. Join those observable events directly.
  const exited = Promise.all([once(child, 'exit'), once(child.stdout, 'close'), once(child.stderr, 'close')]).then(([exit]) => exit);
  void exited.then(() => { closed = true; events.emit('message'); });
  t.after(async () => { if (!closed) child.kill(); await exited; });
  const next = (predicate, timeout = 10_000) => new Promise((resolve, reject) => {
    const done = () => {
      const index = messages.findIndex(predicate);
      if (index !== -1) { cleanup(); resolve(messages.splice(index, 1)[0]); }
      else if (closed) { cleanup(); reject(new Error(`Bridge exited: ${stderr}`)); }
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error('Timed out waiting for bridge response')); }, timeout);
    const cleanup = () => { clearTimeout(timer); events.off('message', done); };
    events.on('message', done); done();
  });
  const send = value => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...value })}\n`);
  const request = (id, method, params, timeout) => { const reply = next(message => message.id === id, timeout); send({ id, method, ...(params !== undefined && { params }) }); return reply; };
  return {
    send, next, request, exited,
    initialize: async () => {
      const reply = await request('fixture-initialize', 'initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'raw-fixture', version: '1' } });
      send({ method: 'notifications/initialized' }); return reply.result;
    },
    stop: async signal => {
      if (signal === 'EOF') { child.stdin.end(); if (child.connected) child.disconnect(); }
      else child.send(signal);
      const timer = setTimeout(() => child.kill(), 5000);
      try { return await exited; } finally { clearTimeout(timer); }
    },
    output: () => ({ stdout, stderr, invalid }),
  };
}

test('hosted discovery uses fresh principal-dependent SDK inventories and preserves pages/schemas/effects', { timeout: 15_000 }, async t => {
  const endUserNames = ['list_my_recordings', 'get_my_recording', 'get_my_transcription', 'get_my_summary', 'get_download_url', 'list_my_devices'];
  const principalNames = {
    sk_fixture: ['list_devices', 'get_device', 'create_transcription', 'list_webhooks'],
    rk_read_fixture: ['list_devices', 'get_device'], rk_write_fixture: ['create_transcription'], eut_fixture: endUserNames,
  };
  let revoked = false;
  const api = await sdkHost(t, {
    list: (params, auth) => ({ tools: (revoked ? [] : principalNames[auth.slice(7)]).map(tool), ...(params?.cursor === undefined ? { nextCursor: 'canonical-next' } : {}), _meta: { cursor: params?.cursor ?? null, revision: 'fixture-1' } }),
    call: () => ({ isError: true, content: [{ type: 'text', text: 'Current authority denied this tool.' }], _meta: { denied: true } }),
  });
  for (const [key, names] of Object.entries(principalNames)) {
    const { client } = await connect(t, api.url, key);
    assert.deepEqual(client.getServerCapabilities(), { tools: {} });
    const first = await client.listTools();
    assert.deepEqual(first, { tools: names.map(tool), nextCursor: 'canonical-next', _meta: { cursor: null, revision: 'fixture-1' } });
    assert.deepEqual(await client.listTools({ cursor: first.nextCursor }), { tools: names.map(tool), _meta: { cursor: 'canonical-next', revision: 'fixture-1' } });
  }
  assert.equal(api.requests.filter(req => req.rpc?.method === 'tools/call').length, 0);
  const { client } = await connect(t, api.url, 'rk_read_fixture');
  assert.equal((await client.listTools()).tools.length, 2);
  revoked = true;
  const denied = await client.request({ method: 'tools/call', params: { name: 'list_devices', arguments: {} } }, CallToolResultSchema);
  assert.deepEqual(denied, { isError: true, content: [{ type: 'text', text: 'Current authority denied this tool.' }], _meta: { denied: true } });
  assert.deepEqual((await client.listTools()).tools, []);
  const rpcRequests = api.requests.filter(req => ['tools/list', 'tools/call'].includes(req.rpc?.method));
  assert.equal(api.requests.filter(req => req.rpc?.method === 'initialize').length, rpcRequests.length);
  assert.equal(api.requests.filter(req => req.rpc?.method === 'tools/call').length, 1);
});

test('hosted calls preserve all text, multiple content blocks, structured content, isError and metadata', { timeout: 15_000 }, async t => {
  const result = { content: [
    { type: 'text', text: 'Plain canonical text, not JSON.', annotations: { audience: ['user'], priority: 0.8 } },
    { type: 'image', mimeType: 'image/png', data: 'iVBORw==' },
    { type: 'resource', resource: { uri: 'bota://fixture/recording', mimeType: 'text/plain', text: 'Canonical resource' } },
    { type: 'text', text: 'Second text block' },
  ], structuredContent: { recording: { id: 'rec_fixture' }, success: false }, isError: true, _meta: { contract: 'canonical-1' } };
  let calls = 0;
  const api = await sdkHost(t, { list: () => ({ tools: [tool('canonical_tool')] }), call: params => {
    calls++; assert.deepEqual(params, { name: 'canonical_tool', arguments: { id: 'rec_fixture' }, _meta: { trace: 'fixture' } }); return result;
  } });
  const { client, stderr } = await connect(t, api.url);
  assert.equal(api.requests.length, 0, 'local startup must not contact hosted/docs/project endpoints');
  assert.deepEqual(await client.request({ method: 'tools/call', params: { name: 'canonical_tool', arguments: { id: 'rec_fixture' }, _meta: { trace: 'fixture' } } }, CallToolResultSchema), result);
  assert.equal(calls, 1); assert.equal(stderr(), '');
});

test('unknown mode fails before credentials/network; hosted failures never fall back or echo HTTP bodies', { timeout: 15_000 }, async t => {
  const api = await fixture(t, (_req, res) => {
    res.writeHead(401, { 'WWW-Authenticate': 'Bearer resource_metadata="https://PROMPT_SECRET.example"' }); res.end('HTTP_BODY_SECRET');
  });
  const env = await isolatedEnvironment(t, api.url); delete env.BOTA_API_KEY;
  const invalid = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--api-url', api.url, 'mcp', '--mode', 'invalid'], {
    cwd: workspace, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let invalidStderr = ''; invalid.stderr.on('data', chunk => { invalidStderr += chunk; });
  assert.deepEqual(await once(invalid, 'close'), [1, null]);
  assert.match(invalidStderr, /--mode must be legacy or hosted/);
  assert.doesNotMatch(invalidStderr, /Not authenticated/);
  assert.equal(api.requests.length, 0);
  for (const baseUrl of ['file:///URL_SECRET', `${api.url}?key=URL_SECRET`, `http://URL_SECRET@127.0.0.1/`]) {
    const invalidUrl = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--api-url', baseUrl, 'mcp', '--mode', 'hosted'], {
      cwd: workspace, env: { ...env, BOTA_API_KEY: 'sk_URL_SECRET' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = ''; invalidUrl.stdout.on('data', chunk => { output += chunk; }); invalidUrl.stderr.on('data', chunk => { output += chunk; });
    assert.deepEqual(await once(invalidUrl, 'close'), [1, null]);
    assert.match(output, /HTTP\(S\) API base URL/); assert.doesNotMatch(output, /URL_SECRET/);
  }
  assert.equal(api.requests.length, 0, 'invalid hosted URLs must fail before network access');
  const { client } = await connect(t, api.url);
  await assert.rejects(client.listTools(), error => {
    assert.equal(error.data.http_status, 401);
    assert.match(error.message, /Hosted MCP request failed/);
    assert.doesNotMatch(JSON.stringify(error) + error.message, /HTTP_BODY_SECRET|PROMPT_SECRET/); return true;
  });
  assert.equal(api.requests.length, 1);
  assert.equal(api.requests[0].url, '/mcp');
});

test('hosted transport rejects origin redirects without sending the credential to the target', { timeout: 15_000 }, async t => {
  const target = await fixture(t, (_req, res) => json(res, { unexpected: true }));
  const source = await fixture(t, (_req, res) => { res.writeHead(307, { Location: `${target.url}/REDIRECT_SECRET` }); res.end(); });
  const { client } = await connect(t, source.url);
  await assert.rejects(client.listTools(), error => { assert.doesNotMatch(error.message, /REDIRECT_SECRET/); return true; });
  assert.equal(source.requests.length, 1); assert.equal(target.requests.length, 0);
});

test('hosted callbacks do not reach downstream prompts and malformed protocol failures stay fixed', { timeout: 15_000 }, async t => {
  let malformed = false;
  const api = await rpcHost(t, (rpc, res) => {
    if (malformed) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('PROTOCOL_SECRET'); return; }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: 'callback', method: 'elicitation/create', params: { message: 'Do not show CALLBACK_SECRET', requestedSchema: { type: 'object' } } })}\n\n`);
    res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: 'No callback forwarding' }] } })}\n\n`);
  });
  const bridge = await rawBridge(t, api.url); await bridge.initialize();
  const taskFailure = await bridge.request('task', 'tools/call', { name: 'TASK_SECRET', arguments: {}, task: { ttl: 30_000 } });
  // The official Server rejects unadvertised task augmentation before dispatch.
  assert.equal(taskFailure.error.code, -32603); assert.match(taskFailure.error.message, /task/i);
  assert.doesNotMatch(bridge.output().stdout + bridge.output().stderr, /TASK_SECRET/);
  assert.equal(api.requests.length, 0, 'unsupported tasks must fail before initialization or a tool effect');
  const result = await bridge.request(1, 'tools/call', { name: 'fixture', arguments: {} });
  assert.deepEqual(result.result, { content: [{ type: 'text', text: 'No callback forwarding' }] });
  malformed = true;
  const failure = await bridge.request(2, 'tools/list', {});
  assert.match(failure.error.message, /Hosted MCP request failed/);
  assert.doesNotMatch(bridge.output().stdout + bridge.output().stderr, /CALLBACK_SECRET|PROTOCOL_SECRET/);
  assert.equal(bridge.output().invalid, false);
  assert.deepEqual(await bridge.stop('EOF'), [0, null]);
});

test('hosted cancellation keeps numeric zero and string zero distinct and rejects duplicate active IDs', { timeout: 15_000 }, async t => {
  const started = new Map(), closed = new Set();
  const api = await rpcHost(t, (rpc, res) => {
    assert.equal(rpc.method, 'tools/call');
    const identity = rpc.params.arguments.identity;
    started.set(identity, true); res.once('close', () => closed.add(identity));
  });
  const bridge = await rawBridge(t, api.url); await bridge.initialize();
  bridge.send({ id: 0, method: 'tools/call', params: { name: 'fixture', arguments: { identity: 'numeric' } } });
  bridge.send({ id: '0', method: 'tools/call', params: { name: 'fixture', arguments: { identity: 'string' } } });
  for (let i = 0; started.size < 2 && i < 100; i++) await tick(10);
  assert.equal(started.size, 2);
  const duplicate = await bridge.request(0, 'tools/call', { name: 'fixture', arguments: { identity: 'duplicate' } });
  assert.match(duplicate.error.message, /already active/); assert.equal(started.has('duplicate'), false);
  bridge.send({ method: 'notifications/cancelled', params: { requestId: 0 } });
  for (let i = 0; !closed.has('numeric') && i < 100; i++) await tick(10);
  assert.equal(closed.has('numeric'), true); assert.equal(closed.has('string'), false);
  bridge.send({ method: 'notifications/cancelled', params: { requestId: '0' } });
  for (let i = 0; !closed.has('string') && i < 100; i++) await tick(10);
  assert.equal(closed.has('string'), true);
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 2);
  assert.deepEqual(await bridge.stop('EOF'), [0, null]);
});

for (const signal of ['EOF', 'SIGINT', 'SIGTERM']) {
  test(`hosted ${signal} joins pending request cleanup and aborts HTTP without replay`, { timeout: 15_000 }, async t => {
    const started = deferred(), closed = deferred();
    const api = await rpcHost(t, (rpc, res) => { assert.equal(rpc.method, 'tools/call'); res.once('close', closed.resolve); started.resolve(); });
    const bridge = await rawBridge(t, api.url); await bridge.initialize();
    bridge.send({ id: 5, method: 'tools/call', params: { name: 'fixture', arguments: {} } });
    await started.promise;
    assert.deepEqual(await bridge.stop(signal), [0, null]); await closed.promise;
    assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/call').length, 1);
    assert.equal(bridge.output().invalid, false); assert.equal(bridge.output().stderr, '');
  });
}

test('hosted cancellation also interrupts a stalled initialized notification before any tool call', { timeout: 15_000 }, async t => {
  const started = deferred(), closed = deferred();
  const api = await rpcHost(t, () => { throw new Error('No tool invocation expected'); }, {
    initialized: (_req, res) => { res.once('close', closed.resolve); started.resolve(); },
  });
  const bridge = await rawBridge(t, api.url); await bridge.initialize();
  bridge.send({ id: 1, method: 'tools/list', params: {} }); await started.promise;
  bridge.send({ method: 'notifications/cancelled', params: { requestId: 1 } });
  await closed.promise;
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'tools/list').length, 0);
  assert.deepEqual(await bridge.stop('EOF'), [0, null]);
});

test('hosted total deadline includes initialize and lost SSE response without resumption or duplicate effects', { timeout: 40_000 }, async t => {
  let calls = 0;
  const api = await rpcHost(t, (rpc, res) => {
    assert.equal(rpc.method, 'tools/call'); calls++;
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('id: lost-response\nretry: 1\n\n');
    setTimeout(() => res.destroy(), 10);
  }, { initializeDelay: 5000 });
  const bridge = await rawBridge(t, api.url); await bridge.initialize();
  const started = Date.now();
  const result = await bridge.request(9, 'tools/call', { name: 'mutation', arguments: {} }, 36_000);
  const elapsed = Date.now() - started;
  assert.match(result.error.message, /30-second total deadline/);
  assert.match(result.error.message, /outcome.*unknown/);
  assert.ok(elapsed >= 29_000 && elapsed < 34_000, `Elapsed ${elapsed} ms`);
  assert.equal(calls, 1);
  assert.equal(api.requests.filter(req => req.body && JSON.parse(req.body).method === 'initialize').length, 1);
  assert.equal(api.requests.filter(req => req.headers['last-event-id']).length, 0);
  assert.deepEqual(await bridge.stop('EOF'), [0, null]);
});

test('hosted cleanup runs after close failure and never exposes raw close/cleanup diagnostics', async () => {
  let cleaned = false;
  await assert.rejects(closeHostedTransport(async () => { throw new Error('CLOSE_SECRET'); }, () => { cleaned = true; }), error => {
    assert.match(error.message, /cleanup failed/); assert.match(error.message, /outcome.*unknown/);
    assert.doesNotMatch(JSON.stringify(error) + error.message, /CLOSE_SECRET/); return true;
  });
  assert.equal(cleaned, true);
  await assert.rejects(closeHostedTransport(async () => undefined, () => { throw new Error('CLEANUP_SECRET'); }), error => {
    assert.doesNotMatch(JSON.stringify(error) + error.message, /CLEANUP_SECRET/); return true;
  });
});
