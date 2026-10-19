import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { fixture, isolatedEnvironment, json, workspace } from './helpers.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};

// These lifecycle fixtures intentionally use actual CLI stdio and loopback HTTP.
// The source owner's hosted-mcp.test.mjs separately covers cancellation identity,
// discovery/results/errors, shutdown and the real 30-second clock.
async function bridge(t, apiUrl) {
  const imports = ['--import', 'tsx', '--import', pathToFileURL(join(workspace, 'tests/fixtures/signal-relay.mjs')).href,
    '--import', pathToFileURL(join(workspace, 'tests/fixtures/hosted-mcp-deadline-clock.mjs')).href];
  const child = spawn(process.execPath,
    [...imports, 'src/index.ts', '--api-url', apiUrl, 'mcp', '--mode', 'hosted'],
    { cwd: workspace, env: await isolatedEnvironment(t, apiUrl), stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
  const events = new EventEmitter(), replies = [];
  let buffer = '', stdout = '', stderr = '', closed = false;
  child.stdout.on('data', chunk => {
    stdout += chunk;
    buffer += chunk;
    let boundary;
    while ((boundary = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 1);
      replies.push(JSON.parse(line)); events.emit('reply');
    }
  });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.on('error', () => undefined);
  // Windows IPC teardown can omit ChildProcess 'close' after its 'exit' and
  // both pipe closures. Join those actual lifecycle boundaries explicitly.
  const exited = Promise.all([once(child, 'exit'), once(child.stdout, 'close'), once(child.stderr, 'close')])
    .then(([result]) => result);
  void exited.then(() => { closed = true; events.emit('reply'); });
  t.after(async () => { if (!closed) child.kill(); await exited; });
  const send = message => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  const reply = id => new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); events.off('reply', check); };
    const check = () => {
      const index = replies.findIndex(value => value.id === id);
      if (index >= 0) { cleanup(); resolve(replies.splice(index, 1)[0]); }
      else if (closed) { cleanup(); reject(new Error(`CLI exited without reply: ${stderr}`)); }
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error('CLI lifecycle reply timed out')); }, 8_000);
    events.on('reply', check); check();
  });
  const request = (id, method, params) => {
    const result = reply(id); send({ id, method, params }); return result;
  };
  await once(child, 'message');
  const initialized = await request('local-initialize', 'initialize', {
    protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'lifecycle-fixture', version: '1' },
  });
  assert.equal(initialized.error, undefined);
  send({ method: 'notifications/initialized' });
  return {
    send, request,
    output: () => `${stdout}\n${stderr}`,
    stop: async signal => {
      if (signal === 'EOF') { child.stdin.end(); if (child.connected) child.disconnect(); }
      else child.send(signal);
      const timer = setTimeout(() => child.kill(), 5_000);
      try { return await exited; } finally { clearTimeout(timer); }
    },
  };
}

async function host(t, { initializeDelay = 0, initialized, operation }) {
  return fixture(t, async (request, res) => {
    assert.equal(request.url, '/mcp');
    assert.equal(request.headers.authorization, 'Bearer sk_test_fixture');
    if (request.method === 'GET') { res.writeHead(405); res.end(); return; }
    const rpc = JSON.parse(request.body);
    if (rpc.method === 'initialize') {
      await pause(initializeDelay);
      return json(res, { jsonrpc: '2.0', id: rpc.id, result: {
        protocolVersion: '2025-03-26', capabilities: { tools: {} },
        serverInfo: { name: 'INITIALIZE_INTERNAL_CANARY', version: '1' },
      } });
    }
    if (rpc.method === 'notifications/initialized') {
      if (initialized) return initialized(res);
      res.writeHead(202); res.end(); return;
    }
    if (rpc.method === 'notifications/cancelled') { res.writeHead(202); res.end(); return; }
    return operation(rpc, res);
  });
}

const toolCalls = api => api.requests.filter(request =>
  request.method === 'POST' && JSON.parse(request.body).method === 'tools/call');
const assertPrivate = cli => assert.doesNotMatch(cli.output(), /INITIALIZE_INTERNAL_CANARY|SSE_INTERNAL_CANARY|sk_test_fixture/);

test('hosted total deadline interrupts a stalled initialized notification without a tools request', { timeout: 12_000 }, async t => {
  const notificationStarted = deferred(), notificationClosed = deferred();
  const api = await host(t, {
    initialized: res => { res.once('close', notificationClosed.resolve); notificationStarted.resolve(); },
    operation: () => assert.fail('The bridge must not invoke a tool before initialization finishes'),
  });
  const cli = await bridge(t, api.url);
  const resultPromise = cli.request(1, 'tools/call', { name: 'mutation_fixture', arguments: {} });
  await notificationStarted.promise;
  const result = await resultPromise;
  assert.equal(result.error.code, -32001);
  assert.match(result.error.message, /30-second total deadline/);
  await notificationClosed.promise;
  assert.equal(toolCalls(api).length, 0);
  assert.equal(api.requests.filter(request => request.body && JSON.parse(request.body).method === 'initialize').length, 1);
  assertPrivate(cli);
  assert.deepEqual(await cli.stop('EOF'), [0, null]);
});

test('hosted initialize and invocation share one total deadline rather than receiving a fresh budget', { timeout: 12_000 }, async t => {
  const callStarted = deferred(), callClosed = deferred();
  let attemptedReplies = 0;
  const api = await host(t, {
    // Each phase fits inside the accelerated 1500 ms deadline. Their combined
    // 1800 ms does not: independent/reset per-phase budgets would return success.
    initializeDelay: 900,
    operation: async (rpc, res) => {
      assert.equal(rpc.method, 'tools/call');
      res.once('close', callClosed.resolve); callStarted.resolve();
      await pause(900);
      attemptedReplies++;
      if (!res.destroyed) json(res, { jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: 'Unexpected reset-budget success' }] } });
    },
  });
  const cli = await bridge(t, api.url);
  const resultPromise = cli.request(2, 'tools/call', { name: 'mutation_fixture', arguments: {} });
  await callStarted.promise;
  const result = await resultPromise;
  assert.equal(result.error.code, -32001);
  assert.match(result.error.message, /30-second total deadline/);
  assert.match(result.error.message, /outcome.*unknown/);
  await callClosed.promise;
  assert.equal(attemptedReplies, 0, 'the combined deadline expires before the staged result becomes available');
  assert.equal(toolCalls(api).length, 1);
  assertPrivate(cli);
  assert.deepEqual(await cli.stop('EOF'), [0, null]);
});
