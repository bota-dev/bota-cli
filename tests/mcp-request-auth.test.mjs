import assert from 'node:assert/strict';
import test from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { installMcpRequestAuth } from '../src/mcp-request-auth.ts';
import { getApiKey, getProfileContext, withInvocationCredential } from '../src/config.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const keyA = 'rk_MCP_GATE_A_CANARY', keyB = 'rk_MCP_GATE_B_CANARY';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const options = { timeout: 3000, maxTotalTimeout: 3000 };
const turn = () => new Promise(resolve => setImmediate(resolve));
function credential(key) {
  return { apiKey: key, apiOrigin: 'https://api.example.invalid', source: 'store', profile: {}, identity: {
    project_id: 'project:synthetic', organization_id: 'organization:synthetic', key_id: key === keyA ? 'key:a' : 'key:b',
    key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false } };
}
function refused(code, flags = {}) {
  return error => {
    assert.ok(error instanceof McpError); assert.equal(error.code, ErrorCode.InternalError);
    assert.equal(error.data?.code, code);
    for (const [name, value] of Object.entries(flags)) assert.equal(error.data?.[name], value);
    assert.doesNotMatch(String(error) + JSON.stringify(error), /MCP_GATE_[AB]_CANARY|RAW_DETAIL/);
    return true;
  };
}
function state() {
  const h = { key: keyA, status: 'ready', admissions: 0, callbacks: 0, closes: 0, signals: [], seenKeys: [],
    closeFault: false, opaqueFault: false, synchronousFault: false, handler: undefined, beforeAuth: undefined,
    authCleanup: undefined };
  h.authenticate = (signal, action) => {
    h.admissions++; h.signals.push(signal);
    if (h.synchronousFault) throw new NativeProfileTransactionError('profile_pending_recovery', true);
    return (async () => {
      if (h.opaqueFault) throw new Error(`${keyA} RAW_DETAIL`);
      if (h.status === 'pending') throw new NativeProfileTransactionError('profile_pending_recovery', true);
      if (h.status === 'removed') throw new NativeProfileTransactionError('profile_disabled');
      if (signal.aborted) throw new NativeProfileTransactionError('profile_cancelled');
      await h.beforeAuth?.(signal);
      const context = { signal, budget: { assertActive() {} } };
      try {
        return await withInvocationCredential(credential(h.key), context, action);
      } finally {
        await h.authCleanup?.(); h.closes++;
        if (h.closeFault) throw new NativeProfileTransactionError('profile_lease_failed', false, true);
      }
    })();
  };
  return h;
}
async function fixture(t, h = state()) {
  const server = new McpServer({ name: 'gate-fixture', version: '1' });
  const original = server.server.setRequestHandler;
  const gate = installMcpRequestAuth(server.server, h.authenticate);
  server.registerTool('echo', { description: 'Synthetic gate fixture', inputSchema: { value: z.string().optional() } },
    async (args, extra) => {
      h.callbacks++; h.seenKeys.push(getApiKey());
      if (h.handler) return h.handler(args, extra);
      return { content: [{ type: 'text', text: JSON.stringify({ value: args.value ?? '', key_id: getProfileContext().identity.key_id }) }] };
    });
  gate.registered(); assert.equal(server.server.setRequestHandler, original);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'gate-client-fixture', version: '1' });
  client.onerror = () => undefined; server.server.onerror = () => undefined;
  await server.connect(serverTransport); await client.connect(clientTransport, options);
  t.after(async () => { gate.stop(); await Promise.allSettled([client.close(), server.close()]); await gate.join(); });
  return { h, server, client, clientTransport, serverTransport, gate };
}

test('public SDK initialization captures no credential and each tools/list or tools/call authenticates separately', async t => {
  const f = await fixture(t); assert.equal(f.h.admissions, 0); assert.equal(f.h.callbacks, 0);
  const listed = await f.client.listTools(undefined, options);
  assert.equal(listed.tools[0].name, 'echo'); assert.equal(f.h.admissions, 1); assert.equal(f.h.callbacks, 0);
  const result = await f.client.callTool({ name: 'echo', arguments: { value: 'safe' } }, undefined, options);
  assert.deepEqual(JSON.parse(result.content[0].text), { value: 'safe', key_id: 'key:a' });
  assert.equal(f.h.admissions, 2); assert.equal(f.h.callbacks, 1); assert.equal(f.h.closes, 2);
  assert.ok(f.h.signals.every(signal => signal.aborted));
  assert.doesNotMatch(JSON.stringify(listed) + JSON.stringify(result), /MCP_GATE_[AB]_CANARY/);
});

test('key rotation is resolved for the next discovery/invocation rather than retained at MCP startup', async t => {
  const f = await fixture(t);
  const first = await f.client.callTool({ name: 'echo', arguments: {} }, undefined, options);
  f.h.key = keyB; await f.client.listTools(undefined, options);
  const second = await f.client.callTool({ name: 'echo', arguments: {} }, undefined, options);
  assert.equal(JSON.parse(first.content[0].text).key_id, 'key:a'); assert.equal(JSON.parse(second.content[0].text).key_id, 'key:b');
  assert.deepEqual(f.h.seenKeys, [keyA, keyB]); assert.equal(f.h.admissions, 3);
});

test('successful structured tool results remain intact through the secure gate', async t => {
  const h = state(); const expected = { content: [{ type: 'text', text: 'safe-result' }],
    structuredContent: { value: 'safe-structured' }, _meta: { 'fixture/safe': 'retained' }, isError: false };
  h.handler = async () => expected;
  const f = await fixture(t, h);
  assert.deepEqual(await f.client.callTool({ name: 'echo', arguments: {} }, undefined, options), expected);
});

test('removed and pending profiles refuse discovery/calls before any business callback', async t => {
  const f = await fixture(t);
  for (const [status, code] of [['removed', 'profile_disabled'], ['pending', 'profile_pending_recovery']]) {
    f.h.status = status;
    await assert.rejects(f.client.listTools(undefined, options), refused(code, { recovery_required: status === 'pending' }));
    await assert.rejects(f.client.callTool({ name: 'echo', arguments: {} }, undefined, options), refused(code));
  }
  assert.equal(f.h.callbacks, 0); assert.equal(f.h.closes, 0);
  assert.ok(f.h.signals.every(signal => signal.aborted));
});

test('provider closure failure is joined and surfaced with private fixed uncertainty after callback completion', async t => {
  const f = await fixture(t); f.h.closeFault = true;
  await assert.rejects(f.client.callTool({ name: 'echo', arguments: {} }, undefined, options),
    refused('profile_lease_failed', { operation_may_have_executed: true, recovery_required: false }));
  assert.equal(f.h.callbacks, 1); assert.equal(f.h.closes, 1); assert.equal(f.h.signals[0].aborted, true);
});

test('synchronous and opaque auth failures become private protocol errors and retire request ownership', async t => {
  const f = await fixture(t); f.h.synchronousFault = true;
  await assert.rejects(f.client.listTools(undefined, options), refused('profile_pending_recovery', { recovery_required: true }));
  f.h.synchronousFault = false; f.h.opaqueFault = true;
  await assert.rejects(f.client.listTools(undefined, options),
    refused('profile_operation_failed', { operation_may_have_executed: true, recovery_required: false }));
  f.h.opaqueFault = false; await f.client.listTools(undefined, options);
  assert.equal(f.h.callbacks, 0); assert.ok(f.h.signals.every(signal => signal.aborted));
});

test('shutdown stop aborts active callbacks and join waits through their joined auth cleanup', async t => {
  const h = state(), started = deferred(), callbackGate = deferred(), cleanupGate = deferred(), cleanupStarted = deferred();
  h.handler = async (_args, extra) => {
    started.resolve(extra.signal); await callbackGate.promise;
    return { content: [{ type: 'text', text: 'safe' }] };
  };
  h.authCleanup = async () => { cleanupStarted.resolve(); await cleanupGate.promise; };
  const f = await fixture(t, h);
  const request = f.client.callTool({ name: 'echo', arguments: {} }, undefined, options);
  const signal = await started.promise; f.gate.stop(); assert.equal(signal.aborted, true);
  let joined = false; const joining = f.gate.join().then(() => { joined = true; });
  await turn(); assert.equal(joined, false); callbackGate.resolve(); await cleanupStarted.promise;
  assert.equal(joined, false); assert.equal(h.closes, 0);
  cleanupGate.resolve(); await joining; await request; assert.equal(h.closes, 1);
  await assert.rejects(f.client.listTools(undefined, options), /cannot be admitted/);
  assert.equal(h.admissions, 1);
});

test('client cancellation propagates its request signal and gate cleanup completes before join', async t => {
  const h = state(), started = deferred(), aborted = deferred();
  h.handler = async (_args, extra) => {
    started.resolve();
    if (!extra.signal.aborted) await new Promise(resolve => extra.signal.addEventListener('abort', resolve, { once: true }));
    aborted.resolve(); throw new NativeProfileTransactionError('profile_cancelled', false, true);
  };
  const f = await fixture(t, h), controller = new AbortController();
  const request = f.client.callTool({ name: 'echo', arguments: {} }, undefined, { ...options, signal: controller.signal });
  await started.promise; controller.abort(); await assert.rejects(request); await aborted.promise;
  await f.gate.join(); assert.equal(h.closes, 1); assert.equal(h.signals[0].aborted, true);
});

test('numeric request ID zero cancellation works through public in-memory protocol and releases that ID', async t => {
  const h = state(), started = deferred(), aborted = deferred(); let first = true;
  h.handler = async (_args, extra) => {
    if (first) {
      first = false; started.resolve();
      await new Promise(resolve => extra.signal.addEventListener('abort', resolve, { once: true }));
      aborted.resolve();
    }
    return { content: [{ type: 'text', text: 'safe' }] };
  };
  const f = await fixture(t, h); const responses = [];
  const receive = f.clientTransport.onmessage;
  f.clientTransport.onmessage = (message, extra) => { if ('id' in message && message.id === 0) responses.push(message); receive?.(message, extra); };
  await f.clientTransport.send({ jsonrpc: '2.0', id: 0, method: 'tools/call', params: { name: 'echo', arguments: {} } });
  await started.promise;
  await f.clientTransport.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 0, reason: 'synthetic' } });
  await aborted.promise; await f.gate.join();
  assert.equal(h.signals[0].aborted, true); assert.equal(h.closes, 1);
  await f.clientTransport.send({ jsonrpc: '2.0', id: 0, method: 'tools/call', params: { name: 'echo', arguments: {} } });
  for (let turnNumber = 0; responses.length < 2 && turnNumber < 20; turnNumber++) await turn();
  assert.equal(responses.length, 2); assert.equal(h.callbacks, 2); assert.equal(h.closes, 2);
});

test('registration completion requires both public discovery/call handlers and restores the registration method', () => {
  const server = new McpServer({ name: 'gate-empty', version: '1' }); const original = server.server.setRequestHandler;
  const gate = installMcpRequestAuth(server.server, async (_signal, action) => action());
  assert.throws(() => gate.registered(), /registration is incomplete/);
  assert.equal(server.server.setRequestHandler, original);
});

test('private callback and unknown-tool failures cannot expose raw input through SDK tool-error results', async t => {
  const h = state(); h.handler = async () => { throw new Error(`${keyA} RAW_DETAIL`); };
  const f = await fixture(t, h);
  for (const name of ['echo', keyB]) {
    let result;
    try { result = await f.client.callTool({ name, arguments: {} }, undefined, options); }
    catch (error) {
      assert.doesNotMatch(String(error) + JSON.stringify(error), /MCP_GATE_[AB]_CANARY|RAW_DETAIL/);
      assert.equal(error.data?.operation_may_have_executed, true);
      continue;
    }
    assert.doesNotMatch(JSON.stringify(result), /MCP_GATE_[AB]_CANARY|RAW_DETAIL/);
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result), /operation_may_have_executed/);
  }
});

test('SDK argument failures are private and conservatively retain outcome uncertainty without invoking the callback', async t => {
  const f = await fixture(t);
  const result = await f.client.callTool({ name: 'echo', arguments: { value: { [keyA]: keyB } } }, undefined, options);
  assert.equal(result.isError, true); assert.equal(f.h.callbacks, 0); assert.equal(f.h.admissions, 1);
  assert.doesNotMatch(JSON.stringify(result), /MCP_GATE_[AB]_CANARY|RAW_DETAIL/);
  assert.match(JSON.stringify(result), /operation_may_have_executed/);
  const detail = JSON.parse(result.content.find(item => item.type === 'text' && item.text.startsWith('{')).text).error;
  assert.equal(detail.operation_may_have_executed, true); assert.equal(detail.code, 'profile_operation_failed');
});
