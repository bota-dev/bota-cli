import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once, getEventListeners } from 'node:events';
import { createServer } from 'node:http';
import nodeTest from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createDelegatedMcpIdentityVerifier, createDelegatedMcpIdentityVerifierForTrustedPorts,
  DelegatedMcpIdentityHttpError } from '../src/delegated-mcp-identity-http.ts';

const test = (name, work) => nodeTest(name, { timeout: 10_000 }, work);
const canary = 'PRIVATE_MCP_IDENTITY_CANARY';
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const deployment = () => ({ version: 1, issuer: 'https://auth.fixture.invalid', endpoints: {
  authorization: 'https://auth.fixture.invalid/oauth/authorize', token: 'https://auth.fixture.invalid/oauth/token', revocation: 'https://auth.fixture.invalid/oauth/revoke' },
  resources: { rest: 'https://api.fixture.invalid/v1', mcp: 'https://mcp.fixture.invalid/tools/mcp' }, client: { clientId: 'registered-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const bearer = () => 'bota_da1_' + randomBytes(32).toString('base64url');
const dto = d => ({ format_version: 1, credential_type: 'developer_delegation', issuer: d.issuer, client_id: d.client.clientId,
  user_id: '11111111-1111-1111-1111-111111111111', organization_id: 'org_fixture', project_id: 'proj_fixture',
  grant_id: '22222222-2222-2222-2222-222222222222', family_id: '33333333-3333-3333-3333-333333333333', resource: d.resources.mcp,
  grant_resources: [d.resources.rest, d.resources.mcp], grant_scopes: ['devices:read'], access_scopes: ['devices:read'], expires_at: 1300 });
function context() { const controller = new AbortController(), state = { expired: false };
  return { controller, state, value: { signal: controller.signal, budget: { assertActive() { if (state.expired) throw Error(canary); } } } }; }
function refused(code) { return error => { assert.ok(error instanceof DelegatedMcpIdentityHttpError); if (code) assert.equal(error.code, code);
  assert.equal(error.cause, undefined); assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_MCP_IDENTITY_CANARY|bota_d[acr]1_|fixture\.invalid/); return true; }; }
async function fixture(t, timeoutMs = 3000) {
  const f = { d: deployment(), ctx: context(), access: bearer(), requests: [], logical: [], signals: [], owners: new Set(), jobs: new Set(), after: null, rewrite: null };
  f.row = dto(f.d);
  const server = createServer((req, res) => {
    const job = (async () => {
      let body = ''; for await (const chunk of req) body += chunk; const message = body ? JSON.parse(body) : undefined;
      f.requests.push({ path: req.url, method: req.method, headers: req.headers, message });
      const normal = async () => {
        if (req.method === 'GET') { res.writeHead(405, { Allow: 'POST', Connection: 'close' }); res.end(); return; }
        const mcp = new McpServer({ name: 'owned-identity-fixture', version: '1' });
        mcp.registerTool('get_delegated_identity', { inputSchema: {} }, async () => ({ content: [{ type: 'text', text: JSON.stringify(f.row) }] }));
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
        f.owners.add(mcp); await mcp.connect(transport);
        try { await transport.handleRequest(req, res, message); } finally { await mcp.close(); f.owners.delete(mcp); }
      };
      if (f.reply) await f.reply(req, res, message, normal); else await normal();
    })().catch(() => { res.destroy(); }); f.jobs.add(job); void job.finally(() => f.jobs.delete(job));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await Promise.allSettled([...f.jobs]);
    await Promise.allSettled([...f.owners].map(owner => owner.close())); await new Promise(resolve => server.close(resolve)); });
  f.fetch = async (url, init) => {
    assert.equal(url.href, f.d.resources.mcp); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer ' + f.access); assert.equal(new Headers(init.headers).get('cookie'), null);
    f.logical.push({ method: init.method, body: init.body }); f.signals.push(init.signal);
    const response = await fetch(origin + new URL(url).pathname, init);
    if (f.after) await f.after(response, init); return f.rewrite ? f.rewrite(response, init) : response;
  };
  f.make = (ports = {}) => createDelegatedMcpIdentityVerifierForTrustedPorts(f.d, { fetch: f.fetch, nowSeconds: () => 1000, timeoutMs, ...ports });
  f.verify = f.make(); f.run = () => f.verify(f.d, f.access, f.d.resources.mcp, f.ctx.value);
  f.raw = value => { f.reply = async (_req, res, message, normal) => { if (message?.method !== 'tools/call') return normal();
    res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(typeof value === 'function' ? value(message) : value); }; };
  return f;
}
const resultEnvelope = (id, row, result = {}) => JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(row) }], ...result } });

test('production factory is inactive; invalid configuration and reflective ports fail without effects', () => {
  const d = deployment(); assert.equal(typeof createDelegatedMcpIdentityVerifier(d), 'function');
  let hooks = 0; const accessor = { get fetch() { hooks++; throw Error(canary); } };
  const proxy = new Proxy({}, { getPrototypeOf() { hooks++; throw Error(canary); } });
  for (const ports of [accessor, proxy, { fetch: null }, { fetch, timeoutMs: 30001 }, { fetch, nowSeconds: null }]) {
    assert.throws(() => createDelegatedMcpIdentityVerifierForTrustedPorts(d, ports), refused('mcp_identity_configuration_invalid'));
  }
  const rest = deployment(); rest.client.resourceKinds = ['rest']; assert.throws(() => createDelegatedMcpIdentityVerifier(rest), refused());
  assert.equal(hooks, 0);
});

test('actual SDK1.29 exchange sends exact MCP bearer, fixed identity tool, joined optional405 and frozen authority', async t => {
  const f = await fixture(t), result = await f.run();
  assert.equal(result.projectId, f.row.project_id); assert.equal(result.resource, f.d.resources.mcp); assert.equal(result.expiresAtSeconds, 1300);
  assert.equal(Object.keys(result).length, 12); assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.grantScopes));
  assert.deepEqual(f.requests.filter(x => x.method === 'POST').map(x => x.message.method), ['initialize', 'notifications/initialized', 'tools/call']);
  assert.equal(f.requests.filter(x => x.method === 'GET').length, 1); assert.ok(f.requests.every(x => x.path === '/tools/mcp'));
  assert.deepEqual(f.requests.find(x => x.message?.method === 'tools/call').message.params, { name: 'get_delegated_identity', arguments: {} });
  assert.equal(f.logical.length, 4); assert.ok(f.signals.every(signal => signal.aborted)); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('REST audience, foreign deployment, nonaccess token, forged signals and expired parent have zero egress', async t => {
  const f = await fixture(t), other = deployment(); other.client.clientId = 'foreign';
  for (const [d, token, resource] of [[f.d, f.access, f.d.resources.rest], [other, f.access, f.d.resources.mcp],
    [f.d, 'bota_dr1_' + randomBytes(32).toString('base64url'), f.d.resources.mcp], [f.d, f.access + 'x', f.d.resources.mcp]]) {
    await assert.rejects(f.verify(d, token, resource, f.ctx.value), refused('mcp_identity_input_invalid'));
  }
  await assert.rejects(f.verify(f.d, f.access, f.d.resources.mcp, { signal: Object.create(AbortSignal.prototype), budget: { assertActive() {} } }), refused());
  f.ctx.state.expired = true; await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 0);
});

test('context retargeting before request and after headers refuses publication', async t => {
  const f = await fixture(t); f.ctx.value.budget.assertActive = () => { f.ctx.value.signal = new AbortController().signal; };
  await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 0);
  const g = await fixture(t); g.after = () => { g.ctx.value.budget = { assertActive() {} }; };
  await assert.rejects(g.run(), refused()); assert.equal(g.logical.length, 1);
});

test('raw envelope and text duplicate keys including escaped spellings are rejected before SDK projection', async t => {
  const f = await fixture(t);
  for (const raw of [message => resultEnvelope(message.id, f.row).replace('"jsonrpc":"2.0"', '"jsonrpc":"2.0","\\u006asonrpc":"2.0"'),
    message => resultEnvelope(message.id, f.row).replace('"content":', '"content":[],"content":'),
    message => JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: JSON.stringify(f.row).replace('"format_version":1', '"format_version":1,"\\u0066ormat_version":1') }] } })]) {
    f.raw(raw); await assert.rejects(f.run(), refused());
  }
});

test('malformed RPC/result/content, errors, extensions, BOM and invalid UTF8 disclose no upstream content', async t => {
  const f = await fixture(t);
  for (const raw of [message => resultEnvelope(message.id + 10, f.row), message => JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32000, message: canary } }),
    message => resultEnvelope(message.id, f.row, { isError: true }), message => resultEnvelope(message.id, f.row, { structuredContent: { private: canary } }),
    message => JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'image', data: canary, mimeType: 'image/png' }] } }),
    message => '\ufeff' + resultEnvelope(message.id, f.row), Buffer.from([0xff]), '[]', '{}']) {
    f.raw(raw); await assert.rejects(f.run(), refused());
  }
});

test('issuer/client/resource/scope/expiry changes and private identity fields are rejected', async t => {
  const f = await fixture(t), original = { ...f.row };
  for (const patch of [{ resource: f.d.resources.rest }, { client_id: 'other' }, { issuer: 'https://foreign.invalid' },
    { access_scopes: ['recordings:read'] }, { expires_at: 1000 }, { expires_at: 1301 }, { private: canary }]) {
    f.row = { ...original, ...patch }; await assert.rejects(f.run(), refused());
  }
});

test('status/SSE/session/encoding/declared and decoded body bounds cannot trigger retry or discovery', async t => {
  const f = await fixture(t);
  for (const [status, headers, body] of [[401, { 'WWW-Authenticate': 'Bearer resource_metadata="https://foreign.invalid/metadata"' }, canary],
    [200, { 'Content-Type': 'text/event-stream' }, 'data: ' + canary], [200, { 'Content-Type': 'application/json', 'Mcp-Session-Id': canary }, '{}'],
    [200, { 'Content-Type': 'application/json', 'Content-Encoding': 'identity' }, '{}'],
    [200, { 'Content-Type': 'application/json', 'Content-Length': '16385' }, ''], [200, { 'Content-Type': 'application/json' }, ' '.repeat(16385)]]) {
    f.reply = async (_req, res) => { res.writeHead(status, { ...headers, Connection: 'close' }); res.end(body); };
    const before = f.logical.length; await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, before + 1);
  }
});

test('optional GET accepts only empty405, with no successful SSE or hidden background work', async t => {
  const f = await fixture(t);
  for (const [status, body] of [[200, 'data: ' + canary], [405, canary]]) {
    f.reply = async (req, res, _message, normal) => { if (req.method !== 'GET') return normal(); res.writeHead(status, { 'Content-Type': 'text/event-stream' }); res.end(body); };
    await assert.rejects(f.run(), refused());
  }
});

test('redirect refuses before forwarding bearer to a foreign owned sink', async t => {
  let hits = 0; const sink = createServer((_req, res) => { hits++; res.end(); }); sink.listen(0, '127.0.0.1'); await once(sink, 'listening');
  t.after(async () => { sink.closeAllConnections(); await new Promise(resolve => sink.close(resolve)); });
  const f = await fixture(t); f.reply = (_req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${sink.address().port}/sink` }); res.end(); };
  await assert.rejects(f.run(), refused()); assert.equal(hits, 0); assert.equal(f.logical.length, 1);
});

test('parent cancellation joins an owned pre-header request', async t => {
  const f = await fixture(t), arrived = deferred(); f.reply = () => { arrived.resolve(); };
  const run = f.run(); await arrived.promise; f.ctx.controller.abort(); await assert.rejects(run, refused());
  assert.equal(f.logical.length, 1); assert.ok(f.signals.every(signal => signal.aborted)); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('parent cancellation and finite total timeout join owned stalled response bodies', async t => {
  for (const deadline of [false, true]) {
    const f = await fixture(t, deadline ? 50 : 3000), arrived = deferred();
    f.reply = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); arrived.resolve(); };
    const run = f.run(); await arrived.promise; if (!deadline) f.ctx.controller.abort(); await assert.rejects(run, refused());
    assert.equal(f.logical.length, 1); assert.ok(f.signals.every(signal => signal.aborted));
  }
});

test('native response cleanup rejection stays fixed and withheld until its owned cancellation settles', async t => {
  const f = await fixture(t), cancel = deferred(), entered = deferred();
  f.rewrite = async (response, init) => {
    if (JSON.parse(init.body ?? '{}').method !== 'tools/call') return response;
    await response.body.cancel(); return new Response(new ReadableStream({ cancel() { entered.resolve(); return cancel.promise; } }), { headers: { 'Content-Type': 'text/plain' } });
  };
  let settled = false; const run = f.run().finally(() => { settled = true; }); await entered.promise;
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false); cancel.reject(Error(canary)); await assert.rejects(run, refused());
});

test('parent loss during joined response cleanup cannot return a valid identity', async t => {
  const f = await fixture(t); f.after = (_response, init) => { if (JSON.parse(init.body ?? '{}').method === 'tools/call') f.ctx.controller.abort(); };
  await assert.rejects(f.run(), refused()); assert.ok(f.signals.every(signal => signal.aborted));
});

test('an owned held optional GET is joined before success, and cancellation withdraws every request', async t => {
  const f = await fixture(t), arrived = deferred(), unblock = deferred();
  f.reply = async (req, res, _message, normal) => {
    if (req.method !== 'GET') return normal(); arrived.resolve(); await unblock.promise; res.writeHead(405); res.end();
  };
  let settled = false; const run = f.run().finally(() => { settled = true; }); await arrived.promise;
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  f.ctx.controller.abort(); unblock.resolve(); await assert.rejects(run, refused()); assert.ok(f.signals.every(signal => signal.aborted));
});

test('fresh final clock rejects identity expiry during final authority/cleanup checks', async t => {
  const f = await fixture(t); let now = 1000, normalizedReads = 0;
  const verify = f.make({ nowSeconds() { normalizedReads++; if (normalizedReads >= 3) now = 1300; return now; } });
  await assert.rejects(verify(f.d, f.access, f.d.resources.mcp, f.ctx.value), refused());
  assert.equal(normalizedReads, 3); assert.equal(f.requests.filter(req => req.message?.method === 'tools/call').length, 1);
});

test('upstream rejected objects never reflect private errors or execute proxy/accessor hooks', async t => {
  const f = await fixture(t); let hooks = 0;
  for (const value of [Object.assign(Error(canary), { cause: Error(canary) }), new Proxy({}, { getPrototypeOf() { hooks++; throw Error(canary); } }),
    { get message() { hooks++; throw Error(canary); } }]) {
    const verify = f.make({ fetch: async () => { throw value; } }); await assert.rejects(verify(f.d, f.access, f.d.resources.mcp, f.ctx.value), refused());
  }
  assert.equal(hooks, 0);
});
