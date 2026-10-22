import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getEventListeners, once } from 'node:events';
import { createServer } from 'node:http';
import nodeTest from 'node:test';
import { createDelegatedRestIdentityVerifier, createDelegatedRestIdentityVerifierForTrustedPorts,
  DelegatedRestIdentityHttpError } from '../src/delegated-rest-identity-http.ts';

const test = (name, work) => nodeTest(name, { timeout: 10_000 }, work);
const canary = 'PRIVATE_REST_IDENTITY_CANARY';
const deployment = () => ({ version: 1, issuer: 'https://auth.fixture.invalid', endpoints: {
  authorization: 'https://auth.fixture.invalid/oauth/authorize', token: 'https://auth.fixture.invalid/oauth/token', revocation: 'https://auth.fixture.invalid/oauth/revoke' },
  resources: { rest: 'https://api.fixture.invalid/v1', mcp: 'https://mcp.fixture.invalid/mcp' }, client: { clientId: 'registered-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const endpoint = d => d.resources.rest + '/auth/delegated-identity';
const bearer = () => 'bota_da1_' + randomBytes(32).toString('base64url');
const dto = d => ({ format_version: 1, credential_type: 'developer_delegation', issuer: d.issuer, client_id: d.client.clientId,
  user_id: '11111111-1111-1111-1111-111111111111', organization_id: 'org_fixture', project_id: 'proj_fixture',
  grant_id: '22222222-2222-2222-2222-222222222222', family_id: '33333333-3333-3333-3333-333333333333', resource: d.resources.rest,
  grant_resources: [d.resources.rest, d.resources.mcp], grant_scopes: ['devices:read'], access_scopes: ['devices:read'], expires_at: 1300 });
function context() {
  const controller = new AbortController(), state = { expired: false };
  return { controller, state, value: { signal: controller.signal, budget: { assertActive() { if (state.expired) throw Error(canary); } } } };
}
function refused(code) { return error => {
  assert.ok(error instanceof DelegatedRestIdentityHttpError); if (code) assert.equal(error.code, code);
  assert.equal(error.cause, undefined); assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_REST_IDENTITY_CANARY|bota_d[acr]1_|fixture\.invalid/); return true;
}; }
async function fixture(t, timeoutMs = 3000) {
  const d = deployment(), f = { d, ctx: context(), access: bearer(), requests: [], logical: [], signals: [], after: null, transport: null,
    response: (req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(f.row)); } };
  f.row = dto(d);
  const server = createServer((req, res) => { f.requests.push({ path: req.url, method: req.method, headers: req.headers });
    try { f.response(req, res); } catch { res.destroy(); } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  f.origin = `http://127.0.0.1:${server.address().port}`;
  f.fetch = async (url, init) => {
    assert.equal(url, endpoint(d)); assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.equal(init.cache, 'no-store'); assert.equal(init.headers.Accept, 'application/json'); assert.equal(init.headers.Authorization, 'Bearer ' + f.access);
    assert.equal(init.body, undefined); assert.equal(init.headers.Cookie, undefined); f.logical.push(url); f.signals.push(init.signal);
    const result = f.transport ? await f.transport(url, init) : await fetch(f.origin + new URL(url).pathname, init);
    if (f.after) await f.after(result); return result;
  };
  f.make = (ports = {}) => createDelegatedRestIdentityVerifierForTrustedPorts(d, { identityUrl: endpoint(d) }, { fetch: f.fetch, nowSeconds: () => 1000, timeoutMs, ...ports });
  f.verify = f.make(); f.run = () => f.verify(d, f.access, d.resources.rest, f.ctx.value);
  return f;
}

test('explicit HTTPS endpoint binds REST origin/path and factories do no egress', () => {
  const d = deployment(); assert.equal(typeof createDelegatedRestIdentityVerifier(d, { identityUrl: endpoint(d) }), 'function');
  const root = deployment(); root.resources.rest = 'https://api.fixture.invalid';
  assert.equal(typeof createDelegatedRestIdentityVerifier(root, { identityUrl: endpoint(root) }), 'function');
  for (const url of ['http://api.fixture.invalid/v1/auth/delegated-identity', endpoint(d) + '/', endpoint(d) + '?x=1',
    'https://other.fixture.invalid/v1/auth/delegated-identity', d.resources.mcp + '/auth/delegated-identity', d.endpoints.token]) {
    assert.throws(() => createDelegatedRestIdentityVerifier(d, { identityUrl: url }), refused('identity_http_configuration_invalid'));
  }
  const mcp = deployment(); mcp.client.resourceKinds = ['mcp'];
  assert.throws(() => createDelegatedRestIdentityVerifier(mcp, { identityUrl: endpoint(mcp) }), refused());
  for (const ports of [{ fetch: null }, { fetch, timeoutMs: 30001 }, { fetch, nowSeconds: null }]) {
    assert.throws(() => createDelegatedRestIdentityVerifierForTrustedPorts(d, { identityUrl: endpoint(d) }, ports), refused());
  }
});

test('actual GET sends only REST access bearer and returns frozen authoritative identity after owned cleanup', async t => {
  const f = await fixture(t), result = await f.run();
  assert.equal(result.projectId, f.row.project_id); assert.equal(result.expiresAtSeconds, 1300); assert.equal(Object.keys(result).length, 12);
  assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.grantScopes));
  assert.deepEqual(f.requests.map(x => [x.method, x.path]), [['GET', '/v1/auth/delegated-identity']]);
  assert.equal(f.requests[0].headers.authorization, 'Bearer ' + f.access); assert.equal(f.requests[0].headers.cookie, undefined);
  assert.equal(f.signals[0].aborted, true); assert.equal(f.ctx.controller.signal.aborted, false);
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('MCP resource, wrong deployment, nonaccess credentials and expired parent refuse before bearer egress', async t => {
  const f = await fixture(t), other = deployment(); other.client.clientId = 'other-client';
  for (const [d, token, resource] of [[f.d, f.access, f.d.resources.mcp], [other, f.access, f.d.resources.rest],
    [f.d, 'bota_dr1_' + randomBytes(32).toString('base64url'), f.d.resources.rest], [f.d, f.access + 'x', f.d.resources.rest]]) {
    await assert.rejects(f.verify(d, token, resource, f.ctx.value), refused('identity_http_input_invalid'));
  }
  f.ctx.state.expired = true; await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 0);
});

test('retargeted context and assertion-time field mutation grant no request or result authority', async t => {
  const f = await fixture(t); f.ctx.value.budget.assertActive = () => { f.ctx.value.signal = new AbortController().signal; };
  await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 0);
  const g = await fixture(t); g.after = () => { g.ctx.value.budget = { assertActive() {} }; };
  await assert.rejects(g.run(), refused()); assert.equal(g.logical.length, 1); assert.equal(g.signals[0].aborted, true);
});

test('raw duplicate keys including escaped names refuse, while escaped keys and key-like string data remain valid', async t => {
  const f = await fixture(t), base = JSON.stringify(f.row);
  for (const duplicate of [',"format_version":1}', ',"\\u0066ormat_version":1}']) {
    f.response = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(base.slice(0, -1) + duplicate); };
    await assert.rejects(f.run(), refused());
  }
  f.row.project_id = 'project "format_version": 1';
  f.response = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' });
    res.end(JSON.stringify(f.row).replace('"format_version"', '"\\u0066ormat_version"')); };
  assert.equal((await f.run()).projectId, f.row.project_id);
});

test('private extensions, nested arrays/objects, BOM and invalid UTF8 never reach identity publication', async t => {
  const f = await fixture(t);
  const values = [JSON.stringify({ ...f.row, private: canary }), JSON.stringify({ ...f.row, grant_scopes: [['devices:read']] }),
    JSON.stringify({ ...f.row, grant_resources: [{ url: f.d.resources.rest }] }), '\ufeff' + JSON.stringify(f.row), Buffer.from([0xff]), '{}', '[]', 'null'];
  for (const value of values) {
    f.response = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(value); };
    await assert.rejects(f.run(), refused());
  }
});

test('untrusted response binding and stale metadata are refused after a successful HTTP read', async t => {
  const f = await fixture(t), original = { ...f.row };
  for (const patch of [{ resource: f.d.resources.mcp }, { client_id: 'other' }, { issuer: 'https://other.fixture.invalid' },
    { access_scopes: ['recordings:read'] }, { expires_at: 1000 }, { expires_at: 1301 }]) {
    f.row = { ...original, ...patch }; await assert.rejects(f.run(), refused());
  }
  assert.equal(f.requests.length, 6);
});

test('redirects do not forward the access bearer to an owned foreign sink', async t => {
  let received = 0; const sink = createServer((_req, res) => { received++; res.end(); }); sink.listen(0, '127.0.0.1'); await once(sink, 'listening');
  t.after(async () => { sink.closeAllConnections(); await new Promise(resolve => sink.close(resolve)); });
  const f = await fixture(t); f.response = (_req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${sink.address().port}/sink`, Connection: 'close' }); res.end(); };
  await assert.rejects(f.run(), refused()); assert.equal(received, 0); assert.equal(f.logical.length, 1);
});

test('status, content type, encoding and declared/decoded size boundaries reject without retry', async t => {
  const f = await fixture(t);
  for (const [status, headers, value] of [[503, {}, canary], [200, { 'Content-Type': 'text/plain' }, JSON.stringify(f.row)],
    [200, { 'Content-Type': 'application/json', 'Content-Encoding': 'identity' }, JSON.stringify(f.row)],
    [200, { 'Content-Type': 'application/json', 'Content-Length': '16385' }, ''],
    [200, { 'Content-Type': 'application/json' }, ' '.repeat(16385)]]) {
    f.response = (_req, res) => { res.writeHead(status, { ...headers, Connection: 'close' }); res.end(value); };
    const before = f.logical.length; await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, before + 1);
  }
});

test('parent cancellation interrupts owned stalled body and clears signal listeners', async t => {
  const f = await fixture(t); let arrived; const seen = new Promise(resolve => { arrived = resolve; });
  f.response = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.flushHeaders(); res.write('{'); arrived(); };
  const run = f.run(); await seen; f.ctx.controller.abort(); await assert.rejects(run, refused());
  assert.equal(f.logical.length, 1); assert.equal(f.signals[0].aborted, true); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('parent cancellation before response headers joins the native GET without retry', async t => {
  const f = await fixture(t); let arrived; const seen = new Promise(resolve => { arrived = resolve; });
  f.response = () => { arrived(); };
  const run = f.run(); await seen; f.ctx.controller.abort(); await assert.rejects(run, refused());
  assert.equal(f.logical.length, 1); assert.equal(f.signals[0].aborted, true);
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('original finite deadline aborts a stalled body without a second request', async t => {
  const f = await fixture(t, 1000);
  f.response = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.flushHeaders(); res.write('{'); };
  await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 1); assert.equal(f.signals[0].aborted, true);
});

test('late parent expiry and throwing clock suppress an otherwise valid response', async t => {
  const f = await fixture(t); f.after = () => { f.ctx.state.expired = true; };
  await assert.rejects(f.run(), refused()); assert.equal(f.logical.length, 1);
  const g = await fixture(t), verify = g.make({ nowSeconds: () => { throw Error(canary); } });
  await assert.rejects(verify(g.d, g.access, g.d.resources.rest, g.ctx.value), refused()); assert.equal(g.signals[0].aborted, true);
});

test('captured native response/body slots ignore shadow getters and join cancellation failure safely', async t => {
  const f = await fixture(t); let hooks = 0;
  f.transport = async () => { const response = new Response(JSON.stringify(f.row), { headers: { 'Content-Type': 'application/json' } });
    for (const name of ['status', 'body', 'headers', 'redirected']) Object.defineProperty(response, name, { get() { hooks++; throw Error(canary); } }); return response; };
  assert.equal((await f.run()).familyId, f.row.family_id); assert.equal(hooks, 0);
  f.transport = async () => new Response(new ReadableStream({ cancel() { hooks++; throw Error(canary); } }), { status: 503 });
  await assert.rejects(f.run(), refused()); assert.equal(hooks, 1); assert.equal(f.signals.at(-1).aborted, true);
});

test('canonical options/context descriptors refuse getters and proxy hooks without invoking them', async t => {
  const d = deployment(); let hooks = 0;
  const options = Object.defineProperty({}, 'identityUrl', { enumerable: true, get() { hooks++; return endpoint(d); } });
  assert.throws(() => createDelegatedRestIdentityVerifier(d, options), refused());
  const f = await fixture(t), ctx = new Proxy(f.ctx.value, { ownKeys() { hooks++; throw Error(canary); } });
  await assert.rejects(f.verify(f.d, f.access, f.d.resources.rest, ctx), refused()); assert.equal(hooks, 0); assert.equal(f.logical.length, 0);
});
