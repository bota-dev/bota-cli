import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { Command } from 'commander';
import { BotaClient, createCommandClient } from '../src/client.ts';
import { getApiKey, getApiUrl, withInvocationCredential } from '../src/config.ts';
import { registerDevices } from '../src/commands/devices.ts';
import { DelegatedFamilyEngine, createTrustedDelegatedEnrollmentHandoff } from '../src/delegated-family-engine.ts';
import { decodeDelegatedFamilySnapshotBytes, encodeDelegatedFamilySnapshot } from '../src/delegated-family-state.ts';
import { bindDelegatedInvocationForTrustedPorts, captureDelegatedMcpInvocation } from '../src/delegated-invocation.ts';

const context = () => ({ signal: new AbortController().signal, budget: { assertActive() {} } });
const secret = kind => `bota_d${kind}1_${randomBytes(32).toString('base64url')}`;
async function fixture(t, accessScopes = ['devices:read', 'recordings:read'], ttlSeconds = 300) {
  const deployment = { version: 1, issuer: 'https://issuer.example.test', endpoints: {
    authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
    resources: { rest: 'https://rest.example.test/customer/v1', mcp: 'https://mcp.example.test/custom/agent' }, client: {
      clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } };
  const grantId = randomUUID(), familyId = randomUUID(), userId = randomUUID();
  const snapshots = new Map(), secrets = new Map(), identities = new Map(), requests = [], queues = new Map();
  const f = { requests, exchanges: 0, checks: 0, revoked: false, behavior: null, held: 0, maxHeld: 0 };
  const key = { storeId: 'session-test', issuer: deployment.issuer, clientId: deployment.client.clientId, familyId };
  const pair = resource => {
    const value = { accessToken: secret('a'), refreshToken: secret('r'), resource, grantId, familyId, scopes: accessScopes,
      expiresAtSeconds: Math.floor(Date.now() / 1000) + ttlSeconds };
    identities.set(value.accessToken, { issuer: deployment.issuer, clientId: deployment.client.clientId, userId,
      organizationId: 'org-fixture', projectId: 'project-fixture', grantId, familyId,
      grantResourceUris: Object.values(deployment.resources), grantScopes: accessScopes, resource, accessScopes,
      expiresAtSeconds: value.expiresAtSeconds });
    return value;
  };
  const initial = pair(deployment.resources.rest);
  const ports = {
    store: { id: key.storeId,
      async read(ref) { return secrets.has(JSON.stringify(ref)) ? { status: 'present', refreshToken: secrets.get(JSON.stringify(ref)) } : { status: 'absent' }; },
      async write(ref, value) { const key = JSON.stringify(ref); if (secrets.has(key)) return 'not_stored'; secrets.set(key, value); return 'stored'; },
      async delete(ref) { return secrets.delete(JSON.stringify(ref)) ? 'deleted' : 'absent'; } },
    snapshots: { async load(key) { const bytes = snapshots.get(JSON.stringify(key)); return bytes ? decodeDelegatedFamilySnapshotBytes(bytes, key) : null; },
      async publish(key, revision, next) { const current = await this.load(key); if ((current?.revision ?? null) !== revision) return 'not_committed';
        snapshots.set(JSON.stringify(key), encodeDelegatedFamilySnapshot(next, key)); return 'committed'; } },
    lease: { async runExclusive(key, ctx, work) { const name = JSON.stringify(key), previous = queues.get(name) ?? Promise.resolve(); let release;
      const done = new Promise(resolve => { release = resolve; }); queues.set(name, previous.then(() => done)); await previous;
      f.held++; f.maxHeld = Math.max(f.maxHeld, f.held); try { ctx.budget.assertActive(); return await work(); }
      finally { try { if (f.beforeRelease) await f.beforeRelease(); } finally { f.held--; release(); } } } },
    async verifyAccess(d, access, resource, ctx) { ctx.budget.assertActive(); f.checks++; assert.deepEqual(d, deployment);
      if (f.revoked || !identities.has(access)) throw Error('PRIVATE_IDENTITY_ERROR');
      const identity = structuredClone(identities.get(access)); assert.equal(identity.resource, resource); return identity; },
    async exchange(d, refresh, resource, ctx) { ctx.budget.assertActive(); f.exchanges++; assert.ok([...secrets.values()].includes(refresh)); return pair(resource); },
    async revoke() { f.revoked = true; return { grantId, familyId }; }, nowSeconds: () => Math.floor(Date.now() / 1000),
  };
  const engine = new DelegatedFamilyEngine(ports);
  await engine.enroll(createTrustedDelegatedEnrollmentHandoff(deployment, async () => initial), context());
  const server = createServer((request, response) => {
    requests.push({ url: request.url, method: request.method, authorization: request.headers.authorization });
    if (f.behavior) return f.behavior(request, response);
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ data: [{ id: 'dev_fixture' }] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const fetchPort = async (input, init) => { const url = new URL(input); assert.ok(Object.values(deployment.resources).some(value => url.href.startsWith(value)));
    const response = await fetch(`http://127.0.0.1:${server.address().port}${url.pathname}${url.search}`, init);
    if (f.afterFetch) return await f.afterFetch(response, init) ?? response; return response; };
  f.binding = await bindDelegatedInvocationForTrustedPorts(engine, key, deployment, context(), { fetch: fetchPort });
  f.anotherBinding = () => bindDelegatedInvocationForTrustedPorts(new DelegatedFamilyEngine(ports), key, deployment, context(), { fetch: fetchPort });
  f.engine = engine; f.key = key; f.deployment = deployment; f.run = action => f.binding.run('rest', context(), action);
  f.initialExpiry = initial.expiresAtSeconds;
  return f;
}

test('actual REST client uses the exact selected resource prefix and freshly admitted bearer', async t => {
  const f = await fixture(t);
  const value = await f.run(() => new BotaClient().get('/v1/devices', { limit: 2 }));
  assert.equal(value.data[0].id, 'dev_fixture'); assert.equal(f.requests[0].url, '/customer/v1/devices?limit=2');
  assert.match(f.requests[0].authorization, /^Bearer bota_da1_/); assert.ok(f.checks >= 3);
});

test('actual devices command can consume the delegated client without reading a project key', async t => {
  const f = await fixture(t), command = new Command().option('--json'); registerDevices(command);
  const original = console.log, output = []; console.log = value => output.push(value);
  try { await f.run(() => command.parseAsync(['node', 'bota', '--json', 'devices', 'list'])); }
  finally { console.log = original; }
  assert.equal(JSON.parse(output[0]).data[0].id, 'dev_fixture'); assert.equal(f.requests.length, 1);
});

test('delegated calls never fall through to API-key readers or explicit credential overrides', async t => {
  const f = await fixture(t);
  await f.run(async () => {
    assert.throws(getApiKey); assert.throws(getApiUrl);
    assert.throws(() => new BotaClient({ apiKey: 'sk_COMPATIBILITY_CANARY' }));
    assert.throws(() => new BotaClient({ apiUrl: 'https://other.example.test' }));
  });
  assert.equal(f.requests.length, 0);
});

test('unsupported writes, fleet/admin/nested paths and secret query fields refuse before egress', async t => {
  const f = await fixture(t);
  await f.run(async () => {
    const client = new BotaClient();
    for (const path of ['/v1/devices/stats', '/v1/integrations', '/v1/recordings/r/transcriptions', '/v1/auth/identity', '/v1/devices/../recordings']) await assert.rejects(client.get(path));
    await assert.rejects(client.post('/v1/end-users', {})); await assert.rejects(client.delete('/v1/devices/dev_fixture'));
    await assert.rejects(client.get('/v1/devices', { access_token: 'PRIVATE_CANARY' }));
  });
  assert.equal(f.requests.length, 0);
});

test('granted scopes gate the local request before any REST egress', async t => {
  const f = await fixture(t, ['devices:read']);
  await f.run(async () => { await assert.rejects(new BotaClient().get('/v1/recordings')); });
  assert.equal(f.requests.length, 0);
});

test('REST and MCP scopes cannot be interchanged or used with legacy APIs', async t => {
  const f = await fixture(t);
  await f.run(async () => { assert.throws(captureDelegatedMcpInvocation); });
  await f.binding.run('mcp', context(), async () => {
    assert.throws(() => new BotaClient()); assert.throws(getApiKey);
    const access = captureDelegatedMcpInvocation(); assert.equal(access.url, f.deployment.resources.mcp);
    access.authorizeTool('list_devices'); assert.throws(() => access.authorizeTool('create_transcription'));
    assert.throws(() => access.authorizeTool('get_recording'));
    await assert.rejects(access.fetch('https://foreign.example.test', {}));
  });
  assert.equal(f.requests.length, 0); assert.equal(f.exchanges, 1);
});

test('clients and unjoined descendants retire when their action settles', async t => {
  const f = await fixture(t); let client, later;
  await f.run(async () => { client = new BotaClient(); later = new Promise(resolve => setTimeout(async () => {
    await assert.rejects(client.get('/v1/devices')); resolve();
  }, 25)); });
  await assert.rejects(client.get('/v1/devices')); await later; assert.equal(f.requests.length, 0);
});

test('parent authority replacement is refused after the trusted budget callback', async t => {
  const f = await fixture(t), parent = context(); let calls = 0;
  parent.budget.assertActive = () => { if (++calls > 2) parent.budget = { assertActive() {} }; };
  await assert.rejects(f.binding.run('rest', parent, () => new BotaClient().get('/v1/devices')));
  assert.equal(f.requests.length, 0);
});

test('current remote revocation prevents another action despite a cached access token', async t => {
  const f = await fixture(t); await f.run(() => new BotaClient().get('/v1/devices')); f.revoked = true;
  await assert.rejects(f.run(() => new BotaClient().get('/v1/devices'))); assert.equal(f.requests.length, 1);
});

test('two resource consumers share the actual family-engine lease and rotate serially', async t => {
  const f = await fixture(t), another = await f.anotherBinding();
  await Promise.all([f.run(() => new BotaClient().get('/v1/devices')),
    another.run('mcp', context(), async () => { captureDelegatedMcpInvocation().authorizeTool('list_devices'); })]);
  assert.equal(f.maxHeld, 1); assert.equal(f.held, 0); assert.equal(f.exchanges, 1);
});

test('opaque upstream error and wrong content type produce only a fixed delegated failure', async t => {
  const f = await fixture(t); f.behavior = (_request, response) => { response.writeHead(403, { 'Content-Type': 'application/json' }); response.end('{"error":"PRIVATE_RESPONSE_CANARY"}'); };
  await assert.rejects(f.run(() => new BotaClient().get('/v1/devices')), error => { assert.doesNotMatch(String(error), /PRIVATE_RESPONSE_CANARY|bota_da1_/); return true; });
  assert.equal(f.held, 0);
});

test('cancelled parent refuses before traffic and exposes no raw budget error', async t => {
  const f = await fixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(f.binding.run('rest', { signal: controller.signal, budget: { assertActive() { throw Error('PRIVATE_BUDGET_CANARY'); } } },
    () => new BotaClient().get('/v1/devices')), error => { assert.doesNotMatch(String(error), /PRIVATE_BUDGET_CANARY/); return true; });
  assert.equal(f.requests.length, 0);
});

test('query accessors are refused without executing hooks or sending a token', async t => {
  const f = await fixture(t); let hooks = 0;
  const query = Object.defineProperty({}, 'cursor', { enumerable: true, get() { hooks++; throw Error('PRIVATE_QUERY_CANARY'); } });
  await f.run(async () => { await assert.rejects(new BotaClient().get('/v1/devices', query)); });
  assert.equal(hooks, 0); assert.equal(f.requests.length, 0);
});

test('oversized response is cancelled and the family lease is released', async t => {
  const f = await fixture(t);
  f.behavior = (_request, response) => { response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(1024 * 1024 + 1) }); response.write('{'); };
  await assert.rejects(f.run(() => new BotaClient().get('/v1/devices')));
  assert.equal(f.held, 0); assert.equal(f.requests.length, 1);
});

test('body cancellation joins the native reader before the action releases its lease', async t => {
  const f = await fixture(t), controller = new AbortController(); let started;
  const headersSent = new Promise(resolve => { started = resolve; });
  f.behavior = (_request, response) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{"data":'); started(); };
  const action = f.binding.run('rest', { signal: controller.signal, budget: { assertActive() {} } }, () => new BotaClient().get('/v1/devices'));
  await headersSent; assert.equal(f.held, 1); controller.abort(); await assert.rejects(action); assert.equal(f.held, 0);
});

test('unawaited REST work is cancelled and joined before releasing the actual family lease', async t => {
  const f = await fixture(t); let entered, aborted, release;
  const started = new Promise(resolve => { entered = resolve; }), stopped = new Promise(resolve => { aborted = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  f.afterFetch = async (_response, init) => { entered(); await new Promise(resolve => {
    if (init.signal.aborted) resolve(); else init.signal.addEventListener('abort', resolve, { once: true });
  }); aborted(); await gate; };
  let settled = false;
  const action = f.run(async () => { void new BotaClient().get('/v1/devices').catch(() => undefined); await started; return 'premature'; })
    .finally(() => { settled = true; });
  try { await stopped; assert.equal(f.held, 1); assert.equal(settled, false); }
  finally { release(); }
  await assert.rejects(action); assert.equal(f.held, 0);
});

test('access expiry during joined transport cleanup cannot publish success', { timeout: 6000 }, async t => {
  const f = await fixture(t, ['devices:read'], 2); let entered, aborted, release;
  const started = new Promise(resolve => { entered = resolve; }), stopped = new Promise(resolve => { aborted = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  f.behavior = (_request, response) => { response.writeHead(405); response.end(); };
  f.afterFetch = async (_response, init) => { entered(); await new Promise(resolve => {
    if (init.signal.aborted) resolve(); else init.signal.addEventListener('abort', resolve, { once: true });
  }); aborted(); await gate; };
  let settled = false;
  const action = f.binding.run('mcp', context(), async () => {
    const access = captureDelegatedMcpInvocation();
    void access.fetch(access.url, { method: 'GET', headers: { Authorization: `Bearer ${access.accessToken}` } }).catch(() => undefined);
    await started; return 'cannot-publish-after-expiry';
  }).finally(() => { settled = true; });
  try {
    await stopped; assert.equal(settled, false); assert.equal(f.held, 1);
    while (Math.floor(Date.now() / 1000) < f.initialExpiry) await new Promise(resolve => setTimeout(resolve, 20));
  } finally { release(); }
  await assert.rejects(action); assert.equal(f.held, 0);
});

test('API-key profile commands preserve canonical equivalent URL overrides without native operations', async t => {
  const original = globalThis.fetch, seen = []; globalThis.fetch = async (url, init) => { seen.push({ url, init }); return new Response('{"data":[]}', { headers: { 'Content-Type': 'application/json' } }); };
  t.after(() => { globalThis.fetch = original; });
  const identity = { project_id: 'project-fixture', organization_id: 'org-fixture', key_id: 'key-fixture', key_type: 'secret',
    is_test_mode: true, scope_mode: 'project_secret', scopes: null };
  for (const override of ['https://api.example.test/', 'https://API.example.test:443/', 'https://api.example.test:443']) {
    await withInvocationCredential({ apiOrigin: 'https://api.example.test', apiKey: 'sk_SYNTHETIC_FIXTURE', identity }, context(),
      () => createCommandClient(override).get('/v1/devices'));
  }
  assert.equal(seen.length, 3); assert.ok(seen.every(item => item.url === 'https://api.example.test/v1/devices'));
});

test('background MCP cancellation joins and refuses a rejected native body cleanup', async t => {
  const f = await fixture(t); let entered, cleanupEntered, release;
  const started = new Promise(resolve => { entered = resolve; }), cleaning = new Promise(resolve => { cleanupEntered = resolve; });
  const gate = new Promise(resolve => { release = resolve; }); let settled = false;
  f.behavior = (_request, response) => { response.writeHead(405); response.end(); };
  f.afterFetch = async (response, init) => {
    await response.body?.cancel(); entered();
    await new Promise(resolve => { if (init.signal.aborted) resolve(); else init.signal.addEventListener('abort', resolve, { once: true }); });
    return new Response(new ReadableStream({ async cancel() { cleanupEntered(); await gate; throw Error('PRIVATE_CLEANUP_CANARY'); } }), { status: 405 });
  };
  const action = f.binding.run('mcp', context(), async () => {
    const access = captureDelegatedMcpInvocation();
    void access.fetch(access.url, { method: 'GET', headers: { Authorization: `Bearer ${access.accessToken}` } }).catch(() => undefined);
    await started; return 'must-not-publish';
  }).finally(() => { settled = true; });
  try { await cleaning; assert.equal(f.held, 1); assert.equal(settled, false); }
  finally { release(); }
  await assert.rejects(action, error => { assert.doesNotMatch(String(error), /PRIVATE_CLEANUP_CANARY/); return true; });
  assert.equal(f.held, 0);
});

test('expiry while the actual lease releases refuses an otherwise completed action', { timeout: 6000 }, async t => {
  const f = await fixture(t, ['devices:read'], 2); let entered, release;
  const releasing = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { release = resolve; });
  f.beforeRelease = async () => { entered(); await gate; }; let settled = false;
  const action = f.run(() => new BotaClient().get('/v1/devices')).finally(() => { settled = true; });
  try {
    await releasing; assert.equal(f.held, 1); assert.equal(settled, false);
    while (Math.floor(Date.now() / 1000) < f.initialExpiry) await new Promise(resolve => setTimeout(resolve, 20));
  } finally { release(); }
  await assert.rejects(action); assert.equal(f.held, 0);
});
