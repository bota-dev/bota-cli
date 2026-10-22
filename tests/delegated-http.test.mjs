import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners, once } from 'node:events';
import { createServer, request } from 'node:http';
import { performance } from 'node:perf_hooks';
import { gzipSync } from 'node:zlib';
import nodeTest from 'node:test';
import { createDelegatedHttpAdapter, createDelegatedHttpAdapterForTrustedPorts, DelegatedHttpError } from '../src/delegated-http.ts';
import { startDelegatedLoginAttempt } from '../src/delegated-login.ts';
import { createTrustedDelegatedEnrollmentHandoff, DelegatedFamilyEngine } from '../src/delegated-family-engine.ts';

const canary = 'PRIVATE_HTTP_CANARY';
const test = (name, work) => nodeTest(name, { timeout: 10_000 }, work);
const credential = kind => `bota_d${kind}1_${randomBytes(32).toString('base64url')}`;
const deployment = () => ({ version: 1, issuer: 'https://issuer.example.test', endpoints: {
  authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
  resources: { rest: 'https://api.example.test/v1', mcp: 'https://mcp.example.test/mcp' }, client: { clientId: 'registered-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
function context() { const controller = new AbortController(), state = { expired: false };
  return { controller, state, value: { signal: controller.signal, budget: { assertActive() { if (state.expired) throw Error(canary); } } } }; }
function failure(submitted, ...codes) { return error => { assert.ok(error instanceof DelegatedHttpError); assert.equal(error.mutationSubmitted, submitted);
  if (codes.length) assert.ok(codes.includes(error.code), error.code);
  assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_HTTP_CANARY|bota_d[acr]1_|example\.test/); assert.equal(error.cause, undefined); return true; }; }
const json = (res, value) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
async function fixture(t, timeoutMs = 1500) {
  const d = deployment(), ctx = context(), accesses = new Map();
  const f = { d, ctx, accesses, requests: [], logical: [], verifierContexts: [], grantId: randomUUID(), familyId: randomUUID(), userId: randomUUID(),
    tokenResponse: (res, wire) => json(res, wire), revokeResponse: res => json(res, { bota_revoked: true, bota_grant_id: f.grantId, bota_family_id: f.familyId }),
    identityModifier: value => value, verifierAfter: null, fetchAfter: null };
  const server = createServer(async (req, res) => {
    try {
      let text = ''; for await (const bytes of req) { text += bytes; assert.ok(text.length <= 4096); }
      f.requests.push({ path: req.url, headers: req.headers, body: text });
      if (req.url === '/oauth/token') {
        const fields = new URLSearchParams(text), resource = fields.get('resource'), access = credential('a');
        const identity = { issuer: d.issuer, clientId: d.client.clientId, userId: f.userId, organizationId: 'org', projectId: 'project', grantId: f.grantId,
          familyId: f.familyId, grantResourceUris: [d.resources.rest, d.resources.mcp], grantScopes: ['devices:read', 'recordings:read'],
          resource, accessScopes: ['devices:read', 'recordings:read'], expiresAtSeconds: 1300 };
        accesses.set(access, identity);
        const wire = { access_token: access, refresh_token: credential('r'), token_type: 'Bearer', expires_in: 299, resource,
          bota_grant_id: f.grantId, bota_family_id: f.familyId, scope: 'devices:read recordings:read' };
        f.lastWire = wire; f.tokenResponse(res, wire, fields);
      } else if (req.url === '/oauth/revoke') f.revokeResponse(res, new URLSearchParams(text));
      else if (req.url === '/fixture/rest-identity' || req.url === '/fixture/mcp-identity') {
        const access = req.headers.authorization?.slice(7), identity = accesses.get(access);
        assert.ok(identity); assert.equal(req.url, identity.resource === d.resources.rest ? '/fixture/rest-identity' : '/fixture/mcp-identity');
        json(res, identity);
      } else { res.writeHead(404); res.end(canary); }
    } catch { res.destroy(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  f.origin = `http://127.0.0.1:${server.address().port}`;
  f.fetch = async (url, init) => {
    assert.ok([d.endpoints.token, d.endpoints.revocation].includes(url)); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.equal(init.cache, 'no-store'); assert.equal(init.headers.Authorization, undefined); assert.equal(init.headers.Cookie, undefined);
    f.logical.push(url); const result = await fetch(f.origin + new URL(url).pathname, init);
    if (f.fetchAfter) await f.fetchAfter(result); return result;
  };
  f.verifier = async (selected, access, resource, actualContext) => {
    assert.deepEqual(selected, d); actualContext.budget.assertActive(); f.verifierContexts.push(actualContext);
    assert.equal(accesses.get(access)?.resource, resource);
    const response = await fetch(f.origin + (resource === d.resources.rest ? '/fixture/rest-identity' : '/fixture/mcp-identity'), {
      headers: { Authorization: 'Bearer ' + access }, signal: actualContext.signal, redirect: 'error', credentials: 'omit' });
    let value; try { value = await response.json(); } finally { if (response.body && !response.body.locked) await response.body.cancel(); }
    actualContext.budget.assertActive(); if (f.verifierAfter) await f.verifierAfter(actualContext); return f.identityModifier(value);
  };
  f.make = () => createDelegatedHttpAdapterForTrustedPorts(d, { fetch: f.fetch, verifyAccess: f.verifier, nowSeconds: () => 1000, timeoutMs });
  f.adapter = f.make(); f.refresh = () => f.adapter.exchange(d, credential('r'), d.resources.rest, ctx.value);
  f.expected = () => ({ grantId: f.grantId, familyId: f.familyId });
  return f;
}
async function completed(t, d, choice = {}) {
  const attempt = await startDelegatedLoginAttempt(d, { resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'],
    scopes: ['devices:read', 'recordings:read'], loopbackHost: '127.0.0.1', ...choice }, { timeoutMs: 5000 });
  t.after(() => attempt.cancel()); const code = credential('c'), callback = new URL(attempt.redirectUri);
  callback.search = new URLSearchParams({ code, state: new URL(attempt.authorizationUrl).searchParams.get('state') }).toString();
  await new Promise((resolve, reject) => { const req = request(callback, { agent: false }, res => { res.resume(); res.once('end', resolve); }); req.on('error', reject); req.end(); });
  await attempt.result; return { attempt, code };
}

test('inactive factories require explicit configuration and verifier without contacting any endpoint', () => {
  const d = deployment(); assert.equal(createDelegatedHttpAdapter(d, async () => {}).stage, 'inactive-one-attempt-http');
  for (const args of [[undefined, {}], [d, {}], [d, { fetch, verifyAccess: null }], [d, { fetch, verifyAccess: async () => {}, timeoutMs: 30001 }]]) {
    assert.throws(() => createDelegatedHttpAdapterForTrustedPorts(...args), failure(false, 'http_configuration_invalid'));
  }
});

test('one refresh form POST and actual resource identity read preserve authoritative exact expiry and scopes', async t => {
  const f = await fixture(t), prior = credential('r');
  const pair = await f.adapter.exchange(f.d, prior, f.d.resources.rest, f.ctx.value);
  assert.equal(pair.expiresAtSeconds, 1300); assert.notEqual(pair.expiresAtSeconds, 1000 + f.lastWire.expires_in);
  assert.deepEqual(pair.scopes, ['devices:read', 'recordings:read']); assert.ok(Object.isFrozen(pair));
  const request = f.requests[0]; assert.equal(request.path, '/oauth/token'); assert.equal(request.headers.authorization, undefined); assert.equal(request.headers.cookie, undefined);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(request.body)), { grant_type: 'refresh_token', client_id: f.d.client.clientId, refresh_token: prior, resource: f.d.resources.rest });
  assert.equal((await f.adapter.verifyAccess(f.d, pair.accessToken, pair.resource, f.ctx.value)).familyId, pair.familyId);
  assert.deepEqual(f.requests.map(value => value.path), ['/oauth/token', '/fixture/rest-identity', '/fixture/rest-identity']);
  f.verifierContexts.forEach((issued, index) => { assert.equal(issued.signal.aborted, true); assert.throws(() => issued.budget.assertActive(), failure(index === 0, 'http_unknown')); });
  assert.equal(f.ctx.controller.signal.aborted, false); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('relative expires_in is range-only plausibility and never manufactured into authoritative absolute expiry', async t => {
  const f = await fixture(t); f.tokenResponse = (res, wire) => json(res, { ...wire, expires_in: 1 });
  const pair = await f.refresh(); assert.equal(pair.expiresAtSeconds, 1300); assert.notEqual(pair.expiresAtSeconds, 1001);
});

test('issued-access ledger refuses unknown, wrong-resource and another-factory tokens before identity egress', async t => {
  const f = await fixture(t), pair = await f.refresh(), before = f.requests.length;
  for (const [adapter, access, resource] of [[f.adapter, pair.accessToken, f.d.resources.mcp], [f.adapter, credential('a'), pair.resource], [f.make(), pair.accessToken, pair.resource]]) {
    await assert.rejects(adapter.verifyAccess(f.d, access, resource, f.ctx.value), failure(false, 'http_input_invalid'));
  }
  assert.equal(f.requests.length, before);
  const fresh = f.make(); assert.equal((await fresh.exchange(f.d, pair.refreshToken, f.d.resources.mcp, f.ctx.value)).resource, f.d.resources.mcp);
  assert.equal((await f.make().revoke(f.d, pair.refreshToken, f.expected(), f.ctx.value)).familyId, f.familyId);
});

test('owned callback code exchanges once across factories and sends exact code/verifier/redirect form', async t => {
  const f = await fixture(t), { attempt, code } = await completed(t, f.d);
  const pair = await f.adapter.exchangeCode(attempt, f.ctx.value), fields = Object.fromEntries(new URLSearchParams(f.requests[0].body));
  assert.equal(fields.code, code); assert.equal(fields.grant_type, 'authorization_code'); assert.equal(fields.redirect_uri, attempt.redirectUri);
  assert.match(fields.code_verifier, /^[A-Za-z0-9_-]{43}$/); assert.deepEqual(Object.keys(fields).sort(), ['client_id', 'code', 'code_verifier', 'grant_type', 'redirect_uri', 'resource']);
  const before = f.requests.length; await assert.rejects(f.make().exchangeCode(attempt, f.ctx.value), failure(false, 'http_input_invalid'));
  assert.equal(f.requests.length, before); assert.equal(pair.familyId, f.familyId);
});

test('lost code response consumes the callback attempt without retry or late access publication', async t => {
  const f = await fixture(t), { attempt } = await completed(t, f.d); f.tokenResponse = res => { res.writeHead(503); res.end(canary); };
  await assert.rejects(f.adapter.exchangeCode(attempt, f.ctx.value), failure(true, 'http_unknown'));
  await assert.rejects(f.make().exchangeCode(attempt, f.ctx.value), failure(false, 'http_input_invalid')); assert.equal(f.requests.length, 1);
});

test('code response cannot expand requested resources/scopes and initial failure remains submitted with no replay', async t => {
  for (const choice of [{ grantResourceKinds: ['rest'] }, { scopes: ['devices:read'] }]) {
    const f = await fixture(t), { attempt } = await completed(t, f.d, choice);
    await assert.rejects(f.adapter.exchangeCode(attempt, f.ctx.value), failure(true, 'http_identity_failed'));
    const before = f.requests.length; await assert.rejects(f.make().exchangeCode(attempt, f.ctx.value), failure(false, 'http_input_invalid'));
    await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, f.ctx.value), failure(false, 'http_input_invalid'));
    assert.equal(f.requests.length, before);
  }
});

test('token/revocation redirects do not forward refresh credentials to a foreign owned sink', async t => {
  let sink = 0; const other = createServer((_req, res) => { sink++; res.end(); }); other.listen(0, '127.0.0.1'); await once(other, 'listening');
  t.after(async () => { other.closeAllConnections(); await new Promise(resolve => other.close(resolve)); });
  const f = await fixture(t), location = `http://127.0.0.1:${other.address().port}/sink`;
  const redirect = res => { res.writeHead(307, { Location: location }); res.end(); }; f.tokenResponse = redirect; f.revokeResponse = redirect;
  await assert.rejects(f.refresh(), failure(true, 'http_unknown')); assert.equal(await f.adapter.revoke(f.d, credential('r'), f.expected(), f.ctx.value), 'unknown');
  assert.equal(f.requests.length, 2); assert.equal(sink, 0);
});

test('strict wire decoding denies malformed credential/resource/scopes/lifetimes without identity or retry', async t => {
  const cases = [v => ({ ...v, access_token: 'rk_' + canary }), v => ({ ...v, resource: 'https://wrong.example.test' }), v => ({ ...v, token_type: 'bearer' }),
    ...[0, 301, '300'].map(expires_in => v => ({ ...v, expires_in })), ...['', 'devices:read  recordings:read', 'devices:read devices:read', 'admin'].map(scope => v => ({ ...v, scope })),
    v => ({ ...v, secret: canary }), v => ({ ...v, bota_family_id: canary })];
  const f = await fixture(t);
  for (const change of cases) { const before = f.requests.length; f.tokenResponse = (res, wire) => json(res, change(wire));
    await assert.rejects(f.refresh(), failure(true)); assert.equal(f.requests.length, before + 1); }
  assert.equal(f.verifierContexts.length, 0);
});

test('identity must match token resource/scopes/grant/family and current exact expiry before ledger publication', async t => {
  const f = await fixture(t);
  for (const change of [v => ({ ...v, grantId: randomUUID() }), v => ({ ...v, familyId: randomUUID() }), v => ({ ...v, resource: f.d.resources.mcp }),
    v => ({ ...v, accessScopes: ['devices:read'] }), v => ({ ...v, expiresAtSeconds: 1000 }), v => ({ ...v, expiresAtSeconds: 1301 }), v => ({ ...v, issuer: 'https://wrong.example.test' })]) {
    f.identityModifier = change; await assert.rejects(f.refresh(), failure(true)); const before = f.requests.length;
    await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, f.ctx.value), failure(false, 'http_input_invalid'));
    assert.equal(f.requests.length, before);
  }
});

test('bound revocation accepts only exact positive wire confirmation; empty200 and malformed receipts remain unknown', async t => {
  const f = await fixture(t), proof = credential('r');
  assert.deepEqual(await f.adapter.revoke(f.d, proof, f.expected(), f.ctx.value), f.expected());
  assert.deepEqual(Object.fromEntries(new URLSearchParams(f.requests[0].body)), { client_id: f.d.client.clientId, token: proof,
    token_type_hint: 'refresh_token', bota_grant_id: f.grantId, bota_family_id: f.familyId });
  for (const response of [undefined, {}, { grantId: f.grantId, familyId: f.familyId }, { bota_revoked: false, bota_grant_id: f.grantId, bota_family_id: f.familyId },
    { bota_revoked: true, bota_grant_id: randomUUID(), bota_family_id: f.familyId }, { bota_revoked: true, bota_grant_id: f.grantId, bota_family_id: f.familyId, refresh_token: proof }]) {
    f.revokeResponse = res => response === undefined ? res.end() : json(res, response);
    const before = f.requests.length; assert.equal(await f.adapter.revoke(f.d, proof, f.expected(), f.ctx.value), 'unknown'); assert.equal(f.requests.length, before + 1);
  }
});

test('actual HTTP empty200 composes with portable engine blocking and retains exact proof until bound recovery', async t => {
  const f = await fixture(t), { attempt } = await completed(t, f.d), pair = await f.adapter.exchangeCode(attempt, f.ctx.value);
  const secrets = new Map(); let state = null, deletes = 0;
  const engine = new DelegatedFamilyEngine({
    store: { id: 'http-fixture', async read(ref) { const refreshToken = secrets.get(JSON.stringify(ref)); return refreshToken ? { status: 'present', refreshToken } : { status: 'absent' }; },
      async write(ref, refreshToken) { if (secrets.has(JSON.stringify(ref))) return 'not_stored'; secrets.set(JSON.stringify(ref), refreshToken); return 'stored'; },
      async delete(ref) { deletes++; return secrets.delete(JSON.stringify(ref)) ? 'deleted' : 'absent'; } },
    snapshots: { async load() { return state; }, async publish(_key, revision, next) { if ((state?.revision ?? null) !== revision) return 'not_committed'; state = next; return 'committed'; } },
    lease: { async runExclusive(_key, _context, work) { return work(); } }, nowSeconds: () => 1000,
    verifyAccess: f.adapter.verifyAccess, exchange: f.adapter.exchange, revoke: f.adapter.revoke,
  });
  const tokenCalls = f.requests.filter(value => value.path === '/oauth/token').length;
  const ready = await engine.enroll(createTrustedDelegatedEnrollmentHandoff(f.d, async () => pair), f.ctx.value);
  assert.equal(f.requests.filter(value => value.path === '/oauth/token').length, tokenCalls, 'handoff cannot hide a code exchange');
  const key = { storeId: ready.storeId, issuer: ready.binding.issuer, clientId: ready.binding.clientId, familyId: ready.binding.familyId };
  const positive = f.revokeResponse; f.revokeResponse = res => res.end();
  await assert.rejects(engine.revoke(key, f.ctx.value), error => error.code === 'revocation_unknown' && error.recoveryRequired);
  assert.equal(state.state, 'revoking'); assert.equal(secrets.size, 1); assert.equal(deletes, 0);
  const before = f.requests.length;
  await assert.rejects(engine.withAccess(key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), error => error.code === 'pending');
  await assert.rejects(engine.remove(key, f.ctx.value), error => error.code === 'pending'); assert.equal(f.requests.length, before);
  f.revokeResponse = positive; assert.equal((await engine.recoverRevocation(key, f.ctx.value)).state, 'revoked');
  assert.equal((await engine.remove(key, f.ctx.value)).state, 'removed'); assert.equal(secrets.size, 0); assert.equal(deletes, 1);
});

test('advertised/decoded/gzip body overflow, duplicate keys, BOM, malformed UTF8 and truncated data fail closed', async t => {
  const f = await fixture(t);
  const responses = [res => { res.writeHead(200, { 'Content-Length': '16385' }); res.flushHeaders(); },
    res => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('x'.repeat(16385)); },
    res => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }); res.end(gzipSync('x'.repeat(20000))); },
    (res, wire) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(wire).replace('"resource":', '"resource":"wrong","resource":')); },
    (res, wire) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('\ufeff' + JSON.stringify(wire)); },
    res => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(Buffer.from([0xff])); },
    res => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 999 }); res.write('{'); setImmediate(() => res.destroy()); }];
  for (const respond of responses) { f.tokenResponse = respond; const before = f.requests.length;
    await assert.rejects(f.refresh(), failure(true)); assert.equal(f.requests.length, before + 1); }
  assert.equal(f.verifierContexts.length, 0);
});

test('original cancellation signal survives context retarget and closes unfinished response without retry', async t => {
  const f = await fixture(t), started = Promise.withResolvers(), closed = Promise.withResolvers();
  f.tokenResponse = res => { res.once('close', closed.resolve); res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); started.resolve(); };
  const pending = f.refresh(); await started.promise;
  f.ctx.value.signal = new AbortController().signal; f.ctx.value.budget = { assertActive() {} }; f.ctx.controller.abort(Error(canary));
  await assert.rejects(pending, failure(true, 'http_cancelled')); await closed.promise; assert.equal(f.requests.length, 1);
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('whole-operation deadline includes unfinished decoded body and preflight refusal sends nothing', async t => {
  const f = await fixture(t, 50), closed = Promise.withResolvers(); f.tokenResponse = res => { res.once('close', closed.resolve); res.writeHead(200); res.write('{'); };
  await assert.rejects(f.refresh(), failure(true, 'http_deadline')); await closed.promise; assert.equal(f.requests.length, 1);
  const before = f.requests.length; f.ctx.state.expired = true;
  await assert.rejects(f.refresh(), failure(false, 'http_deadline')); assert.equal(await f.adapter.revoke(f.d, credential('r'), f.expected(), f.ctx.value), 'not_submitted');
  assert.equal(f.requests.length, before);
});

test('an uncooperative read-only verifier loses authority on abort and its observed late result cannot publish access', async t => {
  const f = await fixture(t), started = Promise.withResolvers(), release = Promise.withResolvers(); let retained;
  f.verifierAfter = async actualContext => { retained = actualContext; started.resolve(); await release.promise; };
  let settled = false; const pending = f.refresh().finally(() => { settled = true; }); void pending.catch(() => {});
  await started.promise; f.ctx.controller.abort(Error(canary)); await assert.rejects(pending, failure(true, 'http_cancelled'));
  assert.equal(settled, true); assert.equal(retained.signal.aborted, true); release.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.throws(() => retained.budget.assertActive(), failure(true, 'http_unknown'));
  await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, context().value), failure(false, 'http_input_invalid'));
});

test('a never-settling read-only verifier cannot extend public deadline or retain issued authority', async t => {
  const f = await fixture(t, 60); let retained;
  f.verifierAfter = actualContext => { retained = actualContext; return new Promise(() => {}); };
  await assert.rejects(f.refresh(), failure(true, 'http_deadline')); assert.equal(retained.signal.aborted, true);
  assert.throws(() => retained.budget.assertActive(), failure(true, 'http_unknown')); assert.equal(f.requests.length, 2);
  await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, context().value), failure(false, 'http_input_invalid'));
});

test('monotonic deadline refuses a response when event-loop blockage delays the timer callback', async t => {
  const f = await fixture(t, 60);
  f.verifierAfter = () => { const until = performance.now() + 90; while (performance.now() < until) {} };
  await assert.rejects(f.refresh(), failure(true, 'http_deadline'));
  await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, context().value), failure(false, 'http_input_invalid'));
});

test('context signal/budget/assertion retarget after await refuses delivery without evaluating replacement hooks', async t => {
  for (const part of ['signal', 'budget', 'assertion']) {
    const f = await fixture(t); let hooks = 0;
    f.verifierAfter = () => {
      if (part === 'signal') f.ctx.value.signal = new AbortController().signal;
      else if (part === 'budget') f.ctx.value.budget = { assertActive() { hooks++; } };
      else Object.defineProperty(f.ctx.value.budget, 'assertActive', { get() { hooks++; throw Error(canary); } });
    };
    await assert.rejects(f.refresh(), failure(true, 'http_input_invalid')); assert.equal(hooks, 0);
    await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, context().value), failure(false, 'http_input_invalid'));
  }
});

test('delayed body cancellation is joined and cleanup failure prevents token or ledger publication', async t => {
  const f = await fixture(t), started = Promise.withResolvers(), release = Promise.withResolvers();
  f.fetchAfter = response => { const body = response.body, original = body.getReader.bind(body);
    body.getReader = () => { const reader = original(); return { read: reader.read.bind(reader), releaseLock: reader.releaseLock.bind(reader),
      async cancel() { await reader.cancel(); started.resolve(); await release.promise; throw Error(canary); } }; }; };
  let settled = false; const pending = f.refresh().finally(() => { settled = true; }); void pending.catch(() => {});
  await started.promise; await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false); release.resolve();
  await assert.rejects(pending, failure(true, 'http_unknown')); assert.equal(f.verifierContexts.length, 0);
  await assert.rejects(f.adapter.verifyAccess(f.d, f.lastWire.access_token, f.d.resources.rest, context().value), failure(false, 'http_input_invalid'));
});

test('private context getters and identity errors never become diagnostics or replace captured authority', async t => {
  const f = await fixture(t); let hooks = 0;
  const input = Object.defineProperty({ budget: f.ctx.value.budget }, 'signal', { enumerable: true, get() { hooks++; throw Error(canary); } });
  await assert.rejects(f.adapter.exchange(f.d, credential('r'), f.d.resources.rest, input), failure(false, 'http_input_invalid')); assert.equal(hooks, 0); assert.equal(f.requests.length, 0);
  const retargeted = context(); retargeted.value.budget.assertActive = () => { retargeted.value.signal = new AbortController().signal; };
  await assert.rejects(f.adapter.exchange(f.d, credential('r'), f.d.resources.rest, retargeted.value), failure(false, 'http_input_invalid')); assert.equal(f.requests.length, 0);
  f.verifierAfter = async () => { const error = new DelegatedHttpError(canary); error.message = canary; error.cause = Error(canary); throw error; };
  await assert.rejects(f.refresh(), failure(true, 'http_unknown'));
});
