import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { parseDelegatedLoginDeployment, startDelegatedLoginAttempt, startRecoverableDelegatedLoginAttempt,
  readDelegatedLoginRecoveryBinding } from '../src/delegated-login.ts';
import { createDelegatedHttpAdapterForTrustedPorts } from '../src/delegated-http.ts';

const deployment = () => ({ version: 1, issuer: 'https://issuer.example.test', endpoints: {
  authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
  resources: { rest: 'https://rest.example.test/v1', mcp: 'https://mcp.example.test/mcp' }, client: {
    clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const selection = { resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read'], loopbackHost: '127.0.0.1' };
const context = () => ({ signal: new AbortController().signal, budget: { assertActive() {} } });
async function proof(t, config) {
  let retained;
  const attempt = await startRecoverableDelegatedLoginAttempt(config, selection, { async retain(binding) {
    retained = binding; return { status: 'retained', attemptId: binding.attemptId };
  } }, { timeoutMs: 3000 });
  t.after(() => attempt.cancel()); await attempt.cancel(); return { attempt, binding: retained };
}
async function fixture(t, opted = true) {
  const config = { ...deployment(), ...opted ? { recoveryProtocol: 'negative-fence-v1' } : {} };
  const p = await proof(t, config), f = { ...p, config, calls: [], verifyCalls: 0, fenceId: randomUUID(), requestId: randomUUID(), mode: 'fence' };
  f.reply = () => ({ bota_enrollment_fenced: 'negative-fence-v1', bota_enrollment_attempt: p.binding.attemptId, bota_fence_id: f.fenceId });
  const server = createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    f.calls.push({ url: req.url, method: req.method, authorization: req.headers.authorization, body });
    if (f.mode === 'lost') { res.destroy(); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (f.mode === 'empty') { res.end(); return; }
    if (f.mode === 'registered') { res.end(JSON.stringify({ bota_enrollment_revoked: true, bota_enrollment_attempt: p.binding.attemptId,
      bota_authorization_request_id: f.requestId, bota_grant_id: null, bota_family_id: null })); return; }
    const result = f.reply(); res.end(typeof result === 'string' ? result : JSON.stringify(result));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  f.adapter = config => createDelegatedHttpAdapterForTrustedPorts(config, {
    fetch(url, init) { assert.equal(url, f.config.endpoints.revocation); return fetch(`http://127.0.0.1:${server.address().port}/oauth/revoke`, init); },
    async verifyAccess() { f.verifyCalls++; throw Error('PRIVATE_IDENTITY_MUST_NOT_RUN'); },
  });
  f.run = (binding = f.binding, config = f.config) => f.adapter(config).revokeEnrollmentAttempt(binding, context()); return f;
}

test('trusted deployment opts in explicitly and copies a frozen protocol value; absent shape stays unchanged', () => {
  const old = deployment(), parsed = parseDelegatedLoginDeployment(old); assert.deepEqual(parsed, old); assert.equal(Object.hasOwn(parsed, 'recoveryProtocol'), false);
  const input = { ...deployment(), recoveryProtocol: 'negative-fence-v1' }, value = parseDelegatedLoginDeployment(input);
  input.recoveryProtocol = 'PRIVATE_CHANGED'; assert.equal(value.recoveryProtocol, 'negative-fence-v1'); assert.ok(Object.isFrozen(value));
});

test('unknown, empty, inherited, getter and proxy protocol selections cannot activate a namespace', () => {
  let hooks = 0;
  for (const value of [undefined, null, '', 'negative-fence-v2', false]) assert.throws(() => parseDelegatedLoginDeployment({ ...deployment(), recoveryProtocol: value }));
  const inherited = Object.assign(Object.create({ recoveryProtocol: 'negative-fence-v1' }), deployment());
  const getter = { ...deployment(), get recoveryProtocol() { hooks++; throw Error('PRIVATE_PROTOCOL'); } };
  const proxy = new Proxy({}, { ownKeys() { hooks++; throw Error('PRIVATE_PROTOCOL'); }, getPrototypeOf() { hooks++; throw Error('PRIVATE_PROTOCOL'); } });
  for (const value of [inherited, getter, proxy]) assert.throws(() => parseDelegatedLoginDeployment(value)); assert.equal(hooks, 0);
});

test('new genuine producer retains explicit protocol before URL publication and never includes its secret proofs', async t => {
  const f = await fixture(t), url = new URL(f.attempt.authorizationUrl);
  assert.equal(f.binding.recoveryProtocol, 'negative-fence-v1'); assert.equal(url.searchParams.get('recovery_protocol'), 'negative-fence-v1');
  for (const key of ['enrollment_attempt', 'recovery_challenge', 'recovery_challenge_method', 'recovery_protocol']) assert.equal(url.searchParams.getAll(key).length, 1);
  assert.equal(readDelegatedLoginRecoveryBinding(f.attempt), f.binding); assert.ok(Object.isFrozen(f.binding));
  assert.equal(f.attempt.authorizationUrl.includes(f.binding.recoveryVerifier), false); assert.equal(f.attempt.authorizationUrl.includes(f.binding.pkceVerifier), false);
});

test('legacy recovery and nonrecoverable producer never infer the new namespace from configuration alone', async t => {
  const old = await proof(t, deployment()); assert.equal(Object.hasOwn(old.binding, 'recoveryProtocol'), false);
  assert.equal(new URL(old.attempt.authorizationUrl).searchParams.has('recovery_protocol'), false);
  const plain = await startDelegatedLoginAttempt({ ...deployment(), recoveryProtocol: 'negative-fence-v1' }, selection, { timeoutMs: 3000 });
  t.after(() => plain.cancel()); const url = new URL(plain.authorizationUrl); assert.equal(url.searchParams.has('recovery_protocol'), false); assert.equal(url.searchParams.has('enrollment_attempt'), false);
});

test('new namespace sends exactly seven explicit-purpose form fields and normalizes only an exact fence', async t => {
  const f = await fixture(t), result = await f.run();
  assert.deepEqual(result, { kind: 'unregistered-fenced-v1', attemptId: f.binding.attemptId, fenceId: f.fenceId }); assert.ok(Object.isFrozen(result));
  assert.equal(f.calls.length, 1); assert.equal(f.verifyCalls, 0);
  const call = f.calls[0], fields = new URLSearchParams(call.body); assert.equal(call.method, 'POST'); assert.equal(call.url, '/oauth/revoke'); assert.equal(call.authorization, undefined);
  assert.deepEqual([...fields.keys()].sort(), ['token_type_hint', 'token', 'bota_enrollment_attempt', 'code_verifier', 'client_id', 'redirect_uri', 'resource'].sort());
  assert.equal(fields.get('token_type_hint'), 'bota_enrollment_attempt_fence_v1'); assert.equal(fields.get('token'), f.binding.recoveryVerifier); assert.equal(fields.get('code_verifier'), f.binding.pkceVerifier);
  assert.equal(Object.hasOwn(result, 'grantId'), false); assert.equal(Object.hasOwn(result, 'familyId'), false); assert.equal(Object.hasOwn(result, 'authorizationRequestId'), false);
});

test('opted-in deployment preserves old binding purpose and never upgrades it from a fence response', async t => {
  const f = await fixture(t, false); const config = { ...f.config, recoveryProtocol: 'negative-fence-v1' };
  assert.equal(await f.run(f.binding, config), 'unknown'); assert.equal(new URLSearchParams(f.calls[0].body).get('token_type_hint'), 'bota_enrollment_attempt');
  f.mode = 'registered'; assert.deepEqual(await f.run(f.binding, config), { attemptId: f.binding.attemptId, authorizationRequestId: f.requestId, grantId: null, familyId: null });
});

test('new binding cannot select an unconfigured protocol or silently downgrade invalid protocol metadata', async t => {
  const f = await fixture(t);
  assert.equal(await f.run(f.binding, deployment()), 'not_submitted');
  for (const value of [undefined, null, '', 'negative-fence-v2']) assert.equal(await f.run({ ...f.binding, recoveryProtocol: value }), 'not_submitted');
  assert.equal(f.calls.length, 0); assert.equal(f.verifyCalls, 0);
});

test('new recovery still accepts a definitive registered four-ID receipt without changing its shape', async t => {
  const f = await fixture(t); f.mode = 'registered'; const result = await f.run();
  assert.deepEqual(result, { attemptId: f.binding.attemptId, authorizationRequestId: f.requestId, grantId: null, familyId: null }); assert.ok(Object.isFrozen(result)); assert.equal(Object.hasOwn(result, 'kind'), false);
});

for (const mode of ['empty', 'lost']) test(`${mode} new-namespace response remains unknown with one POST and retained proof`, async t => {
  const f = await fixture(t); f.mode = mode; assert.equal(await f.run(), 'unknown'); assert.equal(f.calls.length, 1); assert.equal(readDelegatedLoginRecoveryBinding(f.attempt), f.binding);
});

test('malformed, mixed, duplicated, private and foreign fence receipts stay unknown without retry', async t => {
  const f = await fixture(t), valid = f.reply();
  const bodies = [null, {}, { ...valid, bota_enrollment_fenced: true }, { ...valid, bota_enrollment_attempt: randomUUID() },
    { ...valid, bota_fence_id: 'bad' }, { ...valid, bota_fence_id: 'ABCDEFAB-1111-4111-8111-111111111111' }, { ...valid, private: 'PRIVATE_RESPONSE' },
    { ...valid, bota_grant_id: null }, { ...valid, bota_enrollment_revoked: true }, { kind: 'unregistered-fenced-v1', attemptId: f.binding.attemptId, fenceId: f.fenceId },
    JSON.stringify(valid).replace('}', ',"bota_fence_id":"' + randomUUID() + '"}')];
  for (const body of bodies) { f.reply = () => body; const count = f.calls.length; assert.equal(await f.run(), 'unknown'); assert.equal(f.calls.length, count + 1); }
  assert.equal(f.verifyCalls, 0);
});

test('protocol accessors and proxies cannot invoke reflection hooks or submit a revocation', async t => {
  const f = await fixture(t); let hooks = 0;
  const getter = { ...f.binding }; Object.defineProperty(getter, 'recoveryProtocol', { enumerable: true, get() { hooks++; throw Error('PRIVATE_PROTOCOL'); } });
  assert.equal(await f.run(getter), 'not_submitted');
  assert.equal(await f.run(new Proxy({}, { ownKeys() { hooks++; throw Error('PRIVATE_PROTOCOL'); } })), 'not_submitted');
  assert.equal(hooks, 0); assert.equal(f.calls.length, 0);
});
