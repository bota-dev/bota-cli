import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { createDelegatedHttpAdapterForTrustedPorts } from '../src/delegated-http.ts';
import { readDelegatedLoginRecoveryBinding, startRecoverableDelegatedLoginAttempt } from '../src/delegated-login.ts';

async function fixture(t) {
  const d = { version: 1, issuer: 'https://issuer.example.test', endpoints: {
    authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
    resources: { rest: 'https://rest.example.test/v1', mcp: 'https://mcp.example.test/agent' }, client: {
      clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } };
  const attempt = await startRecoverableDelegatedLoginAttempt(d, { resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read'], loopbackHost: '127.0.0.1' },
    { async retain(binding) { return { status: 'retained', attemptId: binding.attemptId }; } }, { timeoutMs: 5000 });
  await attempt.cancel(); const binding = readDelegatedLoginRecoveryBinding(attempt), requestId = randomUUID();
  const requests = [], f = { requests, attempt, binding, requestId, verifyCalls: 0, mode: 'positive', grantId: null, familyId: null };
  const server = createServer(async (request, response) => {
    let body = ''; for await (const bytes of request) body += bytes;
    requests.push({ method: request.method, url: request.url, headers: request.headers, body });
    if (f.mode === 'lost') { response.destroy(); return; }
    response.writeHead(200, { 'Content-Type': 'application/json' });
    if (f.mode === 'empty') { response.end(); return; }
    const receipt = { bota_enrollment_revoked: true, bota_enrollment_attempt: binding.attemptId, bota_authorization_request_id: requestId,
      bota_grant_id: f.grantId, bota_family_id: f.familyId };
    if (f.mode === 'wrong') receipt.bota_enrollment_attempt = randomUUID();
    if (f.mode === 'extension') receipt.private = 'PRIVATE_RESPONSE_CANARY';
    response.end(JSON.stringify(receipt));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  f.adapter = createDelegatedHttpAdapterForTrustedPorts(d, {
    fetch: (url, init) => { assert.equal(url, d.endpoints.revocation); return fetch(`http://127.0.0.1:${server.address().port}/oauth/revoke`, init); },
    async verifyAccess() { f.verifyCalls++; throw Error('PRIVATE_VERIFIER_CANARY'); },
  });
  f.run = (input = binding) => f.adapter.revokeEnrollmentAttempt(input, { signal: new AbortController().signal, budget: { assertActive() {} } });
  return f;
}

test('genuine cancelled pre-callback proof uses only the original existing revoke endpoint and seven POST fields', async t => {
  const f = await fixture(t), result = await f.run();
  assert.deepEqual(result, { attemptId: f.binding.attemptId, authorizationRequestId: f.requestId, grantId: null, familyId: null });
  assert.ok(Object.isFrozen(result)); assert.equal(f.verifyCalls, 0); assert.equal(f.requests.length, 1);
  const request = f.requests[0], body = new URLSearchParams(request.body);
  assert.equal(request.method, 'POST'); assert.equal(request.url, '/oauth/revoke'); assert.equal(request.headers.authorization, undefined);
  assert.deepEqual([...body.keys()].sort(), ['token_type_hint', 'token', 'bota_enrollment_attempt', 'code_verifier', 'client_id', 'redirect_uri', 'resource'].sort());
  assert.equal(body.get('token'), f.binding.recoveryVerifier); assert.equal(body.get('code_verifier'), f.binding.pkceVerifier);
  assert.equal(body.get('token_type_hint'), 'bota_enrollment_attempt');
});

test('linked grant/family confirmation is explicit and repeated cleanup never exchanges a code', async t => {
  const f = await fixture(t); f.grantId = randomUUID(); f.familyId = randomUUID();
  const first = await f.run(), repeated = await f.run(); assert.deepEqual(first, repeated);
  assert.equal(first.familyId, f.familyId); assert.equal(f.requests.length, 2); assert.equal(f.verifyCalls, 0);
});

for (const mode of ['empty', 'lost', 'wrong', 'extension']) test(`${mode} revocation result stays unknown without automatic retry`, async t => {
  const f = await fixture(t); f.mode = mode;
  assert.equal(await f.run(), 'unknown'); assert.equal(f.requests.length, 1); assert.equal(f.verifyCalls, 0);
  assert.equal(readDelegatedLoginRecoveryBinding(f.attempt), f.binding);
});

test('inconsistent null receipt cannot confirm removal', async t => {
  const f = await fixture(t); f.familyId = randomUUID(); assert.equal(await f.run(), 'unknown');
  assert.equal(f.requests.length, 1);
});

test('wrong origin/client/resource/proxy/getter proofs refuse without invoking hooks or sending secrets', async t => {
  const f = await fixture(t); let hooks = 0;
  const getter = { ...f.binding }; Object.defineProperty(getter, 'recoveryVerifier', { enumerable: true, get() { hooks++; throw Error('PRIVATE_PROOF_CANARY'); } });
  for (const input of [{ ...f.binding, issuer: 'https://foreign.example.test' }, { ...f.binding, clientId: 'other' },
    { ...f.binding, resource: 'https://foreign.example.test/resource' }, { ...f.binding, pkceVerifier: f.binding.recoveryVerifier }, getter,
    new Proxy({}, { ownKeys() { hooks++; throw Error('PRIVATE_PROOF_CANARY'); } })]) assert.equal(await f.run(input), 'not_submitted');
  assert.equal(hooks, 0); assert.equal(f.requests.length, 0); assert.equal(f.verifyCalls, 0);
});
