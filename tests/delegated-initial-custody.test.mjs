import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { createDelegatedHttpAdapterForTrustedPorts, DelegatedHttpError } from '../src/delegated-http.ts';
import { readDelegatedLoginRecoveryBinding, startRecoverableDelegatedLoginAttempt } from '../src/delegated-login.ts';

const token = kind => `bota_d${kind}1_${randomBytes(32).toString('base64url')}`;
const ctx = controller => ({ signal: controller.signal, budget: { assertActive() {} } });
async function fixture(t) {
  const d = { version: 1, issuer: 'https://issuer.example.test', endpoints: {
    authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
    resources: { rest: 'https://rest.example.test/v1', mcp: 'https://mcp.example.test/agent' }, client: {
      clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } };
  const events = [], requests = [], refresh = token('r'), access = token('a'), grantId = randomUUID(), familyId = randomUUID();
  const controller = new AbortController(); let retainedProof;
  const attempt = await startRecoverableDelegatedLoginAttempt(d, { resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read'], loopbackHost: '127.0.0.1' },
    { async retain(proof, context) { context.budget.assertActive(); retainedProof = proof; return { status: 'retained', attemptId: proof.attemptId }; } }, { timeoutMs: 5000 });
  t.after(() => attempt.cancel());
  const callback = new URL(attempt.redirectUri); callback.search = new URLSearchParams({ code: token('c'), state: new URL(attempt.authorizationUrl).searchParams.get('state') }).toString();
  const returned = await fetch(callback, { redirect: 'error' }); await returned.text(); await attempt.result;
  const server = createServer(async (request, response) => {
    let body = ''; for await (const bytes of request) body += bytes;
    requests.push({ path: request.url, body }); events.push('token-response');
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ access_token: access, refresh_token: refresh,
      token_type: 'Bearer', expires_in: 299, resource: d.resources.rest, bota_grant_id: grantId, bota_family_id: familyId, scope: 'devices:read' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const f = { d, attempt, controller, events, requests, refresh, access, grantId, familyId, retainedProof, retained: [], verifyError: false, verifyCalls: 0 };
  const retain = async (value, context) => { context.budget.assertActive(); events.push('protected-initial-refresh'); f.retained.push(value);
    assert.ok(Object.isFrozen(value)); assert.ok(Object.isFrozen(value.scopes)); assert.equal(Object.hasOwn(value, 'accessToken'), false);
    return { status: 'retained', attemptId: value.attemptId, grantId: value.grantId, familyId: value.familyId }; };
  f.make = (custody = retain) => createDelegatedHttpAdapterForTrustedPorts(d, {
    fetch: (url, init) => { assert.equal(url, d.endpoints.token); return fetch(`http://127.0.0.1:${server.address().port}/oauth/token`, init); },
    async verifyAccess(selected, bearer, resource, context) {
      context.budget.assertActive(); f.verifyCalls++; events.push('authoritative-identity');
      assert.deepEqual(selected, d); assert.equal(bearer, access); assert.equal(resource, d.resources.rest);
      if (f.verifyError) throw Error('PRIVATE_IDENTITY_CANARY');
      if (f.verifyAfter) await f.verifyAfter();
      return { issuer: d.issuer, clientId: d.client.clientId, userId: randomUUID(), organizationId: 'org', projectId: 'project', grantId, familyId,
        grantResourceUris: Object.values(d.resources), grantScopes: ['devices:read'], resource, accessScopes: ['devices:read'], expiresAtSeconds: Math.floor(Date.now() / 1000) + 299 };
    }, ...(custody === null ? {} : { retainInitialRefresh: custody }),
  });
  f.run = adapter => adapter.exchangeCode(attempt, ctx(controller)); return f;
}
const fixed = submitted => error => { assert.ok(error instanceof DelegatedHttpError); assert.equal(error.mutationSubmitted, submitted);
  assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_|bota_d[acr]1_|example\.test/); return true; };

test('first received refresh is retained before any authoritative identity verification', async t => {
  const f = await fixture(t), pair = await f.run(f.make());
  assert.deepEqual(f.events, ['token-response', 'protected-initial-refresh', 'authoritative-identity']);
  assert.equal(pair.refreshToken, f.refresh); assert.equal(f.retained[0].attemptId, f.retainedProof.attemptId);
  assert.equal(f.retained[0].refreshToken, f.refresh); assert.equal(f.requests.length, 1);
});

test('recoverable attempt without a configured custody port refuses before token egress', async t => {
  const f = await fixture(t); await assert.rejects(f.run(f.make(null)), fixed(false));
  assert.equal(f.requests.length, 0); assert.equal(f.verifyCalls, 0);
});

for (const mode of ['unknown', 'wrong-attempt', 'wrong-family', 'getter']) test(`initial custody ${mode} never publishes or verifies a credential`, async t => {
  const f = await fixture(t); let hooks = 0;
  const adapter = f.make(async value => {
    if (mode === 'unknown') return 'unknown';
    const receipt = { status: 'retained', attemptId: value.attemptId, grantId: value.grantId, familyId: value.familyId };
    if (mode === 'wrong-attempt') receipt.attemptId = randomUUID();
    if (mode === 'wrong-family') receipt.familyId = randomUUID();
    if (mode === 'getter') Object.defineProperty(receipt, 'status', { enumerable: true, get() { hooks++; throw Error('PRIVATE_ACK_CANARY'); } });
    return receipt;
  });
  await assert.rejects(f.run(adapter), fixed(true)); await assert.rejects(f.run(adapter), fixed(false));
  assert.equal(f.requests.length, 1); assert.equal(f.verifyCalls, 0); assert.equal(hooks, 0);
});

test('failed identity verification preserves the initial refresh and genuine original cleanup proof', async t => {
  const f = await fixture(t); f.verifyError = true;
  await assert.rejects(f.run(f.make()), fixed(true));
  assert.equal(f.retained[0].refreshToken, f.refresh); assert.equal(f.verifyCalls, 1);
  await f.attempt.cancel(); const proof = readDelegatedLoginRecoveryBinding(f.attempt);
  assert.equal(proof.attemptId, f.retainedProof.attemptId); assert.equal(proof.pkceVerifier, f.retainedProof.pkceVerifier);
  assert.equal(f.requests.length, 1);
});

test('cancellation during custody joins the cooperative acknowledgement without verifying or retrying', async t => {
  const f = await fixture(t); let entered, custodyContext;
  const waiting = new Promise(resolve => { entered = resolve; });
  const adapter = f.make(async (value, context) => {
    custodyContext = context; entered();
    await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }));
    return { status: 'retained', attemptId: value.attemptId, grantId: value.grantId, familyId: value.familyId };
  });
  const action = f.run(adapter); await waiting; f.controller.abort(); await assert.rejects(action, fixed(true));
  assert.equal(custodyContext.signal.aborted, true); assert.throws(() => custodyContext.budget.assertActive());
  assert.equal(f.verifyCalls, 0); assert.equal(f.requests.length, 1);
});

test('initial custody context is retired before the following identity verification completes', async t => {
  const f = await fixture(t); let custodyContext, entered, release;
  const verifying = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { release = resolve; });
  f.verifyAfter = async () => { entered(); await gate; };
  const adapter = f.make(async (value, context) => { custodyContext = context;
    return { status: 'retained', attemptId: value.attemptId, grantId: value.grantId, familyId: value.familyId }; });
  const action = f.run(adapter);
  try { await verifying; assert.equal(custodyContext.signal.aborted, true); assert.throws(() => custodyContext.budget.assertActive()); }
  finally { release(); }
  await action;
});
