/** Portable source orchestration only: memory ports are NOT native custody. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { createDeveloperProfileServiceForTrustedPorts } from '../src/developer-profile-service.ts';
import { developerProfileFailure } from '../src/developer-profile-error.ts';
import { parseDelegatedLoginDeployment } from '../src/delegated-login.ts';
import { DelegatedFamilyEngine, createTrustedDelegatedEnrollmentHandoff } from '../src/delegated-family-engine.ts';
import { familyKeyOf } from '../src/delegated-family-state.ts';
import { BotaClient } from '../src/client.ts';
import { printJson } from '../src/output.ts';

const deployment = parseDelegatedLoginDeployment({ version: 1, issuer: 'https://issuer.example.test', endpoints: {
  authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
  resources: { rest: 'https://rest.example.test/v1', mcp: 'https://mcp.example.test/mcp' },
  client: { clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const selection = { resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read'], loopbackHost: '127.0.0.1' };
const context = () => ({ signal: new AbortController().signal, budget: { assertActive() {} } });
const secret = kind => `bota_d${kind}1_${randomBytes(32).toString('base64url')}`;
const defer = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
function fixed(code) { return error => { assert.equal(developerProfileFailure(error)?.code, code); assert.doesNotMatch(error.message + JSON.stringify(error), /PRIVATE_/); return true; }; }
async function fixture(seed = true) {
  const snapshots = new Map(), secrets = new Map(), identities = new Map(), proofs = new Map(), initial = new Map(), output = [];
  const grantId = randomUUID(), familyId = randomUUID(), userId = randomUUID(), encoded = value => JSON.stringify(value);
  const f = { snapshots, secrets, proofs, initial, output, creates: 0, closes: 0, browsers: 0, tokenPosts: 0, business: 0,
    held: 0, checks: 0, profile: null, calls: [], beforeClose: undefined, closeFailure: false, identityFailure: false, onBrowser: undefined,
    revokeUnknown: false, revokePosts: 0, deleteUnknown: false, onWrite: undefined };
  const pair = resource => { const value = { accessToken: secret('a'), refreshToken: secret('r'), resource, grantId, familyId, scopes: ['devices:read'], expiresAtSeconds: Math.floor(Date.now() / 1000) + 299 };
    identities.set(value.accessToken, { issuer: deployment.issuer, clientId: deployment.client.clientId, userId, organizationId: 'org_fixture', projectId: 'proj_fixture',
      grantId, familyId, grantResourceUris: Object.values(deployment.resources), grantScopes: ['devices:read'], resource, accessScopes: ['devices:read'], expiresAtSeconds: value.expiresAtSeconds }); return value; };
  const verifyAccess = async (_deployment, access, resource, ctx) => { ctx.budget.assertActive(); f.checks++;
    if (f.identityFailure || !identities.has(access) || identities.get(access).resource !== resource) throw Error('PRIVATE_IDENTITY'); return structuredClone(identities.get(access)); };
  const familyPorts = {
    store: { id: 'portable_developer_fixture', async read(ref) { return secrets.has(encoded(ref)) ? { status: 'present', refreshToken: secrets.get(encoded(ref)) } : { status: 'absent' }; },
      async write(ref, value) { if (secrets.has(encoded(ref))) return 'not_stored'; secrets.set(encoded(ref), value); return 'stored'; },
      async delete(ref) { if (f.deleteUnknown) return 'unknown'; return secrets.delete(encoded(ref)) ? 'deleted' : 'absent'; } },
    snapshots: { async load(key) { return structuredClone(snapshots.get(encoded(key)) ?? null); }, async publish(key, revision, next) {
      if ((snapshots.get(encoded(key))?.revision ?? null) !== revision) return 'not_committed'; snapshots.set(encoded(key), structuredClone(next)); return 'committed'; } },
    lease: { async runExclusive(_key, ctx, work) { assert.equal(f.held, 0); f.held++; try { ctx.budget.assertActive(); return await work(); } finally { f.held--; } } },
  };
  const fetchPort = async (url, options) => {
    if (String(url) === deployment.endpoints.token) { f.tokenPosts++; const fields = new URLSearchParams(options.body), resource = fields.get('resource');
      const value = pair(resource); return Response.json({ access_token: value.accessToken, refresh_token: value.refreshToken, token_type: 'Bearer', expires_in: 299,
        resource, scope: 'devices:read', bota_grant_id: grantId, bota_family_id: familyId }); }
    if (String(url) === deployment.endpoints.revocation) {
      f.revokePosts++; if (f.revokeUnknown) return new Response(null, { status: 200 });
      const fields = new URLSearchParams(options.body);
      if (fields.get('token_type_hint') === 'bota_enrollment_attempt') return Response.json({ bota_enrollment_revoked: true, bota_enrollment_attempt: fields.get('bota_enrollment_attempt'),
        bota_authorization_request_id: randomUUID(), bota_grant_id: grantId, bota_family_id: familyId });
      return Response.json({ bota_revoked: true, bota_grant_id: grantId, bota_family_id: familyId });
    }
    if (String(url) === deployment.resources.rest + '/devices') { f.business++; return Response.json({ data: [{ id: 'dev_fixture' }] }); }
    throw Error('PRIVATE_UNEXPECTED_TRANSPORT');
  };
  const runtime = { familyPorts,
    async reserve(name, selected, ctx) { ctx.budget.assertActive(); assert.equal(f.profile, null); f.calls.push('reserve'); f.profile = { name, state: 'reserved', attemptId: null, familyKey: null, pendingFamilyKey: null, deployment: selected }; return structuredClone(f.profile); },
    async load() { return structuredClone(f.profile); }, async list() { return f.profile ? [structuredClone(f.profile)] : []; },
    async abandonReserved(_name, ctx) { ctx.budget.assertActive(); assert.equal(f.profile.state, 'reserved');
      assert.equal(f.profile.attemptId, null); f.calls.push('reserved-abandoned'); f.profile = { ...f.profile, state: 'removed' }; return structuredClone(f.profile); },
    retentionPort(name) { return { async retain(binding, ctx) { ctx.budget.assertActive(); f.calls.push('proof-retained'); proofs.set(binding.attemptId, structuredClone(binding));
      f.profile = { ...f.profile, name, state: 'proof-ready', attemptId: binding.attemptId }; return { status: 'retained', attemptId: binding.attemptId }; } }; },
    retainInitialRefresh() { return async (value, ctx) => { ctx.budget.assertActive(); f.calls.push('refresh-retained'); initial.set(value.attemptId, structuredClone(value));
      f.profile = { ...f.profile, state: 'refresh-ready', pendingFamilyKey: { storeId: familyPorts.store.id, issuer: deployment.issuer, clientId: deployment.client.clientId, familyId: value.familyId } };
      return { status: 'retained', attemptId: value.attemptId, grantId: value.grantId, familyId: value.familyId }; }; },
    async adopt(name, attemptId, key, ctx) { ctx.budget.assertActive(); f.calls.push('adopt'); const snapshot = snapshots.get(encoded(key));
      assert.ok(snapshot?.state === 'ready' && snapshot.localGeneration === 0 && initial.has(attemptId));
      initial.delete(attemptId); proofs.delete(attemptId); f.profile = { name, state: 'ready', attemptId, familyKey: key, pendingFamilyKey: null, deployment }; return structuredClone(f.profile); },
    async readRecovery(_name, id, ctx) { ctx.budget.assertActive(); return structuredClone(proofs.get(id)); },
    async confirmCleanup(name, id, _receipt, ctx) { ctx.budget.assertActive(); f.calls.push('cleanup-confirmed'); proofs.delete(id); initial.delete(id);
      f.profile = { name, state: 'removed', attemptId: null, familyKey: null, pendingFamilyKey: null, deployment }; return structuredClone(f.profile); },
    async resumeCleanup(_name, ctx) { ctx.budget.assertActive(); assert.ok(['cleanup-confirmed', 'removing'].includes(f.profile.state));
      f.calls.push('cleanup-resumed'); proofs.clear(); initial.clear(); f.profile = { ...f.profile, state: 'removed' }; return structuredClone(f.profile); },
    async finalizeRemoval(name, key, ctx) { ctx.budget.assertActive(); assert.equal(snapshots.get(encoded(key))?.state, 'removed');
      f.profile = { name, state: 'removed', attemptId: null, familyKey: null, pendingFamilyKey: null, deployment }; return structuredClone(f.profile); },
    async close() { f.closes++; if (f.beforeClose) await f.beforeClose(); if (f.closeFailure) throw Error('PRIVATE_CLOSE'); },
  };
  f.ports = { getDeployment: () => deployment, async createRuntime(ctx) { f.creates++; f.context = ctx; return runtime; }, verifyAccess, fetch: fetchPort,
    async openBrowser(url, ctx) { ctx.budget.assertActive(); f.browsers++; f.calls.push('browser'); if (f.onBrowser) return f.onBrowser(url, ctx);
      const target = new URL(url), callback = new URL(target.searchParams.get('redirect_uri')); callback.searchParams.set('code', secret('c')); callback.searchParams.set('state', target.searchParams.get('state'));
      const response = await fetch(callback); assert.equal(response.status, 200); await response.body.cancel(); },
    async writeOutput(channel, text) { assert.equal(f.held, 0); assert.ok(f.closes > 0); output.push({ channel, text }); if (f.onWrite) await f.onWrite(); } };
  if (seed) { const engine = new DelegatedFamilyEngine({ ...familyPorts, verifyAccess, exchange: async (_d, _r, resource) => pair(resource), revoke: async () => ({ grantId, familyId }), nowSeconds: () => Math.floor(Date.now() / 1000) });
    const snapshot = await engine.enroll(createTrustedDelegatedEnrollmentHandoff(deployment, async () => pair(deployment.resources.rest)), context());
    f.key = familyKeyOf(snapshot); f.profile = { name: 'work', state: 'ready', attemptId: randomUUID(), familyKey: f.key, pendingFamilyKey: null, deployment }; }
  f.identities = identities; f.runtime = runtime; f.service = createDeveloperProfileServiceForTrustedPorts(f.ports); return f;
}

test('missing trusted deployment refuses before native, listener, browser or transport', async () => {
  const f = await fixture(false); f.ports.getDeployment = () => { throw Error('PRIVATE_CONFIGURATION'); };
  const service = createDeveloperProfileServiceForTrustedPorts(f.ports);
  await assert.rejects(service.login('work', selection), fixed('developer_configuration_unavailable'));
  assert.equal(f.creates + f.browsers + f.tokenPosts, 0);
});
test('aborted parent and invalid scope selection refuse before native creation', async () => {
  const f = await fixture(false), abort = new AbortController(); abort.abort('PRIVATE_REASON');
  await assert.rejects(f.service.inspect('work', { signal: abort.signal }), fixed('developer_cancelled'));
  await assert.rejects(f.service.login('work', { ...selection, scopes: ['admin:write'] }), fixed('developer_profile_invalid'));
  assert.equal(f.creates + f.browsers, 0);
});
test('real code-only loopback waits for both custody acknowledgements and adopts one verified family', async () => {
  const f = await fixture(false), profile = await f.service.login('work', selection);
  assert.equal(profile.state, 'ready'); assert.equal(f.tokenPosts, 1); assert.equal(f.browsers, 1);
  assert.deepEqual(f.calls, ['reserve', 'proof-retained', 'browser', 'refresh-retained', 'adopt']);
  assert.equal(f.initial.size + f.proofs.size, 0); assert.equal(f.secrets.size, 1);
  assert.equal(f.context.signal.aborted, true); assert.throws(() => f.context.budget.assertActive());
});
test('browser failure retains original protected proof and never submits exchange', async () => {
  const f = await fixture(false); f.onBrowser = async () => { throw Error('PRIVATE_BROWSER'); };
  await assert.rejects(f.service.login('work', selection), fixed('developer_operation_failed'));
  assert.equal(f.profile.state, 'proof-ready'); assert.equal(f.proofs.size, 1); assert.equal(f.tokenPosts, 0); assert.equal(f.closes, 1);
});
test('metadata pin is credential-free and rejects an unready pending key as admission', async () => {
  const f = await fixture(); assert.deepEqual(await f.service.pin('work'), f.key); assert.equal(f.checks, 2); assert.equal(f.tokenPosts, 0);
  f.profile = { ...f.profile, state: 'refresh-ready', familyKey: null, pendingFamilyKey: f.key, attemptId: randomUUID() };
  await assert.rejects(f.service.pin('work'), fixed('developer_recovery_required')); assert.equal(f.tokenPosts, 0);
});
test('selected REST command output waits for native cleanup and the actual client never reads a key', async () => {
  const f = await fixture(), entered = defer(), release = defer(); f.beforeClose = async () => { entered.resolve(); await release.promise; };
  const running = f.service.run('work', 'rest', async () => { printJson(await new BotaClient().get('/v1/devices')); return 9; });
  await entered.promise; assert.equal(f.output.length, 0); assert.equal(f.held, 0); release.resolve();
  assert.equal(await running, 9); assert.equal(f.output.length, 1); assert.equal(JSON.parse(f.output[0].text).data[0].id, 'dev_fixture'); assert.equal(f.business, 1);
});
test('native cleanup failure discards successful business output and returns a fixed recovery diagnostic', async () => {
  const f = await fixture(); f.closeFailure = true;
  await assert.rejects(f.service.run('work', 'rest', async () => { printJson(await new BotaClient().get('/v1/devices')); }), fixed('developer_recovery_required'));
  assert.equal(f.output.length, 0); assert.equal(f.held, 0);
});

test('output failure retains the conservative already-executed diagnostic after business work', async () => {
  const f = await fixture(); f.onWrite = async () => { throw Error('PRIVATE_WRITER'); };
  await assert.rejects(f.service.run('work', 'rest', async () => { printJson(await new BotaClient().get('/v1/devices')); }), error => {
    assert.equal(developerProfileFailure(error)?.code, 'developer_output_failed');
    assert.equal(developerProfileFailure(error)?.operation_may_have_executed, true); return true;
  });
  assert.equal(f.business, 1); assert.equal(f.held, 0); assert.equal(f.context.signal.aborted, true);
});
test('parent cancellation during native close joins cleanup and discards buffered success', async () => {
  const f = await fixture(), entered = defer(), release = defer(), parent = new AbortController(); let settled = false;
  f.beforeClose = async () => { entered.resolve(); await release.promise; };
  const running = f.service.run('work', 'rest', async () => { printJson(await new BotaClient().get('/v1/devices')); }, { signal: parent.signal }).finally(() => { settled = true; });
  void running.catch(() => {}); await entered.promise; parent.abort('PRIVATE_ABORT'); await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.equal(f.output.length, 0); release.resolve(); await assert.rejects(running, fixed('developer_cancelled'));
  assert.equal(f.context.signal.aborted, true); assert.equal(f.output.length, 0);
});
test('authoritative access expiry is rechecked after native runtime cleanup', async () => {
  const f = await fixture(), original = Date.now;
  f.beforeClose = async () => { const expiry = Math.max(...[...f.identities.values()].map(value => value.expiresAtSeconds)); Date.now = () => expiry * 1000; };
  try { await assert.rejects(f.service.run('work', 'rest', async () => { printJson(await new BotaClient().get('/v1/devices')); }), fixed('developer_deadline')); }
  finally { Date.now = original; }
  assert.equal(f.output.length, 0); assert.equal(f.context.signal.aborted, true);
});

test('expiry during a joined output write withdraws later buffered chunks', async () => {
  const f = await fixture(), original = Date.now;
  f.onWrite = async () => { const expiry = Math.max(...[...f.identities.values()].map(value => value.expiresAtSeconds)); Date.now = () => expiry * 1000; };
  try { await assert.rejects(f.service.run('work', 'rest', async () => { printJson({ first: true }); printJson({ second: true }); }), fixed('developer_deadline')); }
  finally { Date.now = original; }
  assert.equal(f.output.length, 1); assert.deepEqual(JSON.parse(f.output[0].text), { first: true }); assert.equal(f.context.signal.aborted, true);
});

test('cancellation of a stalled output acknowledgement preserves family state and never resumes later chunks', async () => {
  const f = await fixture(), entered = defer(), release = defer(), parent = new AbortController();
  f.onWrite = async () => { entered.resolve(); await release.promise; };
  const running = f.service.run('work', 'rest', async () => { printJson({ first: true }); printJson({ second: true }); return 'must-not-return'; }, { signal: parent.signal });
  void running.catch(() => {}); await entered.promise;
  assert.equal(f.held, 0); assert.equal(f.closes, 1);
  const saved = JSON.stringify({ profile: f.profile, snapshots: [...f.snapshots], secrets: [...f.secrets], proofs: [...f.proofs], initial: [...f.initial] });
  const posts = f.tokenPosts + f.revokePosts;
  parent.abort('PRIVATE_ABORT');
  await assert.rejects(running, error => {
    fixed('developer_cancelled')(error); assert.equal(developerProfileFailure(error).recovery_required, true);
    assert.equal(developerProfileFailure(error).operation_may_have_executed, true); return true;
  });
  assert.equal(f.context.signal.aborted, true); release.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.output.length, 1); assert.equal(f.tokenPosts + f.revokePosts, posts);
  assert.equal(JSON.stringify({ profile: f.profile, snapshots: [...f.snapshots], secrets: [...f.secrets], proofs: [...f.proofs], initial: [...f.initial] }), saved);
});

test('the original service deadline refuses a stalled output acknowledgement after cleanup', async () => {
  const f = await fixture(), entered = defer(), release = defer();
  f.onWrite = async () => { entered.resolve(); await release.promise; };
  const running = f.service.run('work', 'rest', async () => { printJson({ first: true }); printJson({ second: true }); }, { timeoutMs: 250 });
  void running.catch(() => {}); await entered.promise; const posts = f.tokenPosts + f.revokePosts;
  await assert.rejects(running, fixed('developer_deadline')); assert.equal(f.closes, 1); assert.equal(f.held, 0);
  release.resolve(); await new Promise(resolve => setImmediate(resolve)); assert.equal(f.output.length, 1);
  assert.equal(f.profile.state, 'ready'); assert.equal(f.tokenPosts + f.revokePosts, posts);
});
test('profile deployment mismatch cannot retarget identity or business transport', async () => {
  const f = await fixture(); f.profile = { ...f.profile, deployment: { ...deployment, issuer: 'https://foreign.example.test' } };
  await assert.rejects(f.service.status('work'), fixed('developer_operation_failed')); assert.equal(f.tokenPosts + f.business, 0); assert.equal(f.closes, 1);
});
test('logout confirms the exact family then removes refs and tombstones the selected profile', async () => {
  const f = await fixture(); const profile = await f.service.logout('work');
  assert.equal(profile.state, 'removed'); assert.equal(f.secrets.size, 0); assert.equal(f.snapshots.get(JSON.stringify(f.key)).state, 'removed');
});
test('ready profile retaining original attempt metadata recovers unknown family revocation without reading deleted proof', async () => {
  const f = await fixture(); let proofReads = 0;
  f.runtime.readRecovery = async () => { proofReads++; throw Error('PRIVATE_DELETED_PROOF'); };
  f.revokeUnknown = true; await assert.rejects(f.service.logout('work'), fixed('developer_recovery_required'));
  assert.equal(f.snapshots.get(JSON.stringify(f.key)).state, 'revoking'); assert.ok(f.profile.attemptId); assert.equal(f.profile.state, 'ready');
  f.revokeUnknown = false; const recovered = await f.service.recover('work');
  assert.equal(recovered.state, 'removed'); assert.equal(f.secrets.size, 0); assert.equal(proofReads, 0);
});
test('ready profile retaining original attempt metadata recovers removal without another remote revoke or proof read', async () => {
  const f = await fixture(); let proofReads = 0;
  f.runtime.readRecovery = async () => { proofReads++; throw Error('PRIVATE_DELETED_PROOF'); };
  f.deleteUnknown = true; await assert.rejects(f.service.logout('work'), fixed('developer_recovery_required'));
  assert.equal(f.snapshots.get(JSON.stringify(f.key)).state, 'removing'); const before = f.revokePosts;
  f.deleteUnknown = false; const recovered = await f.service.recover('work');
  assert.equal(recovered.state, 'removed'); assert.equal(f.secrets.size, 0); assert.equal(proofReads, 0); assert.equal(f.revokePosts, before);
});

test('explicit recovery retires only an empty reserved name without proof or network access', async () => {
  const f = await fixture(false); await f.runtime.reserve('work', deployment, context());
  f.runtime.readRecovery = async () => { throw Error('PRIVATE_UNEXPECTED_PROOF_READ'); };
  const value = await f.service.recover('work'); assert.equal(value.state, 'removed');
  assert.deepEqual(f.calls, ['reserve', 'reserved-abandoned']); assert.equal(f.tokenPosts + f.revokePosts + f.browsers, 0);
});

test('confirmed cleanup resumes its durable local receipt even after proof deletion', async () => {
  for (const state of ['cleanup-confirmed', 'removing']) {
    const f = await fixture(false); f.profile = { name: 'work', state, attemptId: randomUUID(), familyKey: null, pendingFamilyKey: null, deployment };
    f.runtime.readRecovery = async () => { throw Error('PRIVATE_ALREADY_DELETED_PROOF'); };
    const value = await f.service.recover('work'); assert.equal(value.state, 'removed');
    assert.deepEqual(f.calls, ['cleanup-resumed']); assert.equal(f.tokenPosts + f.revokePosts + f.browsers, 0);
  }
});
test('readonly inspect joins cleanup and retires its issued context before returning', async () => {
  const f = await fixture(), value = await f.service.inspect('work'); assert.equal(value.name, 'work');
  assert.equal(f.context.signal.aborted, true); assert.throws(() => f.context.budget.assertActive()); assert.equal(f.tokenPosts, 0);
});
test('reflective list entries refuse without invoking getters or leaking private values', async () => {
  const f = await fixture(); let hooks = 0;
  f.runtime.list = async () => [{ get name() { hooks++; throw Error('PRIVATE_LIST'); } }];
  await assert.rejects(f.service.list(), fixed('developer_operation_failed')); assert.equal(hooks, 0); assert.equal(f.closes, 1);
});

test('metadata list accepts the complete native 2048-record limit and refuses overflow', async () => {
  const f = await fixture(false);
  f.runtime.list = async () => Array.from({ length: 2048 }, (_, index) => ({ name: 'work-' + index, state: 'reserved', attemptId: null, familyKey: null, pendingFamilyKey: null, deployment }));
  const values = await f.service.list(); assert.equal(values.length, 2048); assert.ok(values[0].name < values.at(-1).name);
  f.runtime.list = async () => Array.from({ length: 2049 }, (_, index) => ({ name: 'work-' + index, state: 'reserved', attemptId: null, familyKey: null, pendingFamilyKey: null, deployment }));
  await assert.rejects(f.service.list(), fixed('developer_operation_failed')); assert.equal(f.tokenPosts + f.revokePosts, 0);
});
