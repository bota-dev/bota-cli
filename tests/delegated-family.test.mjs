import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners } from 'node:events';
import test from 'node:test';
import { createTrustedDelegatedEnrollmentHandoff, DelegatedFamilyEngine } from '../src/delegated-family-engine.ts';
import { DELEGATED_REFRESH_NAMESPACE, DelegatedFamilyError, decodeDelegatedFamilySnapshot, decodeDelegatedFamilySnapshotBytes,
  encodeDelegatedFamilySnapshot, familyKeyOf, familyReferences } from '../src/delegated-family-state.ts';

const canary = 'PRIVATE_FAMILY_FAILURE_CANARY';
const token = kind => `bota_d${kind === 'access' ? 'a' : 'r'}1_${randomBytes(32).toString('base64url')}`;
const clone = value => structuredClone(value);
const deployment = () => ({ version: 1, issuer: 'https://issuer.example.test', endpoints: {
  authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
  resources: { rest: 'https://api.example.test/v1', mcp: 'https://mcp.example.test/mcp' }, client: { clientId: 'registered-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
function context() {
  const controller = new AbortController(), state = { expired: false };
  return { controller, state, value: { signal: controller.signal, budget: { assertActive() { if (state.expired) throw Error(canary); } } } };
}
function fails(...codes) {
  return error => { assert.ok(error instanceof DelegatedFamilyError, error); assert.ok(codes.includes(error.code), error.code);
    assert.doesNotMatch(String(error), /PRIVATE_FAMILY_FAILURE_CANARY|bota_dr1_|bota_da1_|example\.test/); assert.equal(error.cause, undefined); return true; };
}
function recoveryFailure(code, required = true) {
  return error => { assert.equal(error.recoveryRequired, required); return fails(code)(error); };
}
function retired(actualContext) {
  assert.equal(actualContext.signal.aborted, true);
  assert.throws(() => actualContext.budget.assertActive(), recoveryFailure('lease_failed'));
  assert.doesNotMatch(String(actualContext.signal.reason), /PRIVATE_FAMILY_FAILURE_CANARY|bota_dr1_|bota_da1_/);
}
function fixture(overrides = {}) {
  const d = deployment(), ctx = context(), snapshots = new Map(), secrets = new Map(), identities = new Map();
  const originalBudget = ctx.value.budget;
  const f = { d, ctx, snapshots, secrets, identities, issuedContexts: [], time: 1000, held: 0, maxHeld: 0, events: [], exchanges: [], revokes: [], revokeBindings: [], writes: [], deletes: [],
    publishFaults: [], writeFault: null, deleteFault: null, exchangeMode: null, revokeMode: null, identityHook: null, afterPublish: null, afterExchange: null,
    userId: randomUUID(), grantId: randomUUID(), familyId: randomUUID(), grantResources: [d.resources.rest, d.resources.mcp], grantScopes: ['devices:read', 'recordings:read'],
    ...overrides };
  const keyString = key => JSON.stringify(key);
  const refString = ref => JSON.stringify(ref);
  const snapshot = key => snapshots.has(keyString(key)) ? decodeDelegatedFamilySnapshotBytes(snapshots.get(keyString(key)), key) : null;
  const pinnedContext = actualContext => { assert.notEqual(actualContext, ctx.value); assert.ok(Object.isFrozen(actualContext));
    assert.notEqual(actualContext.signal, ctx.controller.signal); assert.notEqual(actualContext.budget, originalBudget);
    assert.ok(Object.isFrozen(actualContext.budget)); assert.equal(actualContext.signal.aborted, false); actualContext.budget.assertActive();
    if (!f.issuedContexts.includes(actualContext)) f.issuedContexts.push(actualContext); };
  const locked = (kind, key, actualContext) => { pinnedContext(actualContext); assert.equal(actualContext, f.activeContext); assert.equal(f.held, 1, kind); f.events.push(kind); };
  const pair = resource => {
    const value = { accessToken: token('access'), refreshToken: token('refresh'), resource, expiresAtSeconds: f.time + 300,
      grantId: f.grantId, familyId: f.familyId, scopes: [...f.grantScopes] };
    identities.set(value.accessToken, { issuer: d.issuer, clientId: d.client.clientId, userId: f.userId, organizationId: 'org-one', projectId: 'project-one',
      grantId: f.grantId, familyId: f.familyId, grantResourceUris: [...f.grantResources], grantScopes: [...f.grantScopes],
      resource, accessScopes: [...value.scopes], expiresAtSeconds: value.expiresAtSeconds });
    return value;
  };
  f.initial = pair(d.resources.rest); f.serverRefresh = f.initial.refreshToken; f.consumed = new Set(); f.serverRevoked = false;
  const queues = new Map();
  f.ports = {
    store: { id: 'delegated-test', async read(ref, actualContext) { locked('read', ref, actualContext); assert.equal(ref.namespace, DELEGATED_REFRESH_NAMESPACE);
      return secrets.has(refString(ref)) ? { status: 'present', refreshToken: secrets.get(refString(ref)) } : { status: 'absent' }; },
      async write(ref, secret, actualContext) { locked('write', ref, actualContext); f.writes.push(clone(ref));
        assert.equal(ref.namespace, DELEGATED_REFRESH_NAMESPACE); if (secrets.has(refString(ref))) return 'not_stored';
        const fault = f.writeFault; f.writeFault = null; if (fault === 'unknown_before') return 'unknown';
        secrets.set(refString(ref), secret); return fault === 'unknown_after' ? 'unknown' : 'stored'; },
      async delete(ref, actualContext) { locked('delete', ref, actualContext); f.deletes.push(clone(ref));
        const fault = f.deleteFault; f.deleteFault = null; if (fault === 'unknown_before') return 'unknown';
        const existed = secrets.delete(refString(ref)); return fault === 'unknown_after' ? 'unknown' : existed ? 'deleted' : 'absent'; } },
    snapshots: { async load(key, actualContext) { locked('load', key, actualContext); return snapshot(key); },
      async publish(key, expected, next, actualContext) { locked('publish:' + next.state, key, actualContext);
        const current = snapshot(key); if ((current?.revision ?? null) !== expected) return 'not_committed';
        assert.doesNotMatch(JSON.stringify(next), /bota_dr1_|bota_da1_/);
        const index = f.publishFaults.findIndex(fault => fault.state === next.state);
        const fault = index < 0 ? null : f.publishFaults.splice(index, 1)[0];
        if (fault?.mode === 'unknown_before') return 'unknown';
        snapshots.set(keyString(key), encodeDelegatedFamilySnapshot(next, key)); f.afterPublish?.(next);
        if (fault?.mode === 'throw_after') throw Error(canary); return fault ? 'unknown' : 'committed'; } },
    lease: { async runExclusive(key, actualContext, work) {
      pinnedContext(actualContext); assert.deepEqual(Object.keys(key), ['storeId', 'issuer', 'clientId', 'familyId']);
      const name = keyString(key), previous = queues.get(name) ?? Promise.resolve(); let release;
      const next = new Promise(resolve => { release = resolve; }); queues.set(name, previous.then(() => next)); await previous;
      f.held++; f.activeContext = actualContext; f.maxHeld = Math.max(f.maxHeld, f.held); f.events.push('lease-enter');
      try { const value = await work(); if (f.releaseFault) throw Error(canary); return value; }
      finally { f.held--; f.events.push('lease-close'); release(); }
    } },
    async verifyAccess(selected, access, resource, actualContext) {
      pinnedContext(actualContext); if (f.held) assert.equal(actualContext, f.activeContext); assert.deepEqual(selected, d); f.events.push('identity');
      if (f.serverRevoked || !identities.has(access)) throw Error(canary);
      const value = clone(identities.get(access)); if (f.identityHook) return f.identityHook(value, access, resource); return value;
    },
    async exchange(selected, refresh, resource, actualContext) {
      locked('exchange', null, actualContext); assert.deepEqual(selected, d); f.exchanges.push({ refresh, resource });
      assert.ok(['refreshing', 'suspended'].includes(snapshot(f.key).state));
      if (f.serverRevoked || refresh !== f.serverRefresh || f.consumed.has(refresh)) { f.serverRevoked = true; throw Error(canary); }
      f.consumed.add(refresh); const value = pair(resource); f.serverRefresh = value.refreshToken; f.afterExchange?.();
      if (f.exchangeMode === 'unknown_after') throw Error(canary);
      if (f.exchangeMode === 'malformed_after') return { accessToken: canary };
      return value;
    },
    async revoke(selected, refresh, expected, actualContext) {
      locked('revoke', null, actualContext); assert.deepEqual(selected, d); f.revokes.push(refresh);
      assert.ok(Object.isFrozen(expected)); assert.deepEqual(expected, { grantId: f.grantId, familyId: f.familyId });
      f.revokeBindings.push(clone(expected));
      assert.equal(snapshot(f.key).state, 'revoking'); assert.ok(refresh === f.serverRefresh || f.consumed.has(refresh));
      if (f.revokeMode === 'not_submitted') return 'not_submitted';
      f.serverRevoked = true; if (f.revokeMode === 'unknown_after') return 'unknown'; return Object.freeze({ grantId: f.grantId, familyId: f.familyId });
    }, nowSeconds: () => f.time,
  };
  f.engine = new DelegatedFamilyEngine(f.ports);
  f.key = { storeId: f.ports.store.id, issuer: d.issuer, clientId: d.client.clientId, familyId: f.familyId };
  f.handoff = () => createTrustedDelegatedEnrollmentHandoff(d, async actualContext => { pinnedContext(actualContext); f.events.push('handoff'); return clone(f.initial); });
  f.seed = () => f.engine.enroll(f.handoff(), ctx.value);
  f.read = () => snapshot(f.key);
  f.secret = ref => secrets.get(refString(ref));
  f.fresh = () => new DelegatedFamilyEngine(f.ports);
  return f;
}

test('initial trusted handoff is one-use and public copied DTO/forged handles grant nothing', async () => {
  const f = fixture(); await assert.rejects(f.engine.enroll({ ...f.initial }, f.ctx.value), fails('invalid_input'));
  assert.equal(f.events.length, 0); const handoff = f.handoff(), ready = await f.engine.enroll(handoff, f.ctx.value);
  assert.equal(ready.state, 'ready'); assert.equal(ready.localGeneration, 0); assert.equal(f.secret(ready.current), f.initial.refreshToken);
  assert.ok(f.events.indexOf('identity') < f.events.indexOf('lease-enter')); assert.ok(f.events.indexOf('publish:enrolling') < f.events.indexOf('write'));
  await assert.rejects(f.engine.enroll(handoff, f.ctx.value), fails('invalid_input')); assert.equal(f.writes.length, 1);
  assert.doesNotMatch(JSON.stringify(ready), /bota_da1_|bota_dr1_|accessToken|refreshToken/);
});

test('non-v4 canonical server user/grant/family UUIDs remain supported independently of local v4 IDs', async () => {
  const f = fixture({ userId: '00112233-4455-1677-8899-aabbccddeeff', grantId: '00112233-4455-7677-8899-aabbccddeeff', familyId: '00112233-4455-0677-0899-aabbccddeeff' });
  const ready = await f.seed(); assert.equal(ready.binding.userId, f.userId); assert.equal(ready.binding.grantId, f.grantId); assert.equal(ready.binding.familyId, f.familyId);
  assert.match(ready.localFamilyId, /^[0-9a-f-]{14}4/);
  for (const invalid of ['00112233-4455-1677-8899-AABBCCDDEEFF', '00112233445516778899aabbccddeeff', canary, f.userId + '\n']) {
    const changed = clone(ready); changed.binding.userId = invalid; assert.throws(() => decodeDelegatedFamilySnapshot(changed, f.key), fails('invalid_state'));
  }
});

test('same-family concurrent initial handoffs collide under one canonical lease without replacing a family', async () => {
  const f = fixture(), other = f.fresh(); const outcomes = await Promise.allSettled([f.seed(), other.enroll(f.handoff(), f.ctx.value)]);
  assert.equal(outcomes.filter(value => value.status === 'fulfilled').length, 1);
  assert.ok(outcomes.some(value => value.status === 'rejected' && value.reason.code === 'exists'));
  assert.equal(f.writes.length, 1); assert.equal(f.secrets.size, 1); assert.equal(f.maxHeld, 1); assert.equal(f.read().state, 'ready');
});

test('grant resources/scopes come from current authority, never requested deployment resources or a cached label', async () => {
  const f = fixture({ grantResources: ['https://api.example.test/v1'], grantScopes: ['devices:read'] }); const ready = await f.seed();
  assert.deepEqual(ready.binding.grantResourceUris, [f.d.resources.rest]);
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value), fails('binding_mismatch')); assert.equal(f.exchanges.length, 0);
  f.identityHook = value => ({ ...value, accessScopes: ['devices:read', 'summaries:read'] });
  let called = false; await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => { called = true; }), fails('invalid_state', 'identity_failed'));
  assert.equal(called, false); assert.equal(f.exchanges.length, 0);
});

test('cached access rechecks authoritative identity and holds the family lease through caller action', async () => {
  const f = fixture(); await f.seed(); let finish; const joined = new Promise(resolve => { finish = resolve; });
  const running = f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async access => {
    assert.equal(f.held, 1); assert.equal(access.resource, f.d.resources.rest); assert.equal(access.accessToken, f.initial.accessToken); await joined; return 'ok';
  });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(f.held, 1); finish(); assert.equal(await running, 'ok'); assert.equal(f.held, 0);
  f.identityHook = value => ({ ...value, projectId: 'other-project' }); let called = false;
  await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => { called = true; }), fails('binding_mismatch')); assert.equal(called, false);
});

test('one refresh follows durable intent, verifies successor and atomically advances current plus consumed proof', async () => {
  const f = fixture(); const initial = await f.seed(); const rotated = await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value);
  assert.equal(rotated.state, 'ready'); assert.equal(rotated.localGeneration, 1); assert.deepEqual(rotated.proof, initial.current);
  assert.equal(f.secret(rotated.proof), f.initial.refreshToken); assert.equal(f.secret(rotated.current), f.serverRefresh);
  assert.ok(f.events.indexOf('publish:refreshing') < f.events.indexOf('exchange'));
  assert.equal(f.exchanges.length, 1); assert.equal(f.deletes.length, 0); assert.equal(f.secrets.size, 2);
});

test('only superseded older proof is deleted after a second verified durable rotation', async () => {
  const f = fixture(); const initial = await f.seed(); const first = await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value);
  const second = await f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value);
  assert.equal(second.localGeneration, 2); assert.deepEqual(second.proof, first.current); assert.deepEqual(f.deletes, [initial.current]);
  assert.equal(f.secret(initial.current), undefined); assert.equal(f.secrets.size, 2); assert.equal(f.secret(second.proof), f.exchanges[1].refresh);
});

test('CLI/MCP resource rotations serialize under the same family key and never replay a generation', async () => {
  const f = fixture(); await f.seed(); const other = f.fresh();
  await Promise.all([f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), other.refresh(f.key, f.d.resources.mcp, f.ctx.value)]);
  assert.equal(f.maxHeld, 1); assert.equal(f.read().localGeneration, 2); assert.equal(f.exchanges.length, 2);
  assert.notEqual(f.exchanges[0].refresh, f.exchanges[1].refresh); assert.equal(f.serverRevoked, false);
});

test('lost remote refresh response blocks every instance and cached resource without any identity/business request', async () => {
  const f = fixture(); const initial = await f.seed(); f.exchangeMode = 'unknown_after'; const other = f.fresh();
  await assert.rejects(other.refresh(f.key, f.d.resources.mcp, f.ctx.value), fails('refresh_unknown'));
  const state = f.read(); assert.ok(['refreshing', 'suspended'].includes(state.state)); assert.deepEqual(state.current, initial.current);
  const before = f.events.filter(value => value === 'identity').length;
  for (const engine of [f.engine, other, f.fresh()]) {
    await assert.rejects(engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail('cached access escaped')), fails('pending'));
    await assert.rejects(engine.refresh(f.key, f.d.resources.mcp, f.ctx.value), fails('pending'));
  }
  assert.equal(f.events.filter(value => value === 'identity').length, before); assert.equal(f.exchanges.length, 1);
  assert.equal(f.secret(state.current), f.initial.refreshToken); await assert.rejects(f.engine.recoverRotation(f.key, f.ctx.value), fails('pending'));
});

test('a crash after durable intent but before exchange does not restart or replay refresh', async () => {
  const f = fixture(); await f.seed(); f.afterPublish = next => { if (next.state === 'refreshing') f.ctx.state.expired = true; };
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), recoveryFailure('deadline')); assert.equal(f.exchanges.length, 0);
  f.ctx.state.expired = false; f.afterPublish = null; await assert.rejects(f.fresh().refresh(f.key, f.d.resources.rest, f.ctx.value), fails('pending'));
  assert.equal(f.exchanges.length, 0); assert.equal(f.secrets.size, 1);
});

test('malformed or contradictory definitive refresh results remain blocked and retain all exact references', async () => {
  const f = fixture(); await f.seed(); f.exchangeMode = 'malformed_after';
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), fails('refresh_unknown'));
  assert.ok(f.read().intent.candidate); assert.equal(f.secrets.size, 1); assert.equal(f.deletes.length, 0);
});

test('successor store uncertainty preserves the candidate and refuses adoption or cached access after restart', async () => {
  const f = fixture(); await f.seed(); f.writeFault = 'unknown_after';
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value), fails('store_unknown'));
  const pending = f.read(); assert.equal(pending.state, 'refreshing'); assert.ok(f.secret(pending.intent.candidate)); assert.equal(f.secrets.size, 2);
  await assert.rejects(f.fresh().recoverRotation(f.key, f.ctx.value), fails('pending'));
  await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), fails('pending'));
  assert.equal(f.exchanges.length, 1); assert.equal(f.deletes.length, 0);
});

test('unknown rotation CAS retains intent or proven rotating state, never retries exchange', async () => {
  for (const mode of ['unknown_before', 'unknown_after']) {
    const f = fixture(); await f.seed(); f.publishFaults.push({ state: 'rotating', mode });
    await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), fails('metadata_unknown'));
    assert.equal(f.exchanges.length, 1); assert.equal(f.secrets.size, 2); assert.equal(f.deletes.length, 0);
    if (mode === 'unknown_before') await assert.rejects(f.fresh().recoverRotation(f.key, f.ctx.value), fails('pending'));
    else { const ready = await f.fresh().recoverRotation(f.key, f.ctx.value); assert.equal(ready.state, 'ready'); assert.equal(ready.localGeneration, 1); }
    assert.equal(f.exchanges.length, 1);
  }
});

test('lost local ready-CAS ACK differs from lost remote response: exact durable ready can be read without replay', async () => {
  const f = fixture(); await f.seed(); f.publishFaults.push({ state: 'ready', mode: 'unknown_after' });
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value), fails('metadata_unknown'));
  assert.equal(f.read().state, 'ready'); assert.equal(f.read().localGeneration, 1); assert.equal(f.exchanges.length, 1);
  const restarted = f.fresh(), actual = await restarted.inspect(f.key, f.ctx.value);
  assert.equal(actual.state, 'ready'); assert.equal(f.exchanges.length, 1); assert.equal(f.secret(actual.current), f.serverRefresh);
  await restarted.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => 'ok');
  assert.equal(f.exchanges.length, 2); assert.notEqual(f.exchanges[0].refresh, f.exchanges[1].refresh);
});

test('uncertain proof cleanup is recoverable only from verified rotating metadata with exact absent readback', async () => {
  const f = fixture(); await f.seed(); await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value); f.deleteFault = 'unknown_after';
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), fails('store_unknown'));
  assert.equal(f.read().state, 'rotating'); const count = f.deletes.length;
  const ready = await f.fresh().recoverRotation(f.key, f.ctx.value); assert.equal(ready.state, 'ready'); assert.equal(ready.localGeneration, 2);
  assert.equal(f.deletes.length, count); assert.equal(f.exchanges.length, 2); assert.equal(f.secrets.size, 2);
});

test('revocation after unknown rotation uses retained consumed proof despite ordinary authority loss', async () => {
  const f = fixture(); await f.seed(); f.exchangeMode = 'unknown_after';
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), fails('refresh_unknown'));
  f.identityHook = () => { throw Error(canary); }; const verifiedBefore = f.events.filter(value => value === 'identity').length;
  const revoked = await f.fresh().revoke(f.key, f.ctx.value); assert.equal(revoked.state, 'revoked'); assert.deepEqual(f.revokes, [f.initial.refreshToken]);
  assert.ok(f.consumed.has(f.revokes[0])); assert.equal(f.events.filter(value => value === 'identity').length, verifiedBefore);
  assert.equal(f.secrets.size, 1); assert.equal(f.deletes.length, 0);
});

test('unknown revocation blocks all access/removal and repeats only exact proof through explicit recovery', async () => {
  const f = fixture(); await f.seed(); await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value); f.revokeMode = 'unknown_after';
  await assert.rejects(f.engine.revoke(f.key, f.ctx.value), fails('revocation_unknown')); assert.equal(f.read().state, 'revoking');
  assert.equal(f.secrets.size, 2); await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('pending'));
  await assert.rejects(f.engine.revoke(f.key, f.ctx.value), fails('pending')); assert.equal(f.revokes.length, 1);
  await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), fails('pending'));
  f.revokeMode = null; const revoked = await f.fresh().recoverRevocation(f.key, f.ctx.value); assert.equal(revoked.state, 'revoked');
  assert.equal(f.revokes.length, 2); assert.equal(f.revokes[0], f.revokes[1]); assert.ok(f.consumed.has(f.revokes[0])); assert.equal(f.exchanges.length, 1);
});

test('revocation supplies frozen expected grant/family from the leased binding for current and consumed proofs', async () => {
  for (const consumed of [false, true]) {
    const f = fixture(consumed ? { grantId: '00112233-4455-7677-8899-aabbccddeeff', familyId: '00112233-4455-0677-0899-aabbccddeeff' } : {});
    const initial = await f.seed(); if (consumed) await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value);
    const state = f.read(), original = f.ports.revoke; let captured;
    f.ports.revoke = async (selected, refresh, expected, actualContext) => {
      captured = expected; assert.deepEqual(expected, { grantId: state.binding.grantId, familyId: state.binding.familyId });
      assert.ok(Object.isFrozen(expected)); assert.throws(() => { expected.familyId = randomUUID(); }, TypeError);
      return original(selected, refresh, expected, actualContext);
    };
    const revoked = await f.engine.revoke(f.key, f.ctx.value); assert.equal(revoked.state, 'revoked');
    assert.equal(f.revokes[0], f.initial.refreshToken); assert.deepEqual(f.revokeBindings, [captured]);
    assert.equal(f.consumed.has(f.revokes[0]), consumed); assert.equal(f.secret(initial.current), f.initial.refreshToken);
  }
});

test('empty200-like, raw wire, wrong binding or extra-field receipts retain proofs until exact explicit recovery', async () => {
  const badReceipts = [
    () => undefined, () => null, () => '', () => 200, () => ({}), () => 'revoked', () => 'unknown', () => 'not_submitted',
    () => ({ status: 200, body: '' }),
    f => ({ bota_revoked: true, bota_grant_id: f.grantId, bota_family_id: f.familyId }),
    f => ({ grantId: randomUUID(), familyId: f.familyId }), f => ({ grantId: f.grantId, familyId: randomUUID() }),
    f => ({ grantId: '00112233-4455-6677-8899-AABBCCDDEEFF', familyId: f.familyId }),
    f => ({ grantId: f.grantId }), f => ({ familyId: f.familyId }),
    f => ({ grantId: f.grantId, familyId: f.familyId, bota_revoked: true }),
    f => ({ grantId: f.grantId, familyId: f.familyId, refreshToken: token('refresh') }),
    f => ({ grantId: f.grantId, familyId: f.familyId, accessToken: token('access') }),
    f => ({ grantId: f.grantId, familyId: f.familyId, error: canary }),
  ];
  for (const receipt of badReceipts) {
    const f = fixture(); await f.seed(); await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value);
    const before = familyReferences(f.read()), original = f.ports.revoke;
    f.ports.revoke = async (...args) => { await original(...args); return receipt(f); };
    await assert.rejects(f.engine.revoke(f.key, f.ctx.value), recoveryFailure('revocation_unknown'));
    assert.equal(f.read().state, 'revoking'); assert.deepEqual(familyReferences(f.read()), before); assert.equal(f.secrets.size, 2);
    assert.equal(f.deletes.length, 0); assert.equal(f.revokes.length, 1);
    const identityCount = f.events.filter(value => value === 'identity').length;
    await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), fails('pending'));
    await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('pending')); await assert.rejects(f.engine.revoke(f.key, f.ctx.value), fails('pending'));
    assert.equal(f.events.filter(value => value === 'identity').length, identityCount); assert.equal(f.revokes.length, 1); assert.equal(f.deletes.length, 0);
    f.ports.revoke = original; assert.equal((await f.fresh().recoverRevocation(f.key, f.ctx.value)).state, 'revoked');
    assert.equal(f.revokes.length, 2); assert.equal(f.revokes[0], f.revokes[1]); assert.deepEqual(f.revokeBindings[0], f.revokeBindings[1]);
    await f.engine.remove(f.key, f.ctx.value); assert.equal(f.secrets.size, 0);
  }
});

test('not-submitted revocation remains disabled without pretending the server revoked or retrying implicitly', async () => {
  const f = fixture(); await f.seed(); f.revokeMode = 'not_submitted';
  await assert.rejects(f.engine.revoke(f.key, f.ctx.value), recoveryFailure('revocation_unknown'));
  assert.equal(f.serverRevoked, false); assert.equal(f.read().state, 'revoking'); assert.equal(f.revokes.length, 1); assert.equal(f.secrets.size, 1);
  await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('pending')); assert.equal(f.deletes.length, 0);
  f.revokeMode = null; assert.equal((await f.fresh().recoverRevocation(f.key, f.ctx.value)).state, 'revoked');
  assert.equal(f.serverRevoked, true); assert.equal(f.revokes.length, 2); assert.equal(f.revokes[0], f.revokes[1]);
});

test('reflective or forged receipt shapes cannot confirm a family or evaluate private receipt hooks', async () => {
  let hooks = 0;
  for (const shape of ['accessor', 'proxy', 'inherited', 'extra_symbol', 'array']) {
    const f = fixture(); await f.seed(); const original = f.ports.revoke;
    const expected = { grantId: f.grantId, familyId: f.familyId };
    let receipt;
    if (shape === 'accessor') receipt = Object.defineProperty({ familyId: f.familyId }, 'grantId', { enumerable: true, get() { hooks++; throw Error(canary); } });
    else if (shape === 'proxy') receipt = new Proxy(expected, { ownKeys() { hooks++; throw Error(canary); }, getOwnPropertyDescriptor() { hooks++; throw Error(canary); }, getPrototypeOf() { hooks++; throw Error(canary); } });
    else if (shape === 'inherited') receipt = Object.create(expected);
    else if (shape === 'extra_symbol') receipt = { ...expected, [Symbol(canary)]: canary };
    else receipt = [f.grantId, f.familyId];
    f.ports.revoke = async (...args) => { await original(...args); return receipt; };
    await assert.rejects(f.engine.revoke(f.key, f.ctx.value), recoveryFailure('revocation_unknown'));
    assert.equal(f.read().state, 'revoking'); assert.equal(f.secrets.size, 1); assert.equal(f.deletes.length, 0);
    await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('pending'));
  }
  assert.equal(hooks, 0);
});

test('confirmed revocation removal persists disable/cleanup, proves each exact absence and retains a tombstone', async () => {
  const f = fixture(); await f.seed(); await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value);
  const refs = familyReferences(await f.engine.revoke(f.key, f.ctx.value)); const removed = await f.engine.remove(f.key, f.ctx.value);
  assert.equal(removed.state, 'removed'); assert.deepEqual(removed.cleanup, []); assert.equal(f.secrets.size, 0);
  assert.deepEqual(new Set(f.deletes.map(ref => ref.credentialId)), new Set(refs.map(ref => ref.credentialId)));
  assert.ok(f.events.indexOf('publish:removing') < f.events.indexOf('delete'));
  await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), fails('removed'));
  await assert.rejects(f.fresh().enroll(f.handoff(), f.ctx.value), fails('identity_failed')); assert.equal(f.read().state, 'removed');
});

test('every accepted revoked inventory fits exact removal and oversized revocation cleanup is refused', async () => {
  const f = fixture(); await f.seed(); await f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value); f.writeFault = 'unknown_after';
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), recoveryFailure('store_unknown'));
  const revoked = await f.engine.revoke(f.key, f.ctx.value), refs = familyReferences(revoked);
  assert.equal(revoked.cleanup.length, 1); assert.equal(refs.length, 3); assert.equal(f.secrets.size, 3);
  assert.deepEqual(decodeDelegatedFamilySnapshotBytes(encodeDelegatedFamilySnapshot(revoked, f.key), f.key), revoked);
  for (const state of ['revoking', 'revoked']) {
    const oversized = clone(revoked); oversized.state = state;
    oversized.cleanup.push({ ...revoked.current, credentialId: randomUUID(), localGeneration: 3 });
    oversized.intent = state === 'revoking' ? { transactionId: randomUUID(), operation: 'revoke', resource: null, candidate: null } : null;
    assert.throws(() => decodeDelegatedFamilySnapshot(oversized, f.key), fails('invalid_state'));
  }
  assert.equal((await f.engine.remove(f.key, f.ctx.value)).state, 'removed'); assert.equal(f.secrets.size, 0);
  assert.deepEqual(new Set(f.deletes.map(ref => ref.credentialId)), new Set(refs.map(ref => ref.credentialId)));
});

test('unknown deletion retains its cleanup reference; restart proves absence and never blindly deletes it again', async () => {
  const f = fixture(); await f.seed(); await f.engine.revoke(f.key, f.ctx.value); f.deleteFault = 'unknown_after';
  await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('store_unknown')); assert.equal(f.read().state, 'removing');
  assert.equal(f.read().cleanup.length, 1); assert.equal(f.secrets.size, 0); assert.equal(f.deletes.length, 1);
  assert.equal((await f.fresh().recoverRemoval(f.key, f.ctx.value)).state, 'removed'); assert.equal(f.deletes.length, 1);
});

test('unknown enrollment write preserves exact intent and cannot adopt even a present candidate', async () => {
  const f = fixture(); f.writeFault = 'unknown_after'; await assert.rejects(f.seed(), fails('store_unknown'));
  assert.equal(f.read().state, 'enrolling'); assert.equal(f.secrets.size, 1);
  await assert.rejects(f.fresh().withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => assert.fail()), fails('pending'));
  const revoked = await f.fresh().revoke(f.key, f.ctx.value); assert.equal(revoked.state, 'revoked'); await f.engine.remove(f.key, f.ctx.value); assert.equal(f.secrets.size, 0);
});

test('enrollment crash before credential write cannot falsely confirm remote revocation or discard its record', async () => {
  const f = fixture(); f.publishFaults.push({ state: 'enrolling', mode: 'unknown_after' });
  await assert.rejects(f.seed(), fails('metadata_unknown')); assert.equal(f.read().state, 'enrolling'); assert.equal(f.secrets.size, 0);
  await assert.rejects(f.fresh().revoke(f.key, f.ctx.value), fails('store_absent')); assert.equal(f.read().state, 'revoking');
  assert.equal(f.revokes.length, 0); await assert.rejects(f.engine.remove(f.key, f.ctx.value), fails('pending')); assert.equal(f.deletes.length, 0);
});

test('cancellation after remote rotation keeps the old proof and never emits or uses successor access', async () => {
  const f = fixture(); await f.seed(); f.afterExchange = () => f.ctx.controller.abort(Error(canary));
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), recoveryFailure('cancelled'));
  assert.equal(f.read().state, 'refreshing'); assert.equal(f.exchanges.length, 1); assert.equal(f.secrets.size, 1); assert.equal(f.held, 0);
});

test('initial cancellation/deadline and cancellation after read-only admission require no recovery', async () => {
  for (const failure of ['cancelled', 'deadline']) {
    const f = fixture(); if (failure === 'cancelled') f.ctx.controller.abort(Error(canary)); else f.ctx.state.expired = true;
    await assert.rejects(f.engine.inspect(f.key, f.ctx.value), recoveryFailure(failure, false)); assert.deepEqual(f.events, []);
    assert.equal(f.snapshots.size, 0); assert.equal(f.secrets.size, 0); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
  }
  const f = fixture(); f.identityHook = value => { f.ctx.controller.abort(Error(canary)); return value; };
  await assert.rejects(f.seed(), recoveryFailure('cancelled', false));
  assert.equal(f.snapshots.size, 0); assert.equal(f.secrets.size, 0); assert.equal(f.exchanges.length, 0);
});

test('cancellation after possibly committed metadata, credential, revocation or caller effects requires recovery', async () => {
  for (const boundary of ['publish', 'write', 'delete', 'revoke', 'action']) {
    const f = fixture();
    if (boundary === 'publish') {
      f.afterPublish = () => f.ctx.controller.abort(Error(canary));
      await assert.rejects(f.seed(), recoveryFailure('cancelled')); assert.equal(f.read().state, 'enrolling'); assert.equal(f.secrets.size, 0);
    } else if (boundary === 'write') {
      const original = f.ports.store.write; f.ports.store.write = async (...args) => { const result = await original(...args); f.ctx.controller.abort(Error(canary)); return result; };
      await assert.rejects(f.seed(), recoveryFailure('cancelled')); assert.equal(f.read().state, 'enrolling'); assert.equal(f.secrets.size, 1);
    } else if (boundary === 'delete') {
      await f.seed(); await f.engine.revoke(f.key, f.ctx.value); const original = f.ports.store.delete;
      f.ports.store.delete = async (...args) => { const result = await original(...args); f.ctx.controller.abort(Error(canary)); return result; };
      await assert.rejects(f.engine.remove(f.key, f.ctx.value), recoveryFailure('cancelled')); assert.equal(f.read().state, 'removing'); assert.equal(f.read().cleanup.length, 1);
    } else if (boundary === 'revoke') {
      await f.seed(); const original = f.ports.revoke;
      f.ports.revoke = async (...args) => { const result = await original(...args); f.ctx.controller.abort(Error(canary)); return result; };
      await assert.rejects(f.engine.revoke(f.key, f.ctx.value), recoveryFailure('cancelled')); assert.equal(f.read().state, 'revoking'); assert.equal(f.revokes.length, 1);
    } else {
      await f.seed(); await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => { f.ctx.controller.abort(Error(canary)); }), recoveryFailure('cancelled'));
    }
    assert.equal(f.held, 0); for (const issued of f.issuedContexts) retired(issued);
  }
});

test('issued port contexts retire after success, ordinary failure and lease failure without retiring their parent', async () => {
  for (const outcome of ['success', 'failure', 'lease_failure']) {
    const f = fixture(); await f.seed();
    if (outcome === 'success') assert.equal((await f.engine.inspect(f.key, f.ctx.value)).state, 'ready');
    else if (outcome === 'failure') {
      f.writeFault = 'unknown_after'; await assert.rejects(f.engine.refresh(f.key, f.d.resources.mcp, f.ctx.value), recoveryFailure('store_unknown'));
    } else {
      f.releaseFault = true; await assert.rejects(f.engine.inspect(f.key, f.ctx.value), recoveryFailure('lease_failed'));
    }
    assert.equal(f.ctx.controller.signal.aborted, false); f.ctx.value.budget.assertActive();
    assert.ok(f.issuedContexts.length >= 2); for (const issued of f.issuedContexts) retired(issued);
    assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
  }
});

test('raw adapter errors remain fixed and caller action failure joins the lease', async () => {
  const f = fixture(); await f.seed();
  await assert.rejects(f.engine.withAccess(f.key, f.d.resources.rest, f.ctx.value, async () => { throw Error(canary); }), fails('operation_failed'));
  assert.equal(f.held, 0); f.releaseFault = true;
  await assert.rejects(f.engine.inspect(f.key, f.ctx.value), fails('lease_failed')); assert.equal(f.held, 0);
});

test('mutable known failures and forged, accessor or proxy throws never cross the fixed error boundary', async () => {
  let hooks = 0;
  const known = new DelegatedFamilyError('invalid_state'); known.message = canary; known.stack = canary; known.cause = Error(canary);
  const accessor = new DelegatedFamilyError('invalid_state'); Object.defineProperty(accessor, 'code', { get() { hooks++; throw Error(canary); } });
  const recoveryAccessor = new DelegatedFamilyError('invalid_state'); Object.defineProperty(recoveryAccessor, 'recoveryRequired', { get() { hooks++; throw Error(canary); } });
  const invalidCode = new DelegatedFamilyError(canary);
  const forged = Object.assign(Object.create(DelegatedFamilyError.prototype), { code: 'invalid_state', recoveryRequired: false, message: canary });
  let proxy; proxy = new Proxy({}, { get() { hooks++; throw proxy; }, getPrototypeOf() { hooks++; throw proxy; }, ownKeys() { hooks++; throw proxy; } });
  const inheritedProxy = Object.setPrototypeOf(Error(canary), proxy);
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  for (const injected of [known, accessor, recoveryAccessor, invalidCode, forged, proxy, inheritedProxy, revoked.proxy]) {
    const f = fixture(); f.ports.newId = () => { throw injected; };
    await assert.rejects(f.seed(), error => { assert.notEqual(error, injected);
      return recoveryFailure(injected === known ? 'invalid_state' : 'lease_failed', injected !== known)(error); });
    assert.equal(f.snapshots.size, 0); assert.equal(f.secrets.size, 0); assert.equal(f.held, 0); for (const issued of f.issuedContexts) retired(issued);
  }
  assert.equal(hooks, 0);
});

test('undefined and null lease rejections are distinct from successful release', async () => {
  for (const payload of [undefined, null]) {
    const f = fixture(); const original = f.ports.lease.runExclusive;
    f.ports.lease.runExclusive = async (...args) => { await original(...args); throw payload; };
    await assert.rejects(f.engine.inspect(f.key, f.ctx.value), recoveryFailure('lease_failed'));
    assert.equal(f.held, 0); assert.equal(f.events.filter(value => value === 'load').length, 1); for (const issued of f.issuedContexts) retired(issued);
    const empty = fixture(); empty.ports.lease.runExclusive = async () => { throw payload; };
    await assert.rejects(empty.engine.inspect(empty.key, empty.ctx.value), recoveryFailure('lease_failed', false)); assert.deepEqual(empty.events, []);
  }
});

test('a lease callback invoked after observed early settlement cannot start any port', async () => {
  const f = fixture(); let late;
  f.ports.lease.runExclusive = async (_key, _context, work) => { late = work; return null; };
  await assert.rejects(f.engine.inspect(f.key, f.ctx.value), fails('lease_failed')); assert.deepEqual(f.events, []);
  await assert.rejects(late(), fails('lease_failed')); assert.deepEqual(f.events, []);
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('early lease settlement retires and joins an already-started callback before reporting recovery', async () => {
  const f = fixture(); await f.seed(); let release, started; const waiting = new Promise(resolve => { started = resolve; });
  const blocked = new Promise(resolve => { release = resolve; }); const originalLoad = f.ports.snapshots.load;
  f.ports.snapshots.load = async (...args) => { const value = await originalLoad(...args); started(); await blocked; return value; };
  f.ports.lease.runExclusive = async (_key, actualContext, work) => {
    f.activeContext = actualContext; f.held = 1; const result = work(); void result.catch(() => {}); return null;
  };
  let settled = false; const pending = f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value).finally(() => { settled = true; });
  void pending.catch(() => {}); await waiting; await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  retired(f.activeContext);
  release(); await assert.rejects(pending, error => { assert.equal(error.recoveryRequired, true); return fails('lease_failed')(error); });
  assert.equal(f.exchanges.length, 0); assert.equal(f.writes.length, 1); f.held = 0;
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('signal retarget across an awaited exchange cannot replace the original cancellation authority', async () => {
  const f = fixture(); await f.seed();
  f.afterExchange = () => { f.ctx.value.signal = new AbortController().signal; f.ctx.value.budget = { assertActive() {} }; f.ctx.controller.abort(Error(canary)); };
  await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), recoveryFailure('cancelled'));
  assert.equal(f.exchanges.length, 1); assert.equal(f.secrets.size, 1); assert.equal(f.read().state, 'refreshing');
  assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('budget object and assertion retarget across await cannot replace the original opaque budget', async () => {
  for (const replaceMethod of [false, true]) {
    const f = fixture(); await f.seed(); const original = f.ctx.value.budget;
    f.afterPublish = next => { if (next.state === 'refreshing') { f.ctx.state.expired = true;
      if (replaceMethod) original.assertActive = () => {}; else f.ctx.value.budget = { assertActive() {} }; } };
    await assert.rejects(f.engine.refresh(f.key, f.d.resources.rest, f.ctx.value), recoveryFailure('deadline'));
    assert.equal(f.exchanges.length, 0); assert.equal(f.read().state, 'refreshing'); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
  }
});

test('private context getters/proxies are refused without invocation and native signal event methods are captured', async () => {
  const f = fixture(); let calls = 0;
  const getter = Object.defineProperty({ budget: f.ctx.value.budget }, 'signal', { enumerable: true, get() { calls++; throw Error(canary); } });
  const budget = Object.defineProperty({}, 'assertActive', { enumerable: true, get() { calls++; throw Error(canary); } });
  const proxy = new Proxy({}, { get() { calls++; throw Error(canary); }, ownKeys() { calls++; throw Error(canary); } });
  for (const value of [getter, proxy, { signal: f.ctx.controller.signal, budget }, { signal: f.ctx.controller.signal, budget: proxy },
    { signal: proxy, budget: f.ctx.value.budget }, { signal: Object.create(AbortSignal.prototype), budget: f.ctx.value.budget }]) {
    await assert.rejects(f.engine.inspect(f.key, value), fails('invalid_input'));
  }
  assert.equal(calls, 0); assert.deepEqual(f.events, []);
  Object.defineProperties(f.ctx.controller.signal, { addEventListener: { get() { calls++; throw Error(canary); } }, removeEventListener: { get() { calls++; throw Error(canary); } } });
  assert.equal(await f.engine.inspect(f.key, f.ctx.value), null); assert.equal(calls, 0); assert.equal(getEventListeners(f.ctx.controller.signal, 'abort').length, 0);
});

test('family namespace cannot split by profile alias, resource, store or client retarget', async () => {
  const f = fixture(); await f.seed(); const before = f.events.length;
  for (const key of [{ ...f.key, profile: 'alias' }, { ...f.key, resource: f.d.resources.mcp }, { ...f.key, storeId: 'other-store' }]) {
    await assert.rejects(f.engine.inspect(key, f.ctx.value), fails('invalid_input', 'binding_mismatch'));
  }
  assert.equal(f.events.length, before);
  const changed = clone(f.read()); changed.binding.clientId = 'other-client'; assert.throws(() => decodeDelegatedFamilySnapshot(changed, f.key), fails('invalid_state'));
});

test('strict family codec roundtrips owned bytes, rejects API-key formats and never evaluates metadata hooks', async () => {
  const f = fixture(); const ready = await f.seed(), bytes = encodeDelegatedFamilySnapshot(ready, f.key);
  assert.deepEqual(decodeDelegatedFamilySnapshotBytes(bytes, f.key), ready); bytes.fill(0); assert.equal(ready.state, 'ready');
  for (const mutate of [v => { v.format = 2; }, v => { v.current.namespace = 'Bota/DeveloperToolchain/api-key/v1'; },
    v => { v.current.localGeneration = 1; }, v => { v.proof = v.current; }, v => { v.binding.grantResourceUris = ['https://evil.example.test']; },
    v => { v.localGeneration = Number.MAX_SAFE_INTEGER; }, v => { v.intent = {}; }, v => { v.extra = canary; }]) {
    const input = clone(ready); mutate(input); assert.throws(() => decodeDelegatedFamilySnapshot(input, f.key), fails('invalid_state'));
  }
  let hooks = 0; const accessor = clone(ready); Object.defineProperty(accessor, 'binding', { enumerable: true, get() { hooks++; throw Error(canary); } });
  assert.throws(() => decodeDelegatedFamilySnapshot(accessor, f.key), fails('invalid_state')); assert.equal(hooks, 0);
  const revoked = Proxy.revocable([], {}); revoked.revoke(); const input = clone(ready); input.cleanup = revoked.proxy;
  assert.throws(() => decodeDelegatedFamilySnapshot(input, f.key), fails('invalid_state'));
});

test('canonical byte codec rejects duplicate keys, BOM, CRLF, whitespace, invalid UTF8 and mutable shared input', async () => {
  const f = fixture(), ready = await f.seed(), good = Buffer.from(encodeDelegatedFamilySnapshot(ready, f.key)), text = good.toString();
  for (const bad of [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), good]), Buffer.from(text.replace(/\n$/, '\r\n')),
    Buffer.from(' ' + text), Buffer.from(text.replace('"format":', '"format":"wrong","format":')), Buffer.from([0xff]), Buffer.alloc(65537)]) {
    assert.throws(() => decodeDelegatedFamilySnapshotBytes(bad, f.key), fails('invalid_state'));
  }
  const shared = new Uint8Array(new SharedArrayBuffer(good.length)); shared.set(good);
  assert.throws(() => decodeDelegatedFamilySnapshotBytes(shared, f.key), fails('invalid_state'));
});
