import assert from 'node:assert/strict';
import test from 'node:test';
import { NativeProfileTransactions, NativeProfileTransactionError, decodeNativeProfileSnapshot } from '../src/native-profile-transaction.ts';

const key = 'rk_NATIVE_PROFILE_CANARY';
const override = 'rk_NATIVE_OVERRIDE_CANARY';
const origin = 'https://api.example.invalid';
const clone = value => structuredClone(value);
const identity = extra => ({ project_id: 'project:opaque', organization_id: 'org:opaque', key_id: 'key:stored',
  key_type: 'restricted', is_test_mode: false, scope_mode: 'restricted', scopes: [], ...extra });
const reference = value => `${value.profile_id}/${value.credential_ref}`;
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

function harness() {
  let sequence = 0, active = false, tail = Promise.resolve();
  const state = new Map(), secrets = new Map(), calls = [];
  const controller = new AbortController();
  const h = { state, secrets, calls, expired: false, publishNumber: 0, writeFault: undefined, deleteFault: undefined,
    publishFaults: {}, loadOverride: undefined, readOverride: undefined, identityOverride: undefined, leaseFault: undefined };
  const context = { signal: controller.signal, budget: { assertActive() { if (h.expired) throw new Error(key); } } };
  h.context = context; h.controller = controller;
  const checked = (method, ctx, extra = {}) => {
    assert.equal(ctx, context); assert.equal(ctx.budget, context.budget); assert.equal(ctx.signal, controller.signal);
    assert.ok(active, 'port must run under the namespace/profile lease');
    context.budget.assertActive(); assert.equal(context.signal.aborted, false);
    calls.push({ method, ...extra });
  };
  const ports = {
    newId: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`,
    lease: { async runExclusive(storeId, name, ctx, work) {
      assert.equal(storeId, 'synthetic'); assert.equal(ctx, context);
      if (h.leaseFault === 'never-enter') return 'forged';
      const prior = tail; const gate = deferred(); tail = gate.promise;
      await prior; assert.equal(active, false); active = true;
      calls.push({ method: 'lease-enter', name });
      try {
        const value = await work();
        if (h.leaseFault === 'double-enter') await work();
        if (h.leaseFault === 'release') throw new Error(key);
        return h.leaseFault === 'forged-result' ? {} : value;
      } finally { active = false; calls.push({ method: 'lease-exit', name }); gate.resolve(); }
    } },
    snapshots: {
      async load(name, ctx) { checked('load', ctx, { name }); return h.loadOverride ?? clone(state.get(name) ?? null); },
      async publish(name, expected, value, ctx) {
        checked('publish', ctx, { name, expected, value });
        assert.ok(Object.isFrozen(value));
        const number = ++h.publishNumber, fault = h.publishFaults[number];
        if (fault === 'not_committed') return 'not_committed';
        if (fault === 'unknown-before') return 'unknown';
        if (fault === 'malformed') return { committed: true };
        assert.equal(state.get(name)?.revision ?? null, expected, 'compare-and-publish revision');
        state.set(name, clone(value));
        if (fault === 'throw-after') throw new Error(key);
        if (fault === 'unknown-after') return 'unknown';
        if (fault === 'expire-after') h.expired = true;
        if (fault === 'abort-after') controller.abort(key);
        return 'committed';
      },
    },
    store: { id: 'synthetic',
      async read(ref, ctx) { checked('store-read', ctx, { ref }); assert.ok(Object.isFrozen(ref));
        if (h.readOverride) return h.readOverride(ref);
        return secrets.has(reference(ref)) ? { status: 'present', key: secrets.get(reference(ref)) } : { status: 'absent' }; },
      async write(ref, value, ctx) {
        checked('store-write', ctx, { ref });
        const snapshot = [...state.values()].find(item => item.journal?.desired.credential_ref === ref.credential_ref);
        assert.equal(snapshot.record, null); assert.equal(snapshot.journal.operation, 'enroll');
        assert.equal(snapshot.journal.phase, 'intent', 'durable intent must precede the first store write');
        if (h.writeFault === 'unknown-empty') return 'unknown';
        if (h.writeFault === 'not_stored') return 'not_stored';
        secrets.set(reference(ref), h.writeFault === 'bad-readback' ? override : value);
        if (h.writeFault === 'unknown-created') return 'unknown';
        if (h.writeFault === 'throw-created') throw new Error(key);
        if (h.writeFault === 'malformed') return { stored: true };
        return 'stored';
      },
      async delete(ref, ctx) {
        checked('store-delete', ctx, { ref });
        const snapshot = [...state.values()].find(item => item.journal?.desired.credential_ref === ref.credential_ref);
        assert.ok(snapshot?.journal, 'delete target must be owned by the exact current journal');
        assert.ok(snapshot.record === null || snapshot.record.state === 'disabled', 'durable disable must precede delete');
        if (h.deleteFault === 'unknown-present') return 'unknown';
        if (h.deleteFault === 'not_deleted') return 'not_deleted';
        if (h.deleteFault === 'malformed') return { deleted: true };
        secrets.delete(reference(ref));
        if (h.deleteFault === 'unknown-deleted') return 'unknown';
        if (h.deleteFault === 'throw-deleted') throw new Error(key);
        return 'deleted';
      },
    },
    async readIdentity(apiOrigin, value, ctx) {
      checked('identity', ctx, { origin: apiOrigin }); assert.equal(apiOrigin, origin);
      if (h.identityOverride) return h.identityOverride(value);
      return identity(value === override ? { key_id: 'key:override' } : undefined);
    },
  };
  h.ports = ports; h.engine = new NativeProfileTransactions(ports);
  h.enroll = (name = 'work') => h.engine.enroll({ name, apiOrigin: origin, key }, context);
  h.select = (options = {}, action = async value => ({ source: value.source, identity: value.identity })) => h.engine.withCredential('work', options, context, action);
  h.count = method => calls.filter(call => call.method === method).length;
  h.reset = () => { calls.length = 0; h.publishNumber = 0; h.publishFaults = {}; };
  return h;
}
function failure(code, pending) {
  return error => {
    assert.ok(error instanceof NativeProfileTransactionError);
    assert.equal(error.code, code);
    if (pending !== undefined) assert.equal(error.recovery_required, pending);
    assert.equal(error.cause, undefined);
    for (const text of [String(error), error.stack, JSON.stringify(error)]) assert.ok(!text.includes(key) && !text.includes(override));
    assert.throws(() => { error.operation_may_have_executed = false; }, TypeError);
    return true;
  };
}

test('native enrollment publishes durable intent before one write/readback/commit and returns immutable safe state', async () => {
  const h = harness(); const record = await h.enroll();
  assert.equal(record.state, 'ready'); assert.equal(record.key_id, 'key:stored');
  assert.ok(Object.isFrozen(record)); assert.throws(() => { record.state = 'removed'; }, TypeError);
  assert.equal(h.count('store-write'), 1); assert.equal(h.count('store-delete'), 0); assert.equal(h.count('identity'), 1);
  assert.equal(h.state.get('work').journal, null);
  assert.ok(h.calls.findIndex(call => call.method === 'publish') < h.calls.findIndex(call => call.method === 'store-write'));
  assert.doesNotMatch(JSON.stringify([...h.state.values()]), /CANARY|apiKey|key_hint|key_hash|scopes/);
  const snapshot = await h.engine.inspect('work', h.context);
  assert.ok(Object.isFrozen(snapshot)); assert.ok(Object.isFrozen(snapshot.record));
});

test('existing or terminal names refuse enrollment without credential identity or store activity', async () => {
  const h = harness(); await h.enroll(); await h.engine.remove('work', h.context); h.reset();
  await assert.rejects(h.enroll(), failure('profile_exists', false));
  assert.equal(h.count('identity') + h.count('store-read') + h.count('store-write'), 0);
});

test('known native reference collision never publishes intent, upserts or claims cleanup ownership', async () => {
  const h = harness();
  const ref = { profile_id: '00000000-0000-4000-8000-000000000001', credential_ref: '00000000-0000-4000-8000-000000000002' };
  h.secrets.set(reference(ref), 'unrelated-synthetic-owner-value');
  await assert.rejects(h.enroll(), failure('profile_store_mismatch', false));
  assert.equal(h.count('publish') + h.count('store-write') + h.count('store-delete'), 0);
  assert.equal(h.secrets.get(reference(ref)), 'unrelated-synthetic-owner-value');
});

for (const fault of ['unknown-before', 'unknown-after', 'not_committed', 'malformed', 'throw-after']) {
  test(`intent publication ${fault} never authorizes a store write`, async () => {
    const h = harness(); h.publishFaults[1] = fault;
    await assert.rejects(h.enroll(), failure(fault === 'not_committed' ? 'profile_busy' : 'profile_state_unknown'));
    assert.equal(h.count('store-write'), 0);
    if (h.state.has('work')) { h.publishFaults = {}; await h.engine.recover('work', h.context); assert.equal(h.state.get('work').record.state, 'removed'); }
  });
}
for (const fault of ['unknown-empty', 'unknown-created', 'throw-created', 'not_stored', 'malformed', 'bad-readback']) {
  test(`interrupted native write ${fault} is never repeated and recovery cleans only its owned reference`, async () => {
    const h = harness(); h.writeFault = fault; h.secrets.set('unrelated/reference', 'retained');
    await assert.rejects(h.enroll(), failure(fault === 'bad-readback' ? 'profile_store_mismatch' : 'profile_write_unknown', true));
    assert.equal(h.count('store-write'), 1);
    const before = clone(h.state.get('work')); assert.equal(before.record, null);
    await assert.rejects(h.select({ environmentKey: override }), failure('profile_pending_recovery', true));
    h.writeFault = undefined; const removed = await h.engine.recover('work', h.context);
    assert.equal(removed.state, 'removed'); assert.equal(h.count('store-write'), 1);
    assert.equal(h.secrets.get('unrelated/reference'), 'retained'); assert.equal(h.secrets.has(reference(removed)), false);
  });
}
for (const stage of [2, 3]) {
  for (const fault of ['unknown-before', 'unknown-after', 'not_committed', 'throw-after']) {
    test(`enrollment publication ${stage}/${fault} recovers committed state without deleting its key`, async () => {
      const h = harness(); h.publishFaults[stage] = fault;
      await assert.rejects(h.enroll(), failure(fault === 'not_committed' ? 'profile_busy' : 'profile_state_unknown', true));
      h.publishFaults = {}; const saved = h.state.get('work');
      const committed = saved.record?.state === 'ready';
      const deletes = h.count('store-delete'); const writes = h.count('store-write');
      const result = await h.engine.recover('work', h.context);
      assert.equal(h.count('store-write'), writes);
      if (committed) { assert.equal(result.state, 'ready'); assert.equal(h.count('store-delete'), deletes); assert.equal(h.secrets.get(reference(result)), key); }
      else assert.equal(result.state, 'removed');
    });
  }
}

test('committed enrollment recovery refuses changed stored credential identity and never deletes', async () => {
  const h = harness(); h.publishFaults[3] = 'not_committed'; await assert.rejects(h.enroll());
  h.publishFaults = {}; h.identityOverride = () => identity({ key_id: 'key:changed' });
  await assert.rejects(h.engine.recover('work', h.context), failure('profile_identity_mismatch', true));
  assert.equal(h.count('store-delete'), 0); assert.equal(h.state.get('work').journal.phase, 'committed');
});

for (const [fault, code] of [['absent', 'profile_store_absent'], ['unavailable', 'profile_store_unavailable'],
  ['malformed', 'profile_store_unavailable'], ['invalid-key', 'profile_key_required'],
  ['identity', 'profile_identity_failed'], ['clear-not-committed', 'profile_busy']]) {
  test(`failed committed-enrollment recovery ${fault} retains its recovery requirement and never writes/deletes`, async () => {
    const h = harness(); h.publishFaults[3] = 'not_committed'; await assert.rejects(h.enroll());
    h.reset(); const saved = clone(h.state.get('work'));
    if (fault === 'absent') h.readOverride = () => ({ status: 'absent' });
    if (fault === 'unavailable') h.readOverride = () => { throw new Error(key); };
    if (fault === 'malformed') h.readOverride = () => ({ status: 'present', key, extra: true });
    if (fault === 'invalid-key') h.readOverride = () => ({ status: 'present', key: '' });
    if (fault === 'identity') h.identityOverride = () => { throw new Error(key); };
    if (fault === 'clear-not-committed') h.publishFaults[1] = 'not_committed';
    await assert.rejects(h.engine.recover('work', h.context), failure(code, true));
    assert.deepEqual(h.state.get('work'), saved);
    assert.equal(h.count('store-write') + h.count('store-delete'), 0);
    await assert.rejects(h.select({ environmentKey: override }), failure('profile_pending_recovery', true));
  });
}

test('healthy ready recovery failures do not invent pending journal state', async () => {
  const h = harness(); await h.enroll(); h.reset();
  h.identityOverride = () => { throw new Error(key); };
  await assert.rejects(h.engine.recover('work', h.context), failure('profile_identity_failed', false));
  assert.equal(h.state.get('work').journal, null);
  assert.equal(h.count('store-write') + h.count('store-delete') + h.count('publish'), 0);
});

for (const fault of ['unknown-before', 'unknown-after', 'not_committed', 'throw-after']) {
  test(`removal disable publication ${fault} cannot dispatch delete`, async () => {
    const h = harness(); await h.enroll(); h.reset(); h.publishFaults[1] = fault;
    await assert.rejects(h.engine.remove('work', h.context)); assert.equal(h.count('store-delete'), 0);
    if (h.state.get('work').record.state === 'disabled') await assert.rejects(h.select({ environmentKey: override }), failure('profile_pending_recovery', true));
  });
}
for (const fault of ['unknown-present', 'unknown-deleted', 'throw-deleted', 'not_deleted', 'malformed']) {
  test(`native deletion ${fault} retains disabled intent and explicit recovery verifies absence`, async () => {
    const h = harness(); await h.enroll(); h.reset(); h.deleteFault = fault;
    await assert.rejects(h.engine.remove('work', h.context), failure('profile_delete_unknown', true));
    assert.equal(h.count('store-delete'), 1); assert.equal(h.state.get('work').record.state, 'disabled');
    await assert.rejects(h.select({ environmentKey: override }), failure('profile_pending_recovery', true));
    h.deleteFault = undefined; const removed = await h.engine.recover('work', h.context);
    assert.equal(removed.state, 'removed'); assert.equal(h.secrets.has(reference(removed)), false);
    const count = h.count('store-delete'); await h.engine.remove('work', h.context); await h.engine.recover('work', h.context);
    assert.equal(h.count('store-delete'), count, 'terminal removal is idempotent');
  });
}

test('delete success followed by unknown terminal publication never replays deletion after absence', async () => {
  for (const fault of ['unknown-before', 'unknown-after']) {
    const h = harness(); await h.enroll(); h.reset(); h.publishFaults[2] = fault;
    await assert.rejects(h.engine.remove('work', h.context), failure('profile_state_unknown', true));
    assert.equal(h.count('store-delete'), 1); h.publishFaults = {};
    await h.engine.recover('work', h.context); assert.equal(h.count('store-delete'), 1);
  }
});

test('positive delete acknowledgment without actual absence remains disabled', async () => {
  const h = harness(); await h.enroll(); h.reset();
  h.ports.store.delete = async () => 'deleted';
  await assert.rejects(h.engine.remove('work', h.context), failure('profile_delete_unknown', true));
  assert.equal(h.state.get('work').record.state, 'disabled');
});

test('ready selection verifies pinned key_id; same-project explicit environment key overrides without store read', async () => {
  const h = harness(); const record = await h.enroll(); h.reset();
  const stored = await h.select(); assert.equal(stored.source, 'store');
  h.reset(); const injected = await h.select({ environmentKey: override });
  assert.equal(injected.identity.key_id, 'key:override'); assert.equal(h.count('store-read'), 0);
  assert.ok(Object.isFrozen(injected.identity.scopes));
  h.secrets.set(reference(record), override); h.reset();
  await assert.rejects(h.select(), failure('profile_identity_mismatch', false));
  assert.equal(h.count('store-write') + h.count('store-delete'), 0);
});

test('missing/invalid explicit environment values and foreign origin/binding refuse without fallback', async () => {
  const h = harness(); await h.enroll(); h.reset();
  for (const value of [undefined, '', null, 'line\nkey', 'x'.repeat(2561)]) {
    await assert.rejects(h.select({ environmentKey: value }), failure('profile_key_required', false));
  }
  await assert.rejects(h.select({ apiOriginOverride: 'https://other.example.invalid', environmentKey: override }), failure('profile_origin_mismatch', false));
  const saved = h.state.get('work').record;
  await assert.rejects(h.select({ expectedBinding: { profile_id: saved.profile_id, api_origin: origin,
    project_id: 'other-project', organization_id: saved.organization_id } }), failure('profile_binding_mismatch', false));
  assert.equal(h.count('store-read') + h.count('identity'), 0);
});

test('absent/unavailable native store and project mismatch never activate fallback', async () => {
  const h = harness(); const record = await h.enroll(); h.reset();
  h.secrets.delete(reference(record)); await assert.rejects(h.select(), failure('profile_store_absent', false));
  h.readOverride = () => ({ status: 'absent', ignored: key }); await assert.rejects(h.select(), failure('profile_store_unavailable', false));
  h.readOverride = undefined; h.identityOverride = () => identity({ project_id: 'foreign' });
  await assert.rejects(h.select({ environmentKey: override }), failure('profile_identity_mismatch', false));
});

test('identity controls/scopes/proxies are bounded and copied without invoking accessors', async () => {
  const h = harness(); let hooks = 0;
  const scopes = []; Object.defineProperty(scopes, 0, { enumerable: true, get() { hooks++; return 'read'; } });
  const proxied = new Proxy([], { get() { hooks++; throw new Error(key); } });
  const sparse = new Array(2);
  for (const value of [identity({ scopes }), identity({ scopes: proxied }), identity({ scopes: sparse }),
    identity({ scopes: Array(257).fill('read') }), identity({ scopes: ['x'.repeat(2049)] }),
    identity({ scopes: Array(100).fill('x'.repeat(1000)) }), identity({ key_id: key }),
    identity({ key_type: 'end_user_token' }), identity({ scopes: [key] })]) {
    h.identityOverride = () => value;
    await assert.rejects(h.enroll(), failure('profile_identity_failed', false));
  }
  assert.equal(hooks, 0); assert.equal(h.count('store-write') + h.count('publish'), 0);
});

test('strict versioned snapshot rejects unknown fields, foreign references and inconsistent journal combinations', async () => {
  const h = harness(); await h.enroll(); const saved = clone(h.state.get('work'));
  const variants = [value => { value.version = 2; }, value => { value.format_version = 2; },
    value => { value.record.store_id = 'other'; }, value => { value.record.state = 'disabled'; },
    value => { value.record.credential_ref = value.record.profile_id; }, value => { value.revision = value.record.profile_id; },
    value => { value.record.secret = key; }, value => { value.record.api_origin = 'https://api.example.invalid/path'; },
    value => { value.record.project_id = ''; }, value => { value.record.project_id = 'x'.repeat(9000); }];
  for (const mutate of variants) {
    const value = clone(saved); mutate(value); h.loadOverride = value;
    await assert.rejects(h.select({ environmentKey: override }), failure('profile_invalid_metadata', false));
  }
  let hooks = 0; h.loadOverride = new Proxy({}, { ownKeys() { hooks++; return []; } });
  await assert.rejects(h.select(), failure('profile_invalid_metadata', false)); assert.equal(hooks, 0);
  const value = clone(saved); Object.defineProperty(value, 'record', { get() { hooks++; return saved.record; }, enumerable: true });
  h.loadOverride = value; await assert.rejects(h.select(), failure('profile_invalid_metadata', false)); assert.equal(hooks, 0);
  assert.doesNotThrow(() => decodeNativeProfileSnapshot(saved, 'work', 'synthetic'));
});

test('selection holds namespace/profile lease through identity and the entire caller action', async () => {
  const h = harness(); await h.enroll(); h.reset(); const entered = deferred(), finish = deferred();
  const action = h.select({}, async (credential, context) => {
    assert.equal(context, h.context); assert.equal(credential.apiKey, key);
    assert.ok(!JSON.stringify(credential).includes(key)); entered.resolve(); await finish.promise; return { status: 'safe-result' };
  });
  await entered.promise; const removal = h.engine.remove('work', h.context);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(h.count('store-delete'), 0);
  finish.resolve(); assert.deepEqual(await action, { status: 'safe-result' }); await removal;
  assert.equal(h.state.get('work').record.state, 'removed');
});

test('distinct profiles are intentionally serialized within the same store namespace', async () => {
  const h = harness(); await h.enroll(); const entered = deferred(), finish = deferred(); h.reset();
  const first = h.select({}, async () => { entered.resolve(); await finish.promise; return true; });
  await entered.promise; const other = h.enroll('second');
  await new Promise(resolve => setImmediate(resolve)); assert.equal(h.count('store-write'), 0);
  finish.resolve(); await first; await other; assert.equal(h.count('store-write'), 1);
});

test('budget/cancellation after durable intent leaves recovery state and never starts a native write', async () => {
  for (const fault of ['expire-after', 'abort-after']) {
    const h = harness(); h.publishFaults[1] = fault;
    await assert.rejects(h.enroll(), failure(fault === 'expire-after' ? 'profile_deadline' : 'profile_cancelled', true));
    assert.equal(h.count('store-write'), 0); assert.equal(h.state.get('work').journal.phase, 'intent');
  }
});

test('late caller action/opaque throw preserve possible execution without conflating local recovery', async () => {
  const h = harness(); await h.enroll();
  await assert.rejects(h.select({}, async () => { throw new Error(key); }), error => {
    failure('profile_operation_failed', false)(error); assert.equal(error.operation_may_have_executed, true); return true;
  });
  await assert.rejects(h.select({}, async () => { h.expired = true; return { safe_business_error: true }; }), error => {
    failure('profile_deadline', false)(error); assert.equal(error.operation_may_have_executed, true); return true;
  });
});

test('lease cannot forge callback absence/results or enter transaction work twice', async () => {
  for (const fault of ['never-enter', 'forged-result', 'double-enter', 'release']) {
    const h = harness(); h.leaseFault = fault;
    await assert.rejects(h.enroll());
    assert.ok(h.count('store-write') <= 1);
    if (fault === 'never-enter') assert.equal(h.count('store-write') + h.count('publish'), 0);
  }
});

test('lease cleanup failure after caller action has an immutable possible-execution marker', async () => {
  const h = harness(); await h.enroll(); h.leaseFault = 'release';
  await assert.rejects(h.select({}, async () => ({ sanitized: true })), error => {
    failure('profile_lease_failed', false)(error); assert.equal(error.operation_may_have_executed, true); return true;
  });
});
