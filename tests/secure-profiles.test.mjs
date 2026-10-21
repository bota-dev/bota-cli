import assert from 'node:assert/strict';
import test from 'node:test';
import { createSecureProfileService } from '../src/secure-profiles.ts';
import { NativeProfileTransactions, NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const key = 'rk_SECURE_PROVIDER_CANARY';
const override = 'rk_SECURE_OVERRIDE_CANARY';
const origin = 'https://api.example.invalid';
const identity = (keyId = 'key:stored') => ({ project_id: 'project:synthetic', organization_id: 'org:synthetic',
  key_id: keyId, key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false });
const ref = value => `${value.profile_id}/${value.credential_ref}`;
const copy = value => structuredClone(value);
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

function harness() {
  const h = { snapshots: new Map(), keys: new Map(), calls: [], contexts: [], active: false, closed: 0,
    factoryFault: false, closeFault: false, writeUnknown: false, identityFault: false, wrongProject: false,
    action: undefined, closeHook: undefined, ids: 0 };
  let tail = Promise.resolve();
  const service = createSecureProfileService({ async createRuntime(context) {
    h.calls.push('runtime-open'); h.contexts.push(context);
    if (h.factoryFault) throw new Error(key);
    let ownActive = false;
    const check = method => { assert.equal(context.signal.aborted, false); context.budget.assertActive();
      assert.equal(h.active, true); h.calls.push(method); };
    const engine = new NativeProfileTransactions({
      newId: () => `00000000-0000-4000-8000-${String(++h.ids).padStart(12, '0')}`,
      lease: { async runExclusive(_store, _name, ctx, action) {
        assert.equal(ctx, context);
        const previous = tail, gate = deferred(); tail = gate.promise;
        await previous;
        assert.equal(h.active, false); h.active = true; ownActive = true; h.calls.push('lease-enter');
        try { return await action(); }
        finally { h.active = false; ownActive = false; h.calls.push('lease-close'); gate.resolve(); }
      } },
      snapshots: { async load(name) { check('load'); return copy(h.snapshots.get(name) ?? null); },
        async publish(name, previous, snapshot) {
          check('publish'); assert.equal(h.snapshots.get(name)?.revision ?? null, previous);
          h.snapshots.set(name, copy(snapshot)); return 'committed';
        } },
      store: { id: 'synthetic', async read(reference) { check('read'); return h.keys.has(ref(reference))
        ? { status: 'present', key: h.keys.get(ref(reference)) } : { status: 'absent' }; },
        async write(reference, secret) { check('write'); h.keys.set(ref(reference), secret); return h.writeUnknown ? 'unknown' : 'stored'; },
        async delete(reference) { check('delete'); h.keys.delete(ref(reference)); return 'deleted'; } },
      async readIdentity(apiOrigin, secret) {
        check('identity'); assert.equal(apiOrigin, origin);
        if (h.identityFault) throw new Error(key);
        return { ...identity(secret === override ? 'key:override' : undefined),
          ...(h.wrongProject ? { project_id: 'project:wrong' } : {}) };
      },
    });
    return { engine, async close() {
      assert.equal(ownActive, false); h.calls.push('runtime-close'); h.closed++;
      await h.closeHook?.(); if (h.closeFault) throw new Error(key);
    } };
  } });
  h.service = service;
  h.enroll = (input = { name: 'work', apiOrigin: origin, key }, options = {}) => service.enroll(input, options);
  h.run = (options = {}, action = async credential => ({ source: credential.source, identity: credential.identity })) => service.run('work', { env: {}, ...options }, action);
  h.reset = () => { h.calls.length = 0; h.contexts.length = 0; };
  return h;
}
function refused(code, flags = {}) {
  return error => {
    assert.ok(error instanceof NativeProfileTransactionError); assert.equal(error.code, code);
    for (const [name, value] of Object.entries(flags)) assert.equal(error[name], value);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(String(error) + error.stack + JSON.stringify(error), /PROVIDER_CANARY|OVERRIDE_CANARY|RAW_DETAIL/);
    return true;
  };
}
function parentContext() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, context: { signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error(key); } } } };
}

test('shared service enrolls and inspects only nonsecret native metadata, then removes a terminal reservation', async () => {
  const h = harness(); const ready = await h.enroll();
  assert.equal(ready.state, 'ready'); assert.equal(h.closed, 1);
  const snapshot = await h.service.inspect('work');
  assert.equal(snapshot.journal, null); assert.equal(snapshot.record.profile_id, ready.profile_id);
  assert.doesNotMatch(JSON.stringify(snapshot), /CANARY|apiKey|key_hash|key_hint|scopes/);
  const removed = await h.service.remove('work'); assert.equal(removed.state, 'removed');
  assert.equal(h.keys.size, 0);
  assert.equal((await h.service.recover('work')).state, 'removed');
  await assert.rejects(h.enroll(), refused('profile_exists'));
});

test('deferred secret input starts after runtime qualification and name absence, then enrollment rechecks under a fresh lease', async () => {
  const h = harness(); let reads = 0;
  await h.enroll({ name: 'work', apiOrigin: origin, async readKey(context) {
    reads++; assert.equal(h.active, false); assert.equal(context, h.contexts[0]);
    assert.deepEqual(h.calls, ['runtime-open', 'lease-enter', 'load', 'lease-close']); return key;
  } });
  assert.equal(reads, 1); assert.equal(h.calls.filter(v => v === 'load').length, 2);
  h.reset();
  await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, readKey: async () => { reads++; return key; } }), refused('profile_exists'));
  assert.equal(reads, 1);
  const unsupported = harness(); unsupported.factoryFault = true;
  await assert.rejects(unsupported.enroll({ name: 'work', apiOrigin: origin, readKey: async () => { reads++; return key; } }), refused('profile_store_unavailable'));
  assert.equal(reads, 1); assert.equal(unsupported.closed, 0);
});

test('invalid enrollment fields/origin are refused before opening storage or requesting secret input', async () => {
  const h = harness(); let reads = 0; const readKey = async () => { reads++; return key; };
  for (const input of [{ name: '../work', apiOrigin: origin, readKey }, { name: 'work', apiOrigin: `${origin}/wrong`, readKey },
    { name: 'work', apiOrigin: origin, key, readKey }, { name: 'work', apiOrigin: origin },
    { name: 'work', apiOrigin: origin, allowHttpLoopback: 'yes', readKey },
    { name: 'work', apiOrigin: origin, key, rootDirectory: 'RAW_DETAIL' }]) {
    await assert.rejects(h.enroll(input), refused('profile_invalid_input'));
  }
  assert.equal(reads, 0); assert.equal(h.calls.length, 0);
});

test('enrollment refuses conflicting or malformed supplied origins before storage bootstrap and secret input', async () => {
  const other = 'https://other.example.invalid';
  for (const options of [{ env: { BOTA_API_URL: other } }, { apiUrlOverride: other, env: {} },
    { apiUrlOverride: origin, env: { BOTA_API_URL: other } },
    { apiUrlOverride: other, env: { BOTA_API_URL: origin } },
    { apiUrlOverride: other, env: { BOTA_API_URL: other } },
    { env: { BOTA_API_URL: '' } }, { env: { BOTA_API_URL: undefined } },
    { env: { BOTA_API_URL: `${origin}/wrong` } }]) {
    const h = harness(); let reads = 0;
    await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, async readKey() { reads++; return key; } }, options),
      refused('profile_origin_mismatch', { recovery_required: false, operation_may_have_executed: false }));
    assert.equal(reads, 0); assert.equal(h.calls.length, 0); assert.equal(h.keys.size, 0); assert.equal(h.snapshots.size, 0);
  }
  let getterCalls = 0; const env = {};
  Object.defineProperty(env, 'BOTA_API_URL', { get() { getterCalls++; return origin; } });
  const h = harness(); await assert.rejects(h.enroll(undefined, { env }), refused('profile_origin_mismatch'));
  assert.equal(getterCalls, 0); assert.equal(h.calls.length, 0);
});

test('enrollment admits matching canonical origins and ignores inherited environment selections', async () => {
  for (const options of [{ env: { BOTA_API_URL: `${origin}/` } }, { apiUrlOverride: `${origin}/`, env: {} },
    { apiUrlOverride: `${origin}/`, env: { BOTA_API_URL: origin } },
    { apiUrlOverride: origin, env: Object.create({ BOTA_API_URL: 'https://other.example.invalid' }) }]) {
    const h = harness(); let reads = 0;
    const record = await h.enroll({ name: 'work', apiOrigin: origin, async readKey() { reads++; return key; } }, options);
    assert.equal(record.api_origin, origin); assert.equal(record.state, 'ready'); assert.equal(reads, 1);
    assert.equal(h.calls.filter(value => value === 'write').length, 1);
  }
});

test('an origin changed during deferred input is refused before identity verification or credential mutation', async () => {
  const h = harness(), env = { BOTA_API_URL: origin };
  await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, async readKey() {
    env.BOTA_API_URL = 'https://other.example.invalid'; return key;
  } }, { env }), refused('profile_origin_mismatch'));
  assert.equal(h.calls.includes('identity'), false); assert.equal(h.calls.includes('write'), false);
  assert.equal(h.calls.includes('publish'), false); assert.equal(h.closed, 1);
});

test('secret input failure and invalid capacity never acquire native-secret ownership or call identity', async () => {
  for (const readKey of [async () => { throw new Error(key); }, async () => '', async () => 'x'.repeat(2561), async () => 'x\ny']) {
    const h = harness(); await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, readKey }), refused('profile_key_required'));
    assert.equal(h.keys.size, 0); assert.equal(h.closed, 1); assert.equal(h.calls.includes('identity'), false);
  }
});

test('deferred input preserves only genuine fixed cancellation/deadline errors and never reflects reader details', async () => {
  for (const code of ['profile_cancelled', 'profile_deadline']) {
    const h = harness(); const error = new NativeProfileTransactionError(code, true, true); error.message = key;
    await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, async readKey() { throw error; } }),
      refused(code, { recovery_required: true, operation_may_have_executed: true }));
    assert.equal(h.calls.includes('identity'), false); assert.equal(h.calls.includes('write'), false); assert.equal(h.closed, 1);
  }
  for (const error of [{ code: 'profile_cancelled', message: key }, new NativeProfileTransactionError('profile_operation_failed', true, true)]) {
    const h = harness(); await assert.rejects(h.enroll({ name: 'work', apiOrigin: origin, async readKey() { throw error; } }),
      refused('profile_key_required', { recovery_required: false, operation_may_have_executed: false }));
    assert.equal(h.calls.includes('identity'), false);
  }
});

test('per-invocation store read and current identity are held through the entire action and runtime close is joined', async () => {
  const h = harness(); await h.enroll(); h.reset(); const gate = deferred(), entered = deferred(); let settled = false;
  const running = h.run({}, async (credential, context) => {
    assert.equal(h.active, true); assert.equal(credential.apiKey, key);
    assert.equal(context, h.contexts[0]); assert.equal(Object.keys(credential).includes('apiKey'), false);
    entered.resolve(); await gate.promise; assert.equal(h.active, true); return 'safe-result';
  }).then(value => { settled = true; return value; });
  await entered.promise; assert.equal(settled, false); assert.equal(h.calls.includes('runtime-close'), false);
  gate.resolve(); assert.equal(await running, 'safe-result');
  assert.deepEqual(h.calls.slice(-2), ['lease-close', 'runtime-close']);
  h.reset(); await h.run(); assert.equal(h.calls.filter(v => v === 'read').length, 1);
  assert.equal(h.calls.filter(v => v === 'identity').length, 1);
});

test('same selected credential namespace serializes concurrent CLI/MCP actions through settlement', async () => {
  const h = harness(); await h.enroll(); h.reset(); const gate = deferred(), entered = deferred();
  const first = h.run({}, async () => { entered.resolve(); await gate.promise; return 'cli'; });
  await entered.promise; let secondEntered = false;
  const second = h.run({}, async () => { secondEntered = true; return 'mcp'; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(secondEntered, false);
  gate.resolve(); assert.deepEqual(await Promise.all([first, second]), ['cli', 'mcp']);
});

test('exact own environment presence overrides store credentials without changing identity binding', async () => {
  const h = harness(); await h.enroll(); h.reset();
  assert.equal((await h.run({ env: { BOTA_API_KEY: override } })).source, 'environment');
  assert.equal(h.calls.includes('read'), false);
  assert.equal((await h.run({ env: Object.create({ BOTA_API_KEY: override }) })).source, 'store');
  for (const value of [undefined, '', null, false, 'has whitespace', 'x'.repeat(2561)]) {
    h.reset(); await assert.rejects(h.run({ env: { BOTA_API_KEY: value } }), refused('profile_key_required'));
    assert.equal(h.calls.includes('read'), false); assert.equal(h.calls.includes('identity'), false);
  }
});

test('both explicit and environment API origins must match metadata before native credential access', async () => {
  const h = harness(); await h.enroll(); h.reset();
  await assert.rejects(h.run({ apiUrlOverride: 'https://other.example.invalid', env: { BOTA_API_KEY: '' } }), refused('profile_origin_mismatch'));
  assert.equal(h.calls.includes('read'), false); assert.equal(h.calls.includes('identity'), false);
  for (const options of [{ env: { BOTA_API_URL: 'https://other.example.invalid' } },
    { apiUrlOverride: origin, env: { BOTA_API_URL: 'https://other.example.invalid' } },
    { apiUrlOverride: 'https://other.example.invalid', env: { BOTA_API_URL: origin } },
    { env: { BOTA_API_URL: '' } }, { env: { BOTA_API_URL: undefined } }]) {
    h.reset(); await assert.rejects(h.run(options), refused('profile_origin_mismatch'));
    assert.equal(h.calls.includes('read'), false); assert.equal(h.calls.includes('identity'), false);
  }
  assert.equal((await h.run({ apiUrlOverride: `${origin}/`, env: { BOTA_API_URL: origin } })).source, 'store');
});

test('a nonsecret MCP startup binding is checked anew before any per-request credential or identity read', async () => {
  const h = harness(); const ready = await h.enroll();
  const binding = { profile_id: ready.profile_id, api_origin: ready.api_origin,
    project_id: ready.project_id, organization_id: ready.organization_id };
  await h.run({ expectedBinding: binding }); h.reset();
  await assert.rejects(h.run({ expectedBinding: { ...binding, profile_id: '00000000-0000-4000-8000-999999999999' } }),
    refused('profile_binding_mismatch'));
  assert.equal(h.calls.includes('read'), false); assert.equal(h.calls.includes('identity'), false);
});

test('pending enrollment blocks environment override and explicit recovery cleans only its owned reference', async () => {
  const h = harness(); h.writeUnknown = true;
  await assert.rejects(h.enroll(), refused('profile_write_unknown', { recovery_required: true }));
  assert.equal(h.keys.size, 1); h.reset();
  await assert.rejects(h.run({ env: { BOTA_API_KEY: override } }), refused('profile_pending_recovery', { recovery_required: true }));
  assert.equal(h.calls.includes('identity'), false); assert.equal(h.calls.includes('read'), false);
  assert.equal((await h.service.recover('work')).state, 'removed'); assert.equal(h.keys.size, 0);
});

test('invalid selected identity never invokes an action or falls back to another key/account', async () => {
  const h = harness(); await h.enroll(); h.reset(); let actions = 0; h.wrongProject = true;
  await assert.rejects(h.run({ env: { BOTA_API_KEY: override } }, async () => { actions++; }), refused('profile_identity_mismatch'));
  assert.equal(actions, 0); assert.equal(h.calls.includes('read'), false);
  h.wrongProject = false; h.identityFault = true;
  await assert.rejects(h.run({}, async () => { actions++; }), refused('profile_identity_failed'));
  assert.equal(actions, 0);
});

test('opaque action failures carry fixed uncertainty and never reflect bearer/error payloads', async () => {
  const h = harness(); await h.enroll();
  await assert.rejects(h.run({}, async () => { throw new Error(`${key} RAW_DETAIL`); }),
    refused('profile_operation_failed', { operation_may_have_executed: true, recovery_required: false }));
  assert.equal(h.active, false);
});

test('runtime closure is joined even after action rejection and closure uncertainty retains action/recovery flags', async () => {
  const h = harness(); await h.enroll(); h.closeFault = true;
  await assert.rejects(h.run({}, async () => 'safe'), refused('profile_lease_failed', { operation_may_have_executed: true }));
  const brokenEnrollment = harness(); brokenEnrollment.writeUnknown = true; brokenEnrollment.closeFault = true;
  await assert.rejects(brokenEnrollment.enroll(), refused('profile_lease_failed', { recovery_required: true, operation_may_have_executed: false }));
  const delayed = harness(); await delayed.enroll(); const gate = deferred(), entered = deferred();
  delayed.closeHook = async () => { entered.resolve(); await gate.promise; }; let completed = false;
  const running = delayed.run().then(() => { completed = true; });
  await entered.promise; assert.equal(completed, false); gate.resolve(); await running; assert.equal(completed, true);
});

test('cancellation or budget expiry during joined close cannot return action success', async () => {
  for (const condition of ['cancelled', 'deadline']) {
    const h = harness(); await h.enroll(); const parent = parentContext(), entered = deferred(), gate = deferred();
    h.closeHook = async () => { entered.resolve(); await gate.promise; };
    const running = h.run({ context: parent.context }, async () => 'safe-result');
    await entered.promise;
    if (condition === 'cancelled') parent.controller.abort(key); else parent.expire();
    gate.resolve();
    await assert.rejects(running, refused(`profile_${condition}`, { operation_may_have_executed: true, recovery_required: false }));
    assert.equal(h.calls.at(-1), 'runtime-close');
  }
});

test('a synchronous close that outlasts the monotonic budget is refused before returning success', async () => {
  const h = harness(); await h.enroll(); let deadline = Infinity;
  const context = { signal: new AbortController().signal,
    budget: { assertActive() { if (performance.now() >= deadline) throw new Error(key); } } };
  h.closeHook = () => { deadline = performance.now() + 3; while (performance.now() < deadline + 2) {} };
  await assert.rejects(h.run({ context }, async () => 'safe-result'),
    refused('profile_deadline', { operation_may_have_executed: true }));
});

test('late close cancellation preserves completed mutation uncertainty and prior write/close failures', async () => {
  const committed = harness(), committedParent = parentContext();
  committed.closeHook = () => committedParent.controller.abort(key);
  await assert.rejects(committed.enroll(undefined, { context: committedParent.context }),
    refused('profile_cancelled', { recovery_required: true, operation_may_have_executed: false }));
  assert.equal(committed.snapshots.get('work').record.state, 'ready');
  const pending = harness(), pendingParent = parentContext(); pending.writeUnknown = true;
  pending.closeHook = () => pendingParent.controller.abort(key);
  await assert.rejects(pending.enroll(undefined, { context: pendingParent.context }),
    refused('profile_write_unknown', { recovery_required: true }));
  const ambiguous = harness(), ambiguousParent = parentContext(); await ambiguous.enroll(); ambiguous.closeFault = true;
  ambiguous.closeHook = () => ambiguousParent.controller.abort(key);
  await assert.rejects(ambiguous.run({ context: ambiguousParent.context }),
    refused('profile_lease_failed', { operation_may_have_executed: true }));
});

test('parent context is preserved exactly and cancelled/expired operations do not bootstrap native storage', async () => {
  for (const condition of ['cancelled', 'deadline']) {
    const h = harness(), parent = parentContext();
    if (condition === 'cancelled') parent.controller.abort(key); else parent.expire();
    await assert.rejects(h.service.inspect('work', { context: parent.context }), refused(`profile_${condition}`));
    assert.equal(h.calls.length, 0);
  }
  const h = harness(), parent = parentContext();
  await h.enroll(undefined, { context: parent.context }); assert.equal(h.contexts[0], parent.context);
});

test('opaque context failures are converted to fixed diagnostics before storage bootstrap', async () => {
  const h = harness(); const context = { get signal() { throw new Error(key); }, budget: { assertActive() {} } };
  await assert.rejects(h.service.inspect('work', { context }), refused('profile_invalid_input'));
  assert.equal(h.calls.length, 0);
});

test('parent abort and deadline after a started action preserve possible remote execution and join cleanup', async () => {
  for (const condition of ['cancelled', 'deadline']) {
    const h = harness(); await h.enroll(); const parent = parentContext();
    await assert.rejects(h.run({ context: parent.context }, async (_credential, context) => {
      assert.equal(context, parent.context);
      if (condition === 'cancelled') parent.controller.abort(key); else parent.expire();
      return 'safe';
    }), refused(`profile_${condition}`, { operation_may_have_executed: true }));
    assert.equal(h.calls.at(-1), 'runtime-close');
  }
});

test('owned lifecycle relays caller cancellation and waits for the action to settle before releasing ownership', async () => {
  const h = harness(); await h.enroll(); const parent = new AbortController(), entered = deferred(), gate = deferred();
  let finished = false, signal;
  const running = h.run({ signal: parent.signal }, async (_credential, context) => {
    signal = context.signal; entered.resolve(); await gate.promise; return 'safe';
  }).finally(() => { finished = true; });
  await entered.promise; parent.abort(key); assert.equal(signal.aborted, true);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(h.active, true); assert.equal(finished, false);
  gate.resolve(); await assert.rejects(running, refused('profile_cancelled', { operation_may_have_executed: true }));
});

test('owned finite deadline refuses late success while preserving remote uncertainty', async () => {
  const h = harness(); await h.enroll();
  await assert.rejects(h.run({ timeoutMs: 5 }, async () => { await new Promise(resolve => setTimeout(resolve, 15)); return 'safe'; }),
    refused('profile_deadline', { operation_may_have_executed: true }));
});

test('invalid options, environment accessors/proxies and untrusted enrollment accessors cannot execute code', async () => {
  const h = harness(); let reads = 0;
  const getter = {}; Object.defineProperty(getter, 'BOTA_API_KEY', { enumerable: true, get() { reads++; return key; } });
  for (const options of [{ rootDirectory: 'RAW_DETAIL' }, { timeoutMs: 0 }, { timeoutMs: 300001 }, { timeoutMs: Infinity },
    { context: parentContext().context, timeoutMs: 30 }, { signal: {} }, { apiUrlOverride: undefined }]) {
    await assert.rejects(h.run(options), refused('profile_invalid_input'));
  }
  assert.equal(h.calls.length, 0); await h.enroll();
  await assert.rejects(h.run({ env: getter }), refused('profile_key_required'));
  await assert.rejects(h.run({ env: new Proxy({}, { get() { reads++; throw new Error(key); } }) }), refused('profile_invalid_input'));
  const input = { name: 'work2', apiOrigin: origin };
  Object.defineProperty(input, 'readKey', { enumerable: true, get() { reads++; return async () => key; } });
  await assert.rejects(h.enroll(input), refused('profile_invalid_input'));
  assert.equal(reads, 0);
});
