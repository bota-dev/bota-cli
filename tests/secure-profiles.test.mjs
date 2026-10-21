import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createSecureProfileService } from '../src/secure-profiles.ts';
import { readEnvironmentProfile, ProfileError } from '../src/profiles.ts';
import { NativeProfileTransactions, NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const key = 'rk_SECURE_PROVIDER_CANARY';
const override = 'rk_SECURE_OVERRIDE_CANARY';
const origin = 'https://api.example.invalid';
const identity = (keyId = 'key:stored') => ({ project_id: 'project:synthetic', organization_id: 'org:synthetic',
  key_id: keyId, key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false });
const ref = value => `${value.profile_id}/${value.credential_ref}`;
const copy = value => structuredClone(value);
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

function harness(sourceReader) {
  const h = { snapshots: new Map(), keys: new Map(), calls: [], contexts: [], active: false, closed: 0,
    factoryFault: false, closeFault: false, writeUnknown: false, identityFault: false, wrongProject: false,
    wrongOrganization: false, sourceFault: undefined, sourceReads: 0, action: undefined, closeHook: undefined, ids: 0,
    source: { name: 'work', format_version: 1, api_origin: origin, project_id: 'project:synthetic',
      organization_id: 'org:synthetic', credential_source: 'environment', allow_http_loopback: false } };
  let tail = Promise.resolve();
  const service = createSecureProfileService({ async readEnvironmentProfile(name) {
    h.calls.push('source-read'); h.sourceReads++; assert.equal(name, 'work');
    if (h.sourceFault) throw h.sourceFault; return sourceReader ? sourceReader(name) : h.source;
  }, async createRuntime(context) {
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
      }, async runMetadataExclusive(_store, ctx, action) {
        assert.equal(ctx, context);
        const previous = tail, gate = deferred(); tail = gate.promise; await previous;
        assert.equal(h.active, false); h.active = true; ownActive = true; h.calls.push('metadata-enter');
        try { return await action(); }
        finally { h.active = false; ownActive = false; h.calls.push('metadata-close'); gate.resolve(); }
      } },
      snapshots: { async list() { check('list'); return [...h.snapshots].map(([name, snapshot]) => ({ name, snapshot: copy(snapshot) })); },
        async load(name) { check('load'); return copy(h.snapshots.get(name) ?? null); },
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
          ...(h.wrongProject ? { project_id: 'project:wrong' } : {}),
          ...(h.wrongOrganization ? { organization_id: 'org:wrong' } : {}) };
      },
    });
    return { engine, async close() {
      assert.equal(ownActive, false); h.calls.push('runtime-close'); h.closed++;
      await h.closeHook?.(); if (h.closeFault) throw new Error(key);
    } };
  } });
  h.service = service;
  h.enroll = (input = { name: 'work', apiOrigin: origin, key }, options = {}) => service.enroll(input, options);
  h.migrate = (input = { name: 'work', apiOrigin: origin, readKey: async () => key }, options = { env: {} }) => service.migrateEnvironmentProfile(input, options);
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

test('explicit migration reads one immutable v1 snapshot, defers key acquisition and preserves its source', async () => {
  const h = harness(), source = copy(h.source); let inputReads = 0;
  const result = await h.migrate({ name: 'work', apiOrigin: origin, readKey: async context => {
    inputReads++; assert.equal(context, h.contexts[0]); assert.equal(h.active, false);
    assert.deepEqual(h.calls, ['runtime-open', 'source-read', 'lease-enter', 'load', 'lease-close']); return key;
  } });
  assert.equal(result.state, 'ready'); assert.equal(result.key_id, 'key:stored'); assert.equal(h.sourceReads, 1); assert.equal(inputReads, 1);
  assert.deepEqual(h.source, source); assert.equal(h.calls.filter(value => value === 'write').length, 1);
  assert.doesNotMatch(JSON.stringify(h.snapshots.get('work')), /credential_source|expectedEnrollmentBinding|CANARY/);
});

test('migration uses the actual bounded v1 reader and preserves source and unrelated legacy bytes on success, mismatch and unknown write', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'bota-v1-migration-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const filename = path.join(root, `${Buffer.from('work').toString('hex')}.json`);
  const legacyPath = path.join(root, 'legacy-config.json'), legacy = Buffer.from('{"apiKey":"NEVER_IMPORT_LEGACY","canary":"preserve"}\n');
  const source = Buffer.from(`${JSON.stringify(harness().source, null, 2)}\n`);
  await writeFile(filename, source, { flag: 'wx', mode: 0o600 }); await writeFile(legacyPath, legacy, { flag: 'wx', mode: 0o600 });
  for (const condition of ['success', 'wrongProject', 'writeUnknown']) {
    const h = harness(name => readEnvironmentProfile(name, root));
    if (condition !== 'success') h[condition] = true;
    if (condition === 'success') assert.equal((await h.migrate()).state, 'ready');
    else await assert.rejects(h.migrate(), refused(condition === 'wrongProject' ? 'profile_identity_mismatch' : 'profile_write_unknown'));
    assert.deepEqual(await readFile(filename), source); assert.deepEqual(await readFile(legacyPath), legacy); assert.equal(h.sourceReads, 1);
  }
});

test('migration preserves a source changed after capture without reading it a second time', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'bota-v1-snapshot-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const filename = path.join(root, `${Buffer.from('work').toString('hex')}.json`), profile = harness().source;
  await writeFile(filename, `${JSON.stringify(profile)}\n`, { flag: 'wx', mode: 0o600 });
  const changed = Buffer.from(`${JSON.stringify({ ...profile, project_id: 'later-source-project' })}\n`);
  const h = harness(name => readEnvironmentProfile(name, root));
  const result = await h.migrate({ name: 'work', apiOrigin: origin, readKey: async () => { await writeFile(filename, changed); return key; } });
  assert.equal(result.project_id, profile.project_id); assert.equal(h.sourceReads, 1); assert.deepEqual(await readFile(filename), changed);
});

test('migration does not retarget a captured v1 snapshot changed or removed during deferred input', async () => {
  const h = harness();
  const ready = await h.migrate({ name: 'work', apiOrigin: origin, readKey: async () => {
    h.source.api_origin = 'https://other.example.invalid'; h.source.project_id = 'project:wrong'; h.source = undefined; return key;
  } });
  assert.equal(ready.api_origin, origin); assert.equal(ready.project_id, 'project:synthetic'); assert.equal(h.sourceReads, 1);
});

test('migration identity must match both captured source IDs before generated references, intent or native access', async () => {
  for (const condition of ['wrongProject', 'wrongOrganization']) {
    const h = harness(), source = copy(h.source); h[condition] = true;
    await assert.rejects(h.migrate(), refused('profile_identity_mismatch', { recovery_required: false }));
    assert.equal(h.ids, 0); assert.equal(h.keys.size + h.snapshots.size, 0);
    assert.equal(h.calls.includes('read') || h.calls.includes('write') || h.calls.includes('publish'), false);
    assert.deepEqual(h.source, source); assert.equal(h.sourceReads, 1);
  }
});

test('migration source errors, foreign versions and hostile metadata refuse before key input without legacy fallback', async () => {
  let hooks = 0;
  const accessor = { name: 'work', format_version: 1, api_origin: origin, organization_id: 'org:synthetic', credential_source: 'environment', allow_http_loopback: false };
  Object.defineProperty(accessor, 'project_id', { enumerable: true, get() { hooks++; return 'project:synthetic'; } });
  const proxy = new Proxy({}, { ownKeys() { hooks++; throw new Error(key); } });
  for (const changed of [undefined, {}, { format_version: 2 }, { name: 'foreign' }, { credential_source: 'legacy' },
    { extra: 'RAW_DETAIL' }, { project_id: '' }, { api_origin: `${origin}/path` }, accessor, proxy]) {
    const h = harness(); let reads = 0;
    h.source = changed === accessor || changed === proxy || changed === undefined || Object.keys(changed).length === 0 ? changed : { ...h.source, ...changed };
    await assert.rejects(h.migrate({ name: 'work', apiOrigin: origin, readKey: async () => { reads++; return key; } }), refused('profile_invalid_metadata'));
    assert.equal(reads, 0); assert.equal(h.sourceReads, 1); assert.equal(h.keys.size + h.snapshots.size, 0);
  }
  const unavailable = harness(); unavailable.sourceFault = new Error(`${key} RAW_DETAIL`);
  await assert.rejects(unavailable.migrate(), refused('profile_invalid_metadata'));
  const missing = harness(); missing.sourceFault = new ProfileError('profile_not_found');
  await assert.rejects(missing.migrate(), refused('profile_not_found'));
  assert.equal(hooks, 0);
});

test('migration cancellation, deadlines and hostile input failures join cleanup without leaking raw source or reader errors', async () => {
  for (const condition of ['cancelled', 'deadline']) {
    const parent = parentContext(), h = harness(async () => {
      if (condition === 'cancelled') parent.controller.abort(key); else parent.expire(); return h.source;
    });
    await assert.rejects(h.migrate(undefined, { context: parent.context, env: {} }), refused(`profile_${condition}`));
    assert.equal(h.calls.includes('identity') || h.calls.includes('publish'), false); assert.equal(h.closed, 1);
  }
  let hooks = 0;
  const proxy = new Proxy({}, { getPrototypeOf() { hooks++; throw Error(key); } });
  for (const stage of ['source', 'input']) {
    const h = harness();
    if (stage === 'source') h.sourceFault = proxy;
    await assert.rejects(h.migrate({ name: 'work', apiOrigin: origin, readKey: async () => { throw proxy; } }),
      refused(stage === 'source' ? 'profile_invalid_metadata' : 'profile_key_required'));
  }
  assert.equal(hooks, 0);
});

test('migration requires exact explicit source origin and every supplied origin before input or credential operations', async () => {
  const sourceMismatch = harness(); sourceMismatch.source.api_origin = 'https://source.example.invalid';
  await assert.rejects(sourceMismatch.migrate(), refused('profile_origin_mismatch'));
  assert.equal(sourceMismatch.calls.includes('identity') || sourceMismatch.calls.includes('read'), false);
  for (const options of [{ env: { BOTA_API_URL: 'https://other.example.invalid' } }, { apiUrlOverride: 'https://other.example.invalid', env: {} }]) {
    const h = harness(); await assert.rejects(h.migrate(undefined, options), refused('profile_origin_mismatch'));
    assert.equal(h.calls.length, 0); assert.equal(h.sourceReads, 0);
  }
  const changed = harness(), env = { BOTA_API_URL: origin };
  await assert.rejects(changed.migrate({ name: 'work', apiOrigin: origin, readKey: async () => {
    env.BOTA_API_URL = 'https://other.example.invalid'; return key;
  } }, { env }), refused('profile_origin_mismatch'));
  assert.equal(changed.calls.includes('identity') || changed.calls.includes('publish'), false);
});

test('migration preserves source after an unknown write and refuses occupied or concurrently reserved targets', async () => {
  const unknown = harness(), source = copy(unknown.source); unknown.writeUnknown = true;
  await assert.rejects(unknown.migrate(), refused('profile_write_unknown', { recovery_required: true }));
  assert.deepEqual(unknown.source, source); assert.equal(unknown.snapshots.get('work').journal.phase, 'intent');
  assert.equal(unknown.calls.filter(value => value === 'write').length, 1);
  const existing = harness(); await existing.enroll(); await existing.service.remove('work'); existing.reset();
  let reads = 0;
  await assert.rejects(existing.migrate({ name: 'work', apiOrigin: origin, readKey: async () => { reads++; return key; } }), refused('profile_exists'));
  assert.equal(reads, 0); assert.equal(existing.calls.includes('identity'), false);
  const raced = harness();
  await assert.rejects(raced.migrate({ name: 'work', apiOrigin: origin, readKey: async () => {
    await raced.enroll(); return key;
  } }), refused('profile_exists'));
  assert.equal(raced.calls.filter(value => value === 'write').length, 1);
});

test('migration validates explicit input and bounded key without importing key values or paths from source metadata', async () => {
  for (const input of [{ name: 'work', apiOrigin: origin, key }, { name: 'work', apiOrigin: origin },
    { name: 'work', apiOrigin: origin, readKey: async () => key, directory: 'RAW_DETAIL' },
    { name: 'work', apiOrigin: undefined, readKey: async () => key }]) {
    const h = harness(); await assert.rejects(h.migrate(input), refused('profile_invalid_input')); assert.equal(h.calls.length, 0);
  }
  for (const result of ['', undefined, 'x'.repeat(2561), 'line\nbreak']) {
    const h = harness(); await assert.rejects(h.migrate({ name: 'work', apiOrigin: origin, readKey: async () => result }), refused('profile_key_required'));
    assert.equal(h.calls.includes('identity') || h.calls.includes('read') || h.calls.includes('publish'), false);
  }
});

test('metadata list has no name, credential/environment selection, source read or identity and joins runtime close', async () => {
  const h = harness(); await h.enroll(); await h.service.remove('work'); h.reset();
  let reads = 0; const env = {};
  Object.defineProperty(env, 'BOTA_API_KEY', { enumerable: true, get() { reads++; throw Error(key); } });
  const rows = await h.service.list({ env });
  assert.equal(rows[0].snapshot.record.state, 'removed'); assert.equal(reads, 0);
  assert.deepEqual(h.calls, ['runtime-open', 'metadata-enter', 'list', 'metadata-close', 'runtime-close']);
  h.closeFault = true;
  await assert.rejects(h.service.list({ env: {} }), refused('profile_lease_failed', { recovery_required: false, operation_may_have_executed: false }));
});

test('the nameless list lifecycle never permits a missing name on existing named methods', async () => {
  const h = harness();
  for (const operation of [() => h.service.run(undefined, { env: {} }, async () => 'never'),
    () => h.service.inspect(undefined), () => h.service.remove(undefined), () => h.service.recover(undefined)]) {
    await assert.rejects(operation(), refused('profile_invalid_input'));
  }
  assert.equal(h.calls.length, 0);
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
