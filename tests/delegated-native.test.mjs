import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { parseDelegatedLoginDeployment } from '../src/delegated-login.ts';
import { DelegatedFamilyEngine, createTrustedDelegatedEnrollmentHandoff, createTrustedDelegatedRevocationHandoff } from '../src/delegated-family-engine.ts';
import { delegatedNativeSecretReference, delegatedNativeSecret, delegatedNativeCredentialNames, encodeDelegatedNativeProof, decodeDelegatedNativeProof,
  DELEGATED_NATIVE_STORE_ID, DELEGATED_NATIVE_DATABASE, DELEGATED_NATIVE_JOURNAL } from '../src/delegated-native-contract.ts';
import { decodeDelegatedNativeProfile, decodeDelegatedNativeProfileBytes } from '../src/delegated-native-state.ts';
import { DelegatedNativeSnapshots, delegatedNativeLeaseName } from '../src/delegated-native-snapshots.ts';
import { createDelegatedNativeRuntimeForTrustedPorts, createWindowsDelegatedNativeRuntime } from '../src/delegated-native-runtime.ts';

const supportedNativeSqlite = process.platform === 'win32' && ['v24.19.0', 'v22.23.2'].includes(process.version);
function sqliteTest(name, options, action) {
  return typeof options === 'function' ? test(name, { skip: !supportedNativeSqlite }, options)
    : test(name, { ...options, skip: !supportedNativeSqlite }, action);
}

const deployment = parseDelegatedLoginDeployment({ version: 1, issuer: 'https://auth.fixture.invalid', endpoints: {
  authorization: 'https://auth.fixture.invalid/oauth/authorize', token: 'https://auth.fixture.invalid/oauth/token', revocation: 'https://auth.fixture.invalid/oauth/revoke' },
  resources: { rest: 'https://api.fixture.invalid/v1', mcp: 'https://mcp.fixture.invalid/mcp' },
  client: { clientId: 'fixture-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const recovery = Buffer.alloc(32, 1).toString('base64url'), pkce = Buffer.alloc(32, 2).toString('base64url');
const refresh = 'bota_dr1_' + Buffer.alloc(32, 3).toString('base64url'), access = 'bota_da1_' + Buffer.alloc(32, 4).toString('base64url');
const attemptId = '10000000-0000-4000-8000-000000000001', grantId = '20000000-0000-1000-0000-000000000002', familyId = '30000000-0000-1000-0000-000000000003';
const userId = '40000000-0000-1000-0000-000000000004';
const accessExpiry = Math.floor(Date.now() / 1000) + 200;
const key = Object.freeze({ storeId: DELEGATED_NATIVE_STORE_ID, issuer: deployment.issuer, clientId: deployment.client.clientId, familyId });
const binding = Object.freeze({ attemptId, recoveryVerifier: recovery, pkceVerifier: pkce, issuer: deployment.issuer, clientId: deployment.client.clientId,
  redirectUri: 'http://127.0.0.1:48912/oauth/callback', resource: deployment.resources.rest,
  grantResources: Object.freeze([deployment.resources.rest, deployment.resources.mcp]), scopes: Object.freeze(['devices:read']) });
const initial = Object.freeze({ attemptId, refreshToken: refresh, resource: deployment.resources.rest, grantId, familyId, scopes: Object.freeze(['devices:read']) });
const receipt = Object.freeze({ attemptId, authorizationRequestId: '50000000-0000-1000-0000-000000000005', grantId, familyId });
const DatabaseSync = () => createRequire(import.meta.url)('node:sqlite').DatabaseSync;
function context() { const controller = new AbortController(); let expired = false; return { controller, expire() { expired = true; }, signal: controller.signal,
  budget: Object.freeze({ assertActive() { if (expired) throw Error('PRIVATE_BUDGET'); } }) }; }
const ctx = () => { const { signal, budget } = context(); return { signal, budget }; };
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
const safe = (code, recoveryRequired) => error => { if (code) assert.equal(error.code, code); if (recoveryRequired !== undefined) assert.equal(error.recoveryRequired, recoveryRequired);
  assert.doesNotMatch(error.message + JSON.stringify(error), /PRIVATE_|bota_dr1_|bota_da1_|bota_dep1_|sqlite|fixture\.invalid/i); assert.equal(error.cause, undefined); return true; };
function fixture(t) {
  const parent = path.resolve(tmpdir());
  const root = fs.mkdtempSync(path.join(parent, 'delegated-sqlite-owned-'));
  const secrets = new Map([['Bota/DeveloperToolchain/api-key/v1/owner/unrelated', 'OWNER_UNTOUCHED']]), calls = [], owners = [];
  const h = { root, secrets, calls, writeOutcome: undefined, deleteOutcome: undefined, writeHook: undefined, deleteHook: undefined, closeHook: undefined, afterLease: undefined, afterPublish: undefined };
  h.inspect = work => { const db = new (DatabaseSync())(path.join(root, DELEGATED_NATIVE_DATABASE), { readOnly: true, allowExtension: false }); try { return work(db); } finally { db.close(); } };
  h.record = () => h.inspect(db => { const row = db.prepare("SELECT snapshot FROM delegated_records WHERE kind='profile'").get(); return row ? JSON.parse(Buffer.from(row.snapshot).toString()) : null; });
  h.open = () => {
    let live, liveContext, closed = false;
    const admitted = context => { if (!live || context !== liveContext || closed) throw Error('PRIVATE_TICKET'); return live; };
    const lease = {
      async runExclusive(storeId, name, context, work) { if (live || closed) throw Error('PRIVATE_LEASE'); assert.equal(storeId, 'windows-credential-manager'); live = Object.freeze({ name, storeId, rootDirectory: root }); liveContext = context;
        try { return await work(); } finally { live = undefined; liveContext = undefined; h.afterLease?.(); } },
      async runMetadataExclusive(storeId, context, work) { if (live || closed) throw Error('PRIVATE_LEASE'); live = Object.freeze({ metadataOnly: true, storeId, rootDirectory: root }); liveContext = context;
        try { return await work(); } finally { live = undefined; liveContext = undefined; h.afterLease?.(); } },
      close() { if (live) throw Error('PRIVATE_BUSY'); closed = true; h.closeHook?.(); },
    };
    const guard = { assertCurrentAccess(context) { const value = admitted(context); if (value.metadataOnly) throw Error('PRIVATE_TICKET'); return value; },
      assertCurrentMetadataAccess(context) { const value = admitted(context); if (!value.metadataOnly) throw Error('PRIVATE_TICKET'); return value; },
      openMetadata(binding, context) { if (binding !== admitted(context) || !binding.metadataOnly) throw Error('PRIVATE_TICKET');
        if (!fs.existsSync(path.join(root, DELEGATED_NATIVE_DATABASE)) && !fs.existsSync(path.join(root, DELEGATED_NATIVE_JOURNAL))) return null;
        return this.openFiles(binding, context); },
      open(binding, context) { if (binding !== admitted(context) || binding.metadataOnly) throw Error('PRIVATE_TICKET'); return this.openFiles(binding, context); },
      openFiles(binding, context) {
        const filename = path.join(root, DELEGATED_NATIVE_DATABASE), journal = path.join(root, DELEGATED_NATIVE_JOURNAL);
        const fresh = !fs.existsSync(filename) && !fs.existsSync(journal);
        if (fresh) { fs.writeFileSync(filename, '', { flag: 'wx' }); fs.writeFileSync(journal, '', { flag: 'wx' }); }
        return { fresh, currentSid: 'S-1-5-21-100-200-300-1001', databaseHeader: new Uint8Array(fs.readFileSync(filename).subarray(0, 100)),
          validate() { if (admitted(context) !== binding) throw Error('PRIVATE_TICKET'); }, close() {} };
      } };
    const snapshots = new DelegatedNativeSnapshots(guard), originalPublish = snapshots.publish.bind(snapshots);
    snapshots.publish = async (...args) => { const result = await originalPublish(...args); await h.afterPublish?.(...args, result); return result; };
    const credentials = { assertHealthy() {}, readCredential(ref) { admitted(liveContext); const target = delegatedNativeCredentialNames(ref).target; calls.push(['read', target]);
      const value = secrets.get(target); return value === undefined ? { status: 'absent' } : { status: 'present', secret: delegatedNativeSecret(ref, value) }; },
      writeCredential(ref, value) { admitted(liveContext); const target = delegatedNativeCredentialNames(ref).target; delegatedNativeSecret(ref, value); calls.push(['write', target]);
        h.writeHook?.(ref, value, liveContext); if (secrets.has(target)) return 'not_stored'; if (h.writeOutcome !== 'not_stored') secrets.set(target, value); return h.writeOutcome ?? 'stored'; },
      deleteCredential(ref) { admitted(liveContext); const target = delegatedNativeCredentialNames(ref).target; calls.push(['delete', target]); if (!secrets.has(target)) return 'absent';
        delegatedNativeSecret(ref, secrets.get(target)); const outcome = h.deleteHook?.(ref) ?? h.deleteOutcome; if (outcome !== 'not_deleted') secrets.delete(target); return outcome ?? 'deleted'; } };
    const runtime = createDelegatedNativeRuntimeForTrustedPorts({ lease, snapshots, credentials }); owners.push(runtime); return { runtime, snapshots, lease, guard, credentials };
  };
  t.after(async () => { await Promise.allSettled(owners.map(owner => owner.close())); assert.equal(secrets.get('Bota/DeveloperToolchain/api-key/v1/owner/unrelated'), 'OWNER_UNTOUCHED');
    assert.equal(path.dirname(root), parent); assert.match(path.basename(root), /^delegated-sqlite-owned-/); fs.rmSync(root, { recursive: true, force: true }); });
  return h;
}
async function retained(f) { const { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx()); await runtime.retentionPort('dev').retain(binding, ctx()); return runtime; }
async function received(f) { const runtime = await retained(f); await runtime.retainInitialRefresh('dev')(initial, ctx()); return runtime; }
function engine(runtime, overrides = {}) {
  return new DelegatedFamilyEngine({ ...runtime.familyPorts, nowSeconds: () => Math.floor(Date.now() / 1000),
    async verifyAccess(_deployment, token, resource) { assert.equal(token, access); return { issuer: deployment.issuer, clientId: deployment.client.clientId, userId,
      organizationId: 'org_fixture', projectId: 'project_fixture', grantId, familyId, grantResourceUris: binding.grantResources, grantScopes: binding.scopes,
      resource, accessScopes: binding.scopes, expiresAtSeconds: accessExpiry }; },
    async exchange() { throw Error('PRIVATE_UNEXPECTED_EXCHANGE'); }, async revoke() { throw Error('PRIVATE_UNEXPECTED_REVOKE'); }, ...overrides });
}
function handoff() { return createTrustedDelegatedEnrollmentHandoff(deployment, async () => ({ accessToken: access, refreshToken: refresh, resource: deployment.resources.rest,
  expiresAtSeconds: accessExpiry, grantId, familyId, scopes: binding.scopes })); }

test('closed credential cohort rejects API-key references, malformed proofs and reflective inputs without hooks', () => {
  const ref = { kind: 'attempt-proof', ownerId: attemptId, credentialId: randomUUID() }, proof = encodeDelegatedNativeProof({ recoveryVerifier: recovery, pkceVerifier: pkce });
  assert.equal(proof.length, 97); assert.deepEqual(decodeDelegatedNativeProof(proof), { recoveryVerifier: recovery, pkceVerifier: pkce });
  assert.match(delegatedNativeCredentialNames(ref).target, /^Bota\/DeveloperToolchain\/delegated\/v1\/attempt-proof\//);
  let hooks = 0; const accessor = Object.defineProperty({}, 'kind', { enumerable: true, get() { hooks++; throw Error('PRIVATE_HOOK'); } });
  const proxy = new Proxy({}, { ownKeys() { hooks++; throw Error('PRIVATE_HOOK'); }, getPrototypeOf() { hooks++; throw Error('PRIVATE_HOOK'); } });
  for (const value of [accessor, proxy, { profile_id: attemptId, credential_ref: randomUUID() }, { ...ref, localGeneration: 0 }, { ...ref, kind: 'unknown' }]) assert.throws(() => delegatedNativeSecretReference(value), safe('invalid_input'));
  for (const value of [proof + 'x', refresh, 'bota_dep1_' + recovery + '.' + recovery]) assert.throws(() => decodeDelegatedNativeProof(value), safe('invalid_input'));
  assert.equal(hooks, 0);
});

sqliteTest('reserve and bounded metadata inventory use actual separate SQLite with zero credential access', async t => {
  const f = fixture(t), { runtime } = f.open(); assert.deepEqual(await runtime.list(ctx()), []); assert.deepEqual(fs.readdirSync(f.root), []);
  assert.equal(await runtime.load('dev', ctx()), null); await runtime.reserve('dev', deployment, ctx());
  assert.equal((await runtime.load('dev', ctx())).state, 'reserved'); assert.deepEqual((await runtime.list(ctx())).map(value => value.name), ['dev']);
  assert.equal(f.calls.length, 0); await assert.rejects(runtime.reserve('dev', deployment, ctx()), safe('exists'));
  const names = fs.readdirSync(f.root); assert.deepEqual(names.sort(), [DELEGATED_NATIVE_DATABASE, DELEGATED_NATIVE_JOURNAL].sort());
  assert.equal(f.inspect(db => db.prepare('PRAGMA application_id').get().application_id), 0x42544431);
  assert.equal(f.inspect(db => db.prepare('PRAGMA user_version').get().user_version), 1);
});

sqliteTest('proof and initial refresh commit durable intent before create-only secret write and exact acknowledgement', async t => {
  const f = fixture(t), { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx());
  f.writeHook = reference => assert.equal(f.record().state, reference.kind === 'attempt-proof' ? 'proof-intent' : 'refresh-intent');
  assert.deepEqual(await runtime.retentionPort('dev').retain(binding, ctx()), { status: 'retained', attemptId });
  assert.deepEqual(await runtime.readRecovery('dev', attemptId, ctx()), binding);
  assert.deepEqual(await runtime.retainInitialRefresh('dev')(initial, ctx()), { status: 'retained', attemptId, grantId, familyId });
  const value = await runtime.load('dev', ctx()); assert.equal(value.familyKey, null); assert.deepEqual(value.pendingFamilyKey, key);
  const data = Buffer.concat(fs.readdirSync(f.root).map(name => fs.readFileSync(path.join(f.root, name))));
  for (const secret of [recovery, pkce, refresh, access]) assert.equal(data.includes(Buffer.from(secret)), false);
  assert.doesNotMatch(JSON.stringify(value), /bota_dr1_|bota_dep1_|recoveryVerifier|pkceVerifier|credentialId/);
});

sqliteTest('unknown secret write retains durable intent and exact cleanup proof across runtime reopen', async t => {
  const f = fixture(t), { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx()); f.writeOutcome = 'unknown';
  await assert.rejects(runtime.retentionPort('dev').retain(binding, ctx()), safe('store_unknown', true)); assert.equal(f.record().state, 'proof-intent');
  f.writeOutcome = undefined; const reopened = f.open().runtime; assert.deepEqual(await reopened.readRecovery('dev', attemptId, ctx()), binding);
  const writes = f.calls.filter(item => item[0] === 'write').length; await assert.rejects(reopened.retentionPort('dev').retain(binding, ctx()), safe('pending', true)); assert.equal(f.calls.filter(item => item[0] === 'write').length, writes);
});

sqliteTest('cancellation after native write withholds receipt, retains intent and retires child authority', async t => {
  const f = fixture(t), { runtime } = f.open(), parent = context(); let child;
  await runtime.reserve('dev', deployment, ctx()); f.writeHook = (_ref, _value, context) => { child = context; parent.controller.abort(); };
  await assert.rejects(runtime.retentionPort('dev').retain(binding, { signal: parent.signal, budget: parent.budget }), safe('cancelled', true));
  assert.equal(f.record().state, 'proof-intent'); assert.equal(child.signal.aborted, true); assert.throws(() => child.budget.assertActive(), safe());
});

sqliteTest('initial refresh mismatch refuses all secret mutation and unknown storage stays pending', async t => {
  const f = fixture(t), runtime = await retained(f), before = f.calls.filter(item => item[0] === 'write').length;
  await assert.rejects(runtime.retainInitialRefresh('dev')({ ...initial, attemptId: randomUUID() }, ctx()), safe('binding_mismatch', true));
  assert.equal(f.calls.filter(item => item[0] === 'write').length, before);
  f.writeOutcome = 'unknown'; await assert.rejects(runtime.retainInitialRefresh('dev')(initial, ctx()), safe('store_unknown', true));
  assert.equal((await runtime.load('dev', ctx())).state, 'refresh-intent'); assert.deepEqual(await runtime.readRecovery('dev', attemptId, ctx()), binding);
});

sqliteTest('actual family engine and SQLite adopt only exact ready generation0 then clean attempt entries', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx());
  const before = f.secrets.size; const adopted = await runtime.adopt('dev', attemptId, key, ctx()); assert.equal(adopted.state, 'ready'); assert.deepEqual(adopted.familyKey, key);
  assert.equal(f.secrets.size, before - 2); assert.equal(f.secrets.size, 2); await assert.rejects(runtime.readRecovery('dev', attemptId, ctx()), safe('pending', true));
  await family.revoke(key, ctx()).then(() => assert.fail('must use configured revocation proof'), safe('revocation_unknown', true));
});

sqliteTest('adoption refuses foreign family and changed retained initial before any deletion', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx());
  const deletes = f.calls.filter(item => item[0] === 'delete').length;
  await assert.rejects(runtime.adopt('dev', attemptId, { ...key, familyId: randomUUID() }, ctx()), safe('binding_mismatch', true));
  const reference = f.record().initial.reference; f.secrets.set(delegatedNativeCredentialNames(reference).target, 'bota_dr1_' + Buffer.alloc(32, 9).toString('base64url'));
  await assert.rejects(runtime.adopt('dev', attemptId, key, ctx()), safe('store_unknown', true)); assert.equal(f.calls.filter(item => item[0] === 'delete').length, deletes);
});

sqliteTest('confirmed original-attempt receipt recovers absent-refresh enrollment crash then exact removes all custody', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); f.writeOutcome = 'not_stored';
  await assert.rejects(family.enroll(handoff(), ctx()), safe('store_unknown', true)); f.writeOutcome = undefined;
  assert.equal((await family.inspect(key, ctx())).state, 'enrolling');
  await assert.rejects(runtime.confirmCleanup('dev', attemptId, receipt, ctx()), safe('pending', true));
  const reads = f.calls.filter(item => item[0] === 'read').length;
  const proof = createTrustedDelegatedRevocationHandoff(deployment, attemptId, async () => receipt);
  assert.equal((await family.acceptConfirmedRevocation(key, proof, ctx())).state, 'revoked'); assert.equal(f.calls.filter(item => item[0] === 'read').length, reads);
  await assert.rejects(family.acceptConfirmedRevocation(key, proof, ctx()), safe('invalid_input'));
  assert.equal((await family.remove(key, ctx())).state, 'removed');
  const removed = await runtime.confirmCleanup('dev', attemptId, receipt, ctx()); assert.equal(removed.state, 'removed'); assert.equal(f.secrets.size, 1);
  assert.equal((await runtime.confirmCleanup('dev', attemptId, receipt, ctx())).state, 'removed');
});

for (const fault of ['empty', 'wrong-attempt', 'wrong-grant', 'extra', 'lost', 'cancel', 'deployment']) {
  sqliteTest(`trusted cleanup handoff refuses ${fault}, preserving exact family references`, async t => {
    const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx()); const before = await family.inspect(key, ctx()), parent = context();
    const selected = fault === 'deployment' ? { ...deployment, resources: { ...deployment.resources, mcp: 'https://elsewhere.fixture.invalid/mcp' } } : deployment;
    let calls = 0; const proof = createTrustedDelegatedRevocationHandoff(selected, attemptId, async () => { calls++;
      if (fault === 'lost') throw Error('PRIVATE_REMOTE'); if (fault === 'cancel') parent.controller.abort();
      return fault === 'empty' ? undefined : fault === 'wrong-attempt' ? { ...receipt, attemptId: randomUUID() }
        : fault === 'wrong-grant' ? { ...receipt, grantId: randomUUID() } : fault === 'extra' ? { ...receipt, private: 'PRIVATE_REMOTE' } : receipt; });
    await assert.rejects(family.acceptConfirmedRevocation(key, proof, { signal: parent.signal, budget: parent.budget }), safe());
    const after = await family.inspect(key, ctx());
    if (fault === 'deployment') assert.deepEqual(after, before);
    else { assert.equal(after.state, 'revoking'); assert.deepEqual(after.current, before.current); assert.deepEqual(after.proof, before.proof);
      await assert.rejects(family.withAccess(key, deployment.resources.rest, ctx(), async () => assert.fail('No business egress')), safe('pending', true)); }
    assert.equal(calls, fault === 'deployment' ? 0 : 1);
  });
}

sqliteTest('explicit family logout and removal tombstone the selected native profile without touching keys', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime, { async revoke(_d, _p, expected) { return expected; } });
  await family.enroll(handoff(), ctx()); await runtime.adopt('dev', attemptId, key, ctx());
  await family.revoke(key, ctx()); await assert.rejects(runtime.finalizeRemoval('dev', key, ctx()), safe('pending', true));
  await family.remove(key, ctx()); assert.equal((await runtime.finalizeRemoval('dev', key, ctx())).state, 'removed');
  await assert.rejects(runtime.reserve('dev', deployment, ctx()), safe('exists'));
});

sqliteTest('held postcommit receipt is joined on cancellation and runtime close, never publishes retention success', async t => {
  const f = fixture(t), { runtime } = f.open(), entered = deferred(), release = deferred(), parent = context(); await runtime.reserve('dev', deployment, ctx());
  f.afterPublish = async (_key, _expected, next) => { if (next.state === 'proof-ready') { entered.resolve(); await release.promise; } };
  let settled = false; const job = runtime.retentionPort('dev').retain(binding, { signal: parent.signal, budget: parent.budget }).finally(() => { settled = true; }); void job.catch(() => undefined);
  await entered.promise; parent.controller.abort(); let closeSettled = false; const closing = runtime.close().finally(() => { closeSettled = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false); assert.equal(closeSettled, false); release.resolve();
  await assert.rejects(job, safe()); await closing; assert.equal(f.record().state, 'proof-ready');
});

sqliteTest('postlease cancellation withholds successful metadata and raw close failures stay fixed', async t => {
  const f = fixture(t), { runtime } = f.open(), parent = context(); f.afterLease = () => parent.controller.abort();
  await assert.rejects(runtime.reserve('dev', deployment, { signal: parent.signal, budget: parent.budget }), safe('cancelled', true));
  f.afterLease = undefined; f.closeHook = () => { throw Error('PRIVATE_CLOSE'); }; await assert.rejects(runtime.close(), safe('lease_failed', true));
});

test('forged signals, retargeted contexts and accessors fail before SQL or credentials', async t => {
  const f = fixture(t), { runtime } = f.open(); let hooks = 0;
  const accessor = Object.defineProperty({}, 'signal', { enumerable: true, get() { hooks++; throw Error('PRIVATE_HOOK'); } });
  const signal = new Proxy(new AbortController().signal, { get() { hooks++; throw Error('PRIVATE_HOOK'); } });
  for (const value of [accessor, { signal: Object.create(AbortSignal.prototype), budget: { assertActive() {} } }, { signal, budget: { assertActive() {} } }])
    await assert.rejects(runtime.reserve('dev', deployment, value), safe('invalid_input'));
  assert.equal(hooks, 0); assert.deepEqual(fs.readdirSync(f.root), []); assert.equal(f.calls.length, 0);
});

sqliteTest('unknown retained schema refuses without rewriting or deleting its bytes', async t => {
  const f = fixture(t), { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx());
  const db = new (DatabaseSync())(path.join(f.root, DELEGATED_NATIVE_DATABASE), { allowExtension: false }); db.exec('CREATE TABLE retained_unknown(value TEXT)'); db.close();
  const filename = path.join(f.root, DELEGATED_NATIVE_DATABASE), hash = () => createHash('sha256').update(fs.readFileSync(filename)).digest('hex'), before = hash();
  await assert.rejects(runtime.load('dev', ctx()), safe()); assert.equal(hash(), before); assert.ok(fs.existsSync(filename)); assert.equal(f.calls.length, 0);
});

test('canonical profile codec excludes secrets and refuses alternate byte encodings and getters', () => {
  const reserved = { format: 'bota-delegated-native-profile-v1', revision: randomUUID(), name: 'dev', deployment, state: 'reserved', attempt: null, initial: null, family: null, cleanupReceipt: null };
  const canonical = decodeDelegatedNativeProfile(reserved, 'dev'); assert.deepEqual(decodeDelegatedNativeProfileBytes(Buffer.from(JSON.stringify(canonical) + '\n'), 'dev'), canonical);
  assert.throws(() => decodeDelegatedNativeProfileBytes(Buffer.from(JSON.stringify(canonical)), 'dev'), safe('invalid_state'));
  assert.throws(() => decodeDelegatedNativeProfile({ ...reserved, refreshToken: refresh }, 'dev'), safe('invalid_state'));
  let hooks = 0; assert.throws(() => decodeDelegatedNativeProfile(Object.defineProperty({ ...reserved }, 'state', { enumerable: true, get() { hooks++; return 'reserved'; } }), 'dev'), safe('invalid_state')); assert.equal(hooks, 0);
});

test('unsupported genuine production factory refuses before native bootstrap or canonical custody', { skip: supportedNativeSqlite }, async () => {
  const require = createRequire(import.meta.url), loaded = () => Object.keys(require.cache).filter(name => /[\\/]koffi[\\/]|[\\/]@koromix[\\/]/.test(name)).sort();
  const before = loaded();
  await assert.rejects(createWindowsDelegatedNativeRuntime(ctx()), error => {
    assert.equal(error.code, 'profile_busy'); assert.doesNotMatch(error.message, /fixture|secret|bota_d[arp]/i); return true;
  });
  assert.deepEqual(loaded(), before);
});

sqliteTest('post-COMMIT lost acknowledgement retains exact committed reservation and blocks reenrollment', async t => {
  const f = fixture(t), { runtime } = f.open(), prototype = DatabaseSync().prototype, exec = prototype.exec; let injected = false;
  t.mock.method(prototype, 'exec', function(sql) { const result = Reflect.apply(exec, this, [sql]);
    if (!injected && sql === 'COMMIT' && this.prepare('SELECT count(*) AS n FROM delegated_records').get().n > 0) { injected = true; throw Error('PRIVATE_LOST_ACK'); }
    return result; });
  await assert.rejects(runtime.reserve('dev', deployment, ctx()), safe('metadata_unknown', true)); assert.equal(injected, true);
  t.mock.restoreAll(); const reopened = f.open().runtime; assert.equal((await reopened.load('dev', ctx())).state, 'reserved');
  await assert.rejects(reopened.reserve('dev', deployment, ctx()), safe('exists')); assert.equal(f.calls.length, 0);
});

sqliteTest('independent native snapshot instances refuse stale CAS and observations from a retired ticket', async t => {
  const f = fixture(t), owner = f.open(); await owner.runtime.reserve('dev', deployment, ctx()); const record = f.record(), c = ctx(), selection = { kind: 'profile', name: 'dev' };
  await owner.lease.runExclusive('windows-credential-manager', delegatedNativeLeaseName(selection), c, async () => {
    assert.equal(await owner.snapshots.publish(selection, record.revision, { ...record, revision: randomUUID() }, c), 'not_committed');
    await owner.snapshots.load(selection, c);
  });
  await owner.lease.runExclusive('windows-credential-manager', delegatedNativeLeaseName(selection), c, async () => {
    assert.equal(await owner.snapshots.publish(selection, record.revision, { ...record, revision: randomUUID() }, c), 'not_committed');
  });
  await assert.rejects(owner.snapshots.load(selection, c), safe('metadata_unknown', true));
});

test('aborted parent before deferred work and immediate close open no database or credential', async t => {
  const f = fixture(t), { runtime } = f.open(), parent = context();
  const work = runtime.reserve('dev', deployment, { signal: parent.signal, budget: parent.budget }); parent.controller.abort();
  await assert.rejects(work, safe('cancelled')); assert.deepEqual(fs.readdirSync(f.root), []);
  const second = f.open().runtime, pending = second.reserve('dev', deployment, ctx()); const closing = second.close();
  await assert.rejects(pending, safe('cancelled')); await closing; assert.deepEqual(fs.readdirSync(f.root), []); assert.equal(f.calls.length, 0);
});

sqliteTest('cleanup uncertainty never drops references and explicit recovery reads absence before progress', async t => {
  const f = fixture(t), runtime = await retained(f); const noGrant = { ...receipt, grantId: null, familyId: null }; f.deleteOutcome = 'unknown';
  await assert.rejects(runtime.confirmCleanup('dev', attemptId, noGrant, ctx()), safe('store_unknown', true));
  assert.equal(f.record().state, 'cleanup-confirmed'); assert.ok(f.record().attempt.proof); const deleted = f.calls.filter(item => item[0] === 'delete').length;
  f.deleteOutcome = undefined; assert.equal((await runtime.confirmCleanup('dev', attemptId, noGrant, ctx())).state, 'removed');
  assert.equal(f.calls.filter(item => item[0] === 'delete').length, deleted); assert.equal(f.secrets.size, 1);
});

sqliteTest('adoption cleanup uncertainty resumes local intent without exchange or losing family binding', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx()); f.deleteOutcome = 'unknown';
  await assert.rejects(runtime.adopt('dev', attemptId, key, ctx()), safe('store_unknown', true)); assert.equal((await runtime.load('dev', ctx())).state, 'adopting');
  f.deleteOutcome = undefined; const adopted = await runtime.adopt('dev', attemptId, key, ctx()); assert.equal(adopted.state, 'ready'); assert.deepEqual(adopted.familyKey, key);
});

sqliteTest('terminal family receipts need no new network callback or native credential read', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx());
  await family.acceptConfirmedRevocation(key, createTrustedDelegatedRevocationHandoff(deployment, attemptId, async () => receipt), ctx());
  const count = f.calls.length; let calls = 0;
  const terminal = await family.acceptConfirmedRevocation(key, createTrustedDelegatedRevocationHandoff(deployment, attemptId, async () => { calls++; throw Error('PRIVATE_MUST_NOT_CALL'); }), ctx());
  assert.equal(terminal.state, 'revoked'); assert.equal(calls, 0); assert.equal(f.calls.length, count);
});

sqliteTest('untrusted authority cannot read a family credential through copied references outside its lease', async t => {
  const f = fixture(t), runtime = await received(f), family = engine(runtime); await family.enroll(handoff(), ctx()); const state = await family.inspect(key, ctx()), before = f.calls.length;
  await assert.rejects(runtime.familyPorts.store.read(state.current, ctx()), safe('lease_failed', true)); assert.equal(f.calls.length, before);
});

sqliteTest('retiring context cannot retarget its original parent signal or budget assertion', async t => {
  const f = fixture(t), { runtime } = f.open(), entered = deferred(), release = deferred(), parent = context();
  await runtime.reserve('dev', deployment, ctx()); const input = { signal: parent.signal, budget: { assertActive() {} } };
  f.afterPublish = async (_k, _r, next) => { if (next.state === 'proof-intent') { entered.resolve(); await release.promise; } };
  const pending = runtime.retentionPort('dev').retain(binding, input); void pending.catch(() => undefined); await entered.promise; input.signal = new AbortController().signal; release.resolve();
  await assert.rejects(pending, safe('deadline', true)); assert.equal(f.calls.filter(item => item[0] === 'write').length, 0); assert.equal(f.record().state, 'proof-intent');
});

sqliteTest('actual killed uncommitted SQLite writer recovers only the last canonical profile', { timeout: 20_000 }, async t => {
  const f = fixture(t), { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx()); const before = f.record();
  const source = "const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.argv[1]);db.exec('PRAGMA locking_mode=EXCLUSIVE;PRAGMA trusted_schema=OFF;PRAGMA synchronous=EXTRA;PRAGMA journal_mode=PERSIST;PRAGMA cache_size=1;BEGIN IMMEDIATE');db.prepare(\"UPDATE delegated_records SET snapshot=? WHERE kind='profile'\").run(Buffer.alloc(95000,98));process.stdout.write('READY\\n');setInterval(()=>{},1000);";
  const child = spawn(process.execPath, ['-e', source, path.join(f.root, DELEGATED_NATIVE_DATABASE)], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; const exited = once(child, 'exit'); child.stdout.on('data', chunk => { output += chunk; });
  try { await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('Owned SQLite writer did not signal')), 15000);
    const done = () => { if (output.includes('READY')) { clearTimeout(timer); resolve(); } }; child.stdout.on('data', done); child.once('error', reject); child.once('exit', () => { if (!output.includes('READY')) { clearTimeout(timer); reject(Error('Owned SQLite writer exited')); } }); }); }
  finally { child.kill(); await exited; }
  assert.equal(fs.readFileSync(path.join(f.root, DELEGATED_NATIVE_JOURNAL)).subarray(0, 8).toString('hex'), 'd9d505f920a163d7');
  assert.equal((await runtime.load('dev', ctx())).state, 'reserved'); assert.deepEqual(f.record(), before);
  assert.deepEqual(fs.readFileSync(path.join(f.root, DELEGATED_NATIVE_JOURNAL)).subarray(0, 28), Buffer.alloc(28));
});

sqliteTest('explicit abandon tombstones only an empty reservation with zero credential calls', async t => {
  const f = fixture(t), { runtime } = f.open(); await runtime.reserve('dev', deployment, ctx());
  assert.equal((await runtime.abandonReserved('dev', ctx())).state, 'removed'); assert.equal(f.calls.length, 0);
  assert.equal((await runtime.abandonReserved('dev', ctx())).state, 'removed'); await assert.rejects(runtime.reserve('dev', deployment, ctx()), safe('exists'));
  const other = f.open().runtime; await other.reserve('pending', deployment, ctx()); await other.retentionPort('pending').retain(binding, ctx());
  const before = f.calls.length; await assert.rejects(other.abandonReserved('pending', ctx()), safe('pending', true)); assert.equal(f.calls.length, before);
  assert.equal((await other.load('pending', ctx())).state, 'proof-ready');
});

for (const stage of ['proof', 'initial']) {
  sqliteTest(`saved definitive cleanup receipt resumes after interrupted ${stage} removal without HTTP or proof acquisition`, async t => {
    const f = fixture(t), runtime = await received(f);
    f.deleteHook = ref => (stage === 'proof' ? ref.kind === 'attempt-proof' : ref.kind === 'initial-refresh') ? 'unknown' : undefined;
    await assert.rejects(runtime.confirmCleanup('dev', attemptId, receipt, ctx()), safe('store_unknown', true));
    const saved = f.record(); assert.deepEqual(saved.cleanupReceipt, receipt); assert.equal(saved.state, stage === 'proof' ? 'cleanup-confirmed' : 'removing');
    if (stage === 'initial') assert.equal(saved.attempt.proof, null);
    f.deleteHook = undefined; const reopened = f.open().runtime; assert.equal((await reopened.resumeCleanup('dev', ctx())).state, 'removed');
    assert.equal(f.secrets.size, 1); assert.equal((await reopened.resumeCleanup('dev', ctx())).state, 'removed');
  });
}

sqliteTest('resume cleanup requires an exact protected receipt and never accepts an unconfirmed state', async t => {
  const f = fixture(t), runtime = await received(f), before = f.calls.length;
  await assert.rejects(runtime.resumeCleanup('dev', ctx()), safe('pending', true)); assert.equal(f.calls.length, before);
  f.deleteOutcome = 'not_deleted'; await assert.rejects(runtime.confirmCleanup('dev', attemptId, receipt, ctx()), safe('store_unknown', true));
  const saved = f.record(); saved.cleanupReceipt = { ...saved.cleanupReceipt, grantId: randomUUID() };
  const db = new (DatabaseSync())(path.join(f.root, DELEGATED_NATIVE_DATABASE), { allowExtension: false });
  try { db.prepare("UPDATE delegated_records SET snapshot=? WHERE kind='profile'").run(Buffer.from(JSON.stringify(saved) + '\n')); } finally { db.close(); }
  const calls = f.calls.length; await assert.rejects(f.open().runtime.resumeCleanup('dev', ctx()), safe()); assert.equal(f.calls.length, calls);
});
