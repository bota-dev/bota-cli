import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { WindowsNativeSnapshots, createWindowsNativeSnapshots } from '../src/windows-native-snapshots.ts';
import { openWindowsNativeLease, WINDOWS_NATIVE_STORE_ID } from '../src/windows-native-lease.ts';
import { WINDOWS_SNAPSHOT_APPLICATION_ID, WINDOWS_SNAPSHOT_DATABASE, WINDOWS_SNAPSHOT_JOURNAL,
  WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES } from '../src/windows-snapshot-contract.ts';
import { encodeNativeProfileSnapshot } from '../src/native-profile-codec.ts';
import { NativeProfileTransactions } from '../src/native-profile-transaction.ts';
import { WindowsNativeStore } from '../src/windows-native-store.ts';

const windows = { skip: process.platform !== 'win32' };
const sid = 'S-1-5-21-100-200-300-1001';
const DatabaseSync = () => createRequire(import.meta.url)('node:sqlite').DatabaseSync;
function context() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error('synthetic-private-budget'); } } };
}
function snapshot(state = 'ready', name = 'profile-a') {
  const record = { format_version: 2, name, store_id: WINDOWS_NATIVE_STORE_ID,
    api_origin: 'https://api.example.invalid', project_id: 'synthetic-project', organization_id: 'synthetic-org',
    key_id: 'synthetic-key-id', allow_http_loopback: false, state, profile_id: randomUUID(), credential_ref: randomUUID() };
  const journal = state === 'disabled' ? { format_version: 1, transaction_id: randomUUID(), operation: 'remove', phase: 'intent', desired: record } : null;
  return { format_version: 1, revision: randomUUID(), record, journal };
}
function temp(t) {
  const parent = path.resolve(fileURLToPath(new URL('../../.artifacts/developer-toolchain-20261021/', import.meta.url)));
  fs.mkdirSync(parent, { recursive: true });
  const root = fs.mkdtempSync(path.join(parent, 'bota-native-snapshot-'));
  t.after(() => {
    assert.equal(path.dirname(root), parent); assert.match(path.basename(root), /^bota-native-snapshot-/);
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}
function digest(filename) { return createHash('sha256').update(fs.readFileSync(filename)).digest('hex'); }
function inspect(root, work) {
  const db = new (DatabaseSync())(path.join(root, WINDOWS_SNAPSHOT_DATABASE), { readOnly: true, allowExtension: false });
  try { return work(db); } finally { db.close(); }
}
function fixture(t) {
  const root = temp(t), ctx = context(); let live, liveContext;
  const h = { root, ctx, validateHook: undefined, closeHook: undefined, openHook: undefined, closes: 0 };
  const guard = {
    assertCurrentAccess(context) { assert.ok(live); assert.equal(Object.hasOwn(live, 'metadataOnly'), false); assert.equal(context, liveContext); return live; },
    assertCurrentMetadataAccess(context) { assert.ok(live); assert.equal(live.metadataOnly, true); assert.equal(context, liveContext); return live; },
    openMetadata(binding, context) {
      assert.equal(binding, live); assert.equal(context, liveContext);
      if (!fs.existsSync(path.join(root, WINDOWS_SNAPSHOT_DATABASE)) && !fs.existsSync(path.join(root, WINDOWS_SNAPSHOT_JOURNAL))) return null;
      return this.open(binding, context);
    },
    open(binding, context) {
      assert.equal(binding, live); assert.equal(context, liveContext); h.openHook?.();
      const filename = path.join(root, WINDOWS_SNAPSHOT_DATABASE), journal = path.join(root, WINDOWS_SNAPSHOT_JOURNAL);
      const fresh = !fs.existsSync(filename) && !fs.existsSync(journal);
      if (fresh) { fs.writeFileSync(filename, '', { flag: 'wx' }); fs.writeFileSync(journal, '', { flag: 'wx' }); }
      assert.ok(fs.existsSync(filename) && fs.existsSync(journal));
      return { fresh, currentSid: sid, databaseHeader: fs.readFileSync(filename).subarray(0, 100),
        validate() { assert.equal(live, binding); assert.ok(fs.statSync(filename).size <= WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES); h.validateHook?.(); },
        close() { h.closes++; h.closeHook?.(); } };
    },
  };
  h.port = new WindowsNativeSnapshots(guard);
  h.run = async work => {
    assert.equal(live, undefined); live = Object.freeze({ name: 'profile-a', storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: root }); liveContext = ctx;
    try { return await work(live); } finally { live = undefined; liveContext = undefined; }
  };
  h.runMetadata = async work => {
    assert.equal(live, undefined); live = Object.freeze({ metadataOnly: true, storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: root }); liveContext = ctx;
    try { return await work(live); } finally { live = undefined; liveContext = undefined; }
  };
  h.seed = async value => h.run(async () => { assert.equal(await h.port.load('profile-a', ctx), null); assert.equal(await h.port.publish('profile-a', null, value, ctx), 'committed'); });
  return h;
}
const busy = error => { assert.equal(error.code, 'profile_busy'); assert.equal(error.cause, undefined); assert.doesNotMatch(error.message, /sqlite|S-1-|synthetic-private/i); return true; };

test('fresh SQLite store initializes fixed schema, durable modes and current-SID binding', windows, async t => {
  const h = fixture(t);
  await h.run(async () => assert.equal(await h.port.load('profile-a', h.ctx), null));
  const result = inspect(h.root, db => ({ app: db.prepare('PRAGMA application_id').get().application_id,
    version: db.prepare('PRAGMA user_version').get().user_version, metadata: db.prepare('SELECT * FROM native_profile_store').get(), schema:db.prepare('SELECT type,name FROM sqlite_schema ORDER BY name').all() }));
  assert.equal(result.app, WINDOWS_SNAPSHOT_APPLICATION_ID); assert.equal(result.version, 1);
  assert.deepEqual({ ...result.metadata }, { singleton: 1, format_version: 1, store_id: WINDOWS_NATIVE_STORE_ID, current_sid: sid });
  assert.deepEqual(result.schema.map(item => ({ ...item })), [{ type: 'table', name: 'native_profile_store' }, { type: 'table', name: 'native_profiles' }]);
  assert.deepEqual(fs.readFileSync(path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL)).subarray(0,28), Buffer.alloc(28));
});

test('CAS publishes exact canonical bytes and retains ready, disabled and removed reservations across reopen', windows, async t => {
  const h = fixture(t), ready = snapshot(); await h.seed(ready);
  assert.deepEqual(inspect(h.root, db => Buffer.from(db.prepare('SELECT snapshot FROM native_profiles').get().snapshot)), Buffer.from(encodeNativeProfileSnapshot(ready, 'profile-a', WINDOWS_NATIVE_STORE_ID)));
  let revision = ready.revision;
  for (const state of ['disabled', 'removed']) {
    const next = snapshot(state);
    await h.run(async () => { assert.equal((await h.port.load('profile-a', h.ctx)).revision, revision); assert.equal(await h.port.publish('profile-a', revision, next, h.ctx), 'committed'); });
    revision = next.revision;
    await h.run(async () => { assert.equal((await h.port.load('profile-a', h.ctx)).record.state, state); assert.equal(await h.port.publish('profile-a', null, snapshot(), h.ctx), 'not_committed'); });
  }
});

test('observations belong to one callback ticket even when the same context is reused', windows, async t => {
  const h = fixture(t), initial = snapshot(); await h.seed(initial);
  await h.run(async () => assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed'));
  await assert.rejects(h.port.load('profile-a', h.ctx), busy);
  assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed');
  await h.run(async () => { await h.port.load('profile-a', h.ctx); assert.equal(await h.port.publish('another', initial.revision, snapshot(), h.ctx), 'not_committed'); assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), context()), 'not_committed'); });
});

test('metadata list returns only complete frozen rows and never establishes named CAS authority', windows, async t => {
  const h = fixture(t), initial = snapshot();
  await h.runMetadata(async () => assert.deepEqual(await h.port.list(h.ctx), []));
  assert.deepEqual(fs.readdirSync(h.root), []);
  await h.seed(initial);
  await h.run(async () => await assert.rejects(h.port.list(h.ctx), busy));
  await h.runMetadata(async () => {
    const rows = await h.port.list(h.ctx);
    assert.deepEqual(rows, [{ name: 'profile-a', snapshot: initial }]);
    assert.equal(Object.isFrozen(rows), true); assert.equal(Object.isFrozen(rows[0]), true);
    assert.equal(Object.isFrozen(rows[0].snapshot), true); assert.equal(Object.isFrozen(rows[0].snapshot.record), true);
    await assert.rejects(h.port.load('profile-a', h.ctx), busy);
    assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed');
  });
  await h.run(async () => assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed'));
});

for (const mode of ['cancel', 'deadline', 'close']) {
  test(`metadata ${mode} during joined cleanup returns no result`, windows, async t => {
    const h = fixture(t); await h.seed(snapshot());
    h.closeHook = () => {
      if (mode === 'cancel') h.ctx.controller.abort('synthetic-private-abort');
      else if (mode === 'deadline') h.ctx.expire();
      else throw new Error('synthetic-private-close');
    };
    await h.runMetadata(async () => await assert.rejects(h.port.list(h.ctx), error => ['profile_busy', 'profile_cancelled', 'profile_deadline'].includes(error.code)));
    h.closeHook = undefined;
    if (mode === 'close') {
      const before = h.closes;
      await h.runMetadata(async () => await assert.rejects(h.port.list(h.ctx), busy)); assert.equal(h.closes, before);
    }
  });
}

test('metadata SQL transaction rejects logical writes after its query-only boundary', windows, async t => {
  const h = fixture(t), initial = snapshot(); await h.seed(initial);
  const filename = path.join(h.root, WINDOWS_SNAPSHOT_DATABASE), journal = path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL);
  const before = [digest(filename), digest(journal)], prototype = DatabaseSync().prototype, original = prototype.exec;
  let checked = false;
  prototype.exec = function(sql) {
    if (sql === 'BEGIN') {
      assert.equal(this.prepare('PRAGMA query_only').get().query_only, 1);
      assert.throws(() => this.prepare('DELETE FROM native_profiles').run(), error => error.errcode === 8);
      checked = true;
    }
    return original.call(this, sql);
  };
  try { await h.runMetadata(async () => assert.deepEqual(await h.port.list(h.ctx), [{ name: 'profile-a', snapshot: initial }])); }
  finally { prototype.exec = original; }
  assert.equal(checked, true); assert.deepEqual([digest(filename), digest(journal)], before);
});

test('same revision with different valid bytes fails CAS without overwriting the observed database', windows, async t => {
  const h = fixture(t), initial = snapshot(); await h.seed(initial);
  await h.run(async () => {
    await h.port.load('profile-a', h.ctx);
    const changed = { ...initial, record: { ...initial.record, key_id: 'changed-safe-key' } };
    const db = new (DatabaseSync())(path.join(h.root, WINDOWS_SNAPSHOT_DATABASE));
    try { db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=PERSIST; PRAGMA synchronous=EXTRA'); db.prepare('UPDATE native_profiles SET snapshot=? WHERE name=?').run(encodeNativeProfileSnapshot(changed, 'profile-a', WINDOWS_NATIVE_STORE_ID), 'profile-a'); } finally { db.close(); }
    assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed');
    assert.equal((await h.port.load('profile-a', h.ctx)).record.key_id, 'changed-safe-key');
  });
});

for (const fault of ['cancel', 'deadline', 'close', 'post-commit-validation']) {
  test(`${fault} after commit is unknown, preserves new state, and poisons this ticket`, windows, async t => {
    const h = fixture(t), initial = snapshot(), next = snapshot(); await h.seed(initial);
    await h.run(async () => {
      await h.port.load('profile-a', h.ctx); let validations = 0;
      if (fault === 'close') h.closeHook = () => { throw new Error('synthetic-private-close'); };
      else h.validateHook = () => { if (++validations === 3) { if (fault === 'cancel') h.ctx.controller.abort('synthetic-private-abort'); else if (fault === 'deadline') h.ctx.expire(); else throw new Error('synthetic-private-postcheck'); } };
      assert.equal(await h.port.publish('profile-a', initial.revision, next, h.ctx), 'unknown');
      h.validateHook = undefined; h.closeHook = undefined;
      assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed');
    });
    assert.equal(inspect(h.root, db => db.prepare('SELECT revision FROM native_profiles').get().revision), next.revision);
  });
}

test('cancellation before transaction cannot write the next snapshot and fixed errors omit private reasons', windows, async t => {
  const h = fixture(t), initial = snapshot(); await h.seed(initial);
  await h.run(async () => { await h.port.load('profile-a', h.ctx); h.ctx.controller.abort('synthetic-private-abort'); assert.equal(await h.port.publish('profile-a', initial.revision, snapshot(), h.ctx), 'not_committed'); });
  assert.equal(inspect(h.root, db => db.prepare('SELECT revision FROM native_profiles').get().revision), initial.revision);
});

for (const stage of ['qualification', 'physical-connection']) {
  test(`${stage} close ambiguity retires this adapter before any later callback`, windows, async t => {
    const h=fixture(t),initial=snapshot();await h.seed(initial);
    const prototype=DatabaseSync().prototype, original=prototype.close;let closes=0;
    prototype.close=function(){original.call(this);if(++closes===(stage==='qualification'?1:3))throw new Error('synthetic-private-close-ack');};
    try { await h.run(async()=>await assert.rejects(h.port.load('profile-a',h.ctx),busy)); }
    finally {prototype.close=original;}
    const acquired=h.closes;
    await h.run(async()=>await assert.rejects(h.port.load('profile-a',h.ctx),busy));
    assert.equal(h.closes,acquired);
  });
}

for (const stage of ['before-native-commit', 'after-native-commit']) {
  test(`${stage} acknowledgement failure is unknown even if rollback could prove the prior value`, windows, async t => {
    const h=fixture(t),initial=snapshot(),next=snapshot();await h.seed(initial);
    await h.run(async()=>{
      await h.port.load('profile-a',h.ctx);
      const prototype=DatabaseSync().prototype,original=prototype.exec;
      prototype.exec=function(sql){if(sql==='COMMIT'){if(stage==='after-native-commit')original.call(this,sql);throw new Error('synthetic-private-commit-ack');}return original.call(this,sql);};
      try {assert.equal(await h.port.publish('profile-a',initial.revision,next,h.ctx),'unknown');}
      finally {prototype.exec=original;}
      assert.equal(await h.port.publish('profile-a',initial.revision,snapshot(),h.ctx),'not_committed');
    });
    assert.equal(inspect(h.root,db=>db.prepare('SELECT revision FROM native_profiles').get().revision),stage==='after-native-commit'?next.revision:initial.revision);
  });
}

for (const fault of ['application-id', 'version', 'wal-header', 'foreign-schema', 'foreign-view', 'foreign-trigger', 'nul-suffixed-schema-type', 'foreign-sid', 'oversized-metadata', 'nul-suffixed-metadata', 'too-many-profiles', 'wrong-revision', 'invalid-canonical-bytes', 'empty-bootstrap']) {
  test(`${fault} existing metadata is refused and byte-preserved`, windows, async t => {
    const h = fixture(t), initial = snapshot(); await h.seed(initial);
    const filename = path.join(h.root, WINDOWS_SNAPSHOT_DATABASE);
    if (fault === 'empty-bootstrap') { fs.truncateSync(filename, 0); fs.truncateSync(path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL), 0); }
    else if (fault === 'wal-header') { const fd=fs.openSync(filename,'r+'); try { fs.writeSync(fd, Buffer.from([2,2]),0,2,18); } finally { fs.closeSync(fd); } }
    else {
      const db = new (DatabaseSync())(filename);
      try {
        db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=PERSIST; PRAGMA synchronous=EXTRA');
        if (fault === 'application-id') db.exec('PRAGMA application_id=1');
        else if (fault === 'version') db.exec('PRAGMA user_version=2');
        else if (fault === 'foreign-schema') db.exec('CREATE TABLE foreign_extra(secret BLOB)');
        else if (fault === 'foreign-view') db.exec('CREATE VIEW foreign_view AS SELECT snapshot FROM native_profiles');
        else if (fault === 'foreign-trigger') db.exec('CREATE TRIGGER foreign_trigger AFTER UPDATE ON native_profiles BEGIN DELETE FROM native_profiles; END');
        else if (fault === 'nul-suffixed-schema-type') { db.enableDefensive?.(false); db.exec('PRAGMA writable_schema=ON'); db.prepare('UPDATE sqlite_schema SET type=? WHERE name=?').run('table\0'+'9'.repeat(8192),'native_profiles'); }
        else if (fault === 'foreign-sid') db.prepare('UPDATE native_profile_store SET current_sid=?').run('S-1-5-21-999');
        else if (fault === 'oversized-metadata') db.prepare('UPDATE native_profile_store SET current_sid=?').run('S-1-5-21-' + '9'.repeat(8192));
        else if (fault === 'nul-suffixed-metadata') db.prepare('UPDATE native_profile_store SET current_sid=?').run(sid+'\0'+'9'.repeat(8192));
        else if (fault === 'too-many-profiles') {
          db.exec('BEGIN IMMEDIATE'); const insert=db.prepare('INSERT INTO native_profiles VALUES(?,?,?)');
          for(let index=0;index<1024;index++)insert.run(`extra-${index}`,initial.revision,encodeNativeProfileSnapshot(initial,'profile-a',WINDOWS_NATIVE_STORE_ID));
          db.exec('COMMIT');
        }
        else if (fault === 'wrong-revision') db.prepare('UPDATE native_profiles SET revision=?').run(randomUUID());
        else db.prepare('UPDATE native_profiles SET snapshot=?').run(Buffer.from('{"invalid":true}\n'));
      } finally { db.close(); }
    }
    const before = digest(filename), journalBefore = digest(path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL));
    await h.run(async () => await assert.rejects(h.port.load('profile-a', h.ctx), busy));
    assert.equal(digest(filename), before); assert.equal(digest(path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL)), journalBefore);
    await h.runMetadata(async () => await assert.rejects(h.port.list(h.ctx), busy));
    assert.equal(digest(filename), before); assert.equal(digest(path.join(h.root, WINDOWS_SNAPSHOT_JOURNAL)), journalBefore);
  });
}

function childEnv() {
  const env = {}; for (const name of ['SystemRoot','windir','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA']) if (process.env[name] !== undefined) env[name]=process.env[name];
  env.PATH=path.dirname(process.execPath); return env;
}
async function killedWriter(root, stage, next) {
  const code = `const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.argv[1]);db.exec('PRAGMA locking_mode=EXCLUSIVE;PRAGMA trusted_schema=OFF;PRAGMA synchronous=EXTRA;PRAGMA journal_mode=PERSIST;PRAGMA cache_size=1;BEGIN IMMEDIATE');${next ? "db.prepare('UPDATE native_profiles SET revision=?,snapshot=? WHERE name=?').run(process.argv[3],Buffer.from(process.argv[2],'base64'),'profile-a');" : "db.prepare('UPDATE native_profiles SET snapshot=? WHERE name=?').run(Buffer.alloc(24000,98),'profile-a');"}${stage === 'committed' ? "db.exec('COMMIT');" : ''}process.stdout.write('READY\\n');setInterval(()=>{},1000);`;
  const args=[process.execPath,['-e',code,path.join(root,WINDOWS_SNAPSHOT_DATABASE),next ? Buffer.from(encodeNativeProfileSnapshot(next,'profile-a',WINDOWS_NATIVE_STORE_ID)).toString('base64') : '',next?.revision ?? '']];
  const child=spawn(args[0],args[1],{env:childEnv(),stdio:['ignore','pipe','pipe']});
  let output='',error='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>error+=b);
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill();reject(new Error('synthetic SQLite child timeout'));},15000);child.stdout.on('data',()=>{if(output.includes('READY')){clearTimeout(timer);resolve();}});child.on('error',reject);child.on('exit',()=>{if(!output.includes('READY')){clearTimeout(timer);reject(new Error('synthetic SQLite child exited'));}});});
  const exited=once(child,'exit');child.kill();await exited;return error;
}

test('killed uncommitted writer retains hot journal; SQLite restores last canonical snapshot', windows, async t => {
  const h = fixture(t), initial = snapshot(); await h.seed(initial);
  await killedWriter(h.root, 'uncommitted');
  const header = fs.readFileSync(path.join(h.root,WINDOWS_SNAPSHOT_JOURNAL)).subarray(0,8);
  assert.equal(header.toString('hex'),'d9d505f920a163d7');
  await h.run(async()=>assert.deepEqual(await h.port.load('profile-a',h.ctx),initial));
  assert.ok(fs.existsSync(path.join(h.root,WINDOWS_SNAPSHOT_JOURNAL)));
  assert.deepEqual(fs.readFileSync(path.join(h.root,WINDOWS_SNAPSHOT_JOURNAL)).subarray(0,28),Buffer.alloc(28));
});

test('a writer killed after COMMIT retains the committed canonical snapshot without its acknowledgement', windows, async t => {
  const h=fixture(t),initial=snapshot(),next=snapshot('removed');await h.seed(initial);
  await killedWriter(h.root,'committed',next);
  await h.run(async()=>assert.deepEqual(await h.port.load('profile-a',h.ctx),next));
  assert.ok(fs.existsSync(path.join(h.root,WINDOWS_SNAPSHOT_JOURNAL)));
});

test('actual native pins remain held through SQLite bootstrap, CAS, reopen and file cleanup', windows, async t => {
  const root = temp(t), nativeRoot=path.join(root,'private-store'), ctx=context();
  const lease=await openWindowsNativeLease(nativeRoot,ctx);
  try {
    const port=await createWindowsNativeSnapshots(lease), next=snapshot();
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'profile-a',ctx,async()=>{assert.equal(await port.load('profile-a',ctx),null);assert.equal(await port.publish('profile-a',null,next,ctx),'committed');});
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'profile-a',ctx,async()=>assert.deepEqual(await port.load('profile-a',ctx),next));
    await killedWriter(nativeRoot,'uncommitted');
    await lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID,ctx,async()=>assert.deepEqual(await port.list(ctx),[{name:'profile-a',snapshot:next}]));
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'profile-a',ctx,async()=>assert.deepEqual(await port.load('profile-a',ctx),next));
    assert.ok(fs.existsSync(path.join(nativeRoot,WINDOWS_SNAPSHOT_JOURNAL)));
  } finally { lease.close(); }
});

test('actual namespace-only metadata listing preserves empty absence, all states, CAS isolation and credential denial', windows, async t => {
  const root = temp(t), nativeRoot = path.join(root, 'private-store'), ctx = context();
  let lease = await openWindowsNativeLease(nativeRoot, ctx);
  try {
    let port = await createWindowsNativeSnapshots(lease);
    await lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID, ctx, async () => {
      assert.deepEqual(await port.list(ctx), []);
      assert.deepEqual(fs.readdirSync(nativeRoot), ['store-windows-credential-manager.lease']);
    });
    const values = [snapshot('removed', 'zulu'), snapshot('ready', 'alpha'), snapshot('disabled', 'middle')];
    const pending = snapshot('ready', 'pending');
    values.push({ ...pending, record: null, journal: { format_version: 1, transaction_id: randomUUID(), operation: 'enroll', phase: 'intent', desired: pending.record } });
    for (const next of values) {
      const name = next.record?.name ?? next.journal.desired.name;
      await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, name, ctx, async () => {
        assert.equal(await port.load(name, ctx), null);
        assert.equal(await port.publish(name, null, next, ctx), 'committed');
      });
    }
    const files = fs.readdirSync(nativeRoot), before = [digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_DATABASE)), digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_JOURNAL))];
    lease.close(); lease = await openWindowsNativeLease(nativeRoot, ctx); port = await createWindowsNativeSnapshots(lease);
    const calls = [], credentialApi = { assertHealthy() { calls.push('healthy'); }, readCredential() { calls.push('read'); }, writeCredential() { calls.push('write'); }, deleteCredential() { calls.push('delete'); } };
    const store = WindowsNativeStore.open(credentialApi, lease), reference = { profile_id: values[1].record.profile_id, credential_ref: values[1].record.credential_ref };
    await lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID, ctx, async () => {
      const rows = await port.list(ctx);
      assert.deepEqual(rows.map(entry => entry.name), ['alpha', 'middle', 'pending', 'zulu']);
      for (const entry of rows) assert.deepEqual(entry.snapshot, values.find(value => (value.record?.name ?? value.journal.desired.name) === entry.name));
      for (const action of [() => store.read(reference, ctx), () => store.write(reference, 'synthetic-never-written', ctx), () => store.delete(reference, ctx)]) {
        await assert.rejects(action(), error => error.code === 'windows_native_untrusted');
      }
      await assert.rejects(port.load('alpha', ctx), busy);
      assert.equal(await port.publish('alpha', values[1].revision, snapshot('ready', 'alpha'), ctx), 'not_committed');
    });
    assert.deepEqual(calls, []); assert.deepEqual(fs.readdirSync(nativeRoot), files);
    assert.deepEqual([digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_DATABASE)), digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_JOURNAL))], before);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'alpha', ctx, async () => {
      await assert.rejects(port.list(ctx), busy);
      assert.equal(await port.publish('alpha', values[1].revision, snapshot('ready', 'alpha'), ctx), 'not_committed');
    });
    const retainedLease = path.join(nativeRoot, `profile-${Buffer.from('middle', 'ascii').toString('hex')}.lease`);
    fs.writeFileSync(retainedLease, 'retained invalid lease');
    await lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID, ctx, async () => await assert.rejects(port.list(ctx), busy));
    assert.equal(fs.readFileSync(retainedLease, 'utf8'), 'retained invalid lease');
    assert.deepEqual([digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_DATABASE)), digest(path.join(nativeRoot, WINDOWS_SNAPSHOT_JOURNAL))], before);
  } finally { lease.close(); }
});

test('real hot journal with a foreign super-journal footer refuses before SQLite and preserves every synthetic file', windows, async t => {
  const root=temp(t),nativeRoot=path.join(root,'private-store'),ctx=context(),initial=snapshot();
  const lease=await openWindowsNativeLease(nativeRoot,ctx);
  try {
    const port=await createWindowsNativeSnapshots(lease);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'profile-a',ctx,async()=>{assert.equal(await port.load('profile-a',ctx),null);assert.equal(await port.publish('profile-a',null,initial,ctx),'committed');});
    await killedWriter(nativeRoot,'uncommitted');
    const database=path.join(nativeRoot,WINDOWS_SNAPSHOT_DATABASE),journal=path.join(nativeRoot,WINDOWS_SNAPSHOT_JOURNAL);
    assert.equal(fs.readFileSync(journal).subarray(0,8).toString('hex'),'d9d505f920a163d7');
    const external=path.join(root,'external-synthetic-sentinel'),sentinel=Buffer.from('synthetic external content must remain unchanged');
    fs.writeFileSync(external,sentinel,{flag:'wx'});
    const name=Buffer.from(external,'utf8'),marker=Buffer.alloc(4),footer=Buffer.alloc(16);marker.writeUInt32BE(262145);
    footer.writeUInt32BE(name.length,0);footer.writeUInt32BE(name.reduce((sum,value)=>sum+value,0)>>>0,4);Buffer.from('d9d505f920a163d7','hex').copy(footer,8);
    fs.appendFileSync(journal,Buffer.concat([marker,name,footer]));
    const before=[digest(database),digest(journal),digest(external)],prototype=DatabaseSync().prototype,prepare=prototype.prepare;let sqlCalls=0;
    prototype.prepare=function(){sqlCalls++;throw new Error('synthetic SQLite must not be reached');};
    try {
      await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'profile-a',ctx,async()=>await assert.rejects(port.load('profile-a',ctx),busy));
      await lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID,ctx,async()=>await assert.rejects(port.list(ctx),busy));
    }
    finally {prototype.prepare=prepare;}
    assert.equal(sqlCalls,0);assert.deepEqual([digest(database),digest(journal),digest(external)],before);assert.deepEqual(fs.readFileSync(external),sentinel);
  } finally {lease.close();}
});

test('real lease, file guard and SQLite compose with engine enrollment, action, removal and reopened tombstone', windows, async t => {
  const root=temp(t),nativeRoot=path.join(root,'private-store'),ctx=context(),bearer='rk_SYNTHETIC_SQLITE_ENGINE_ONLY';
  const secrets=new Map(),storeCalls=[];let lease=await openWindowsNativeLease(nativeRoot,ctx);
  const identity={project_id:'synthetic-project',organization_id:'synthetic-org',key_id:'synthetic-key-id',key_type:'restricted',is_test_mode:false,scope_mode:'restricted',scopes:[]};
  const ref=value=>`${value.profile_id}/${value.credential_ref}`;
  const current=()=>JSON.parse(inspect(nativeRoot,db=>Buffer.from(db.prepare('SELECT snapshot FROM native_profiles WHERE name=?').get('profile-a').snapshot).toString('utf8')));
  const store={id:WINDOWS_NATIVE_STORE_ID,
    async read(reference,context){lease.assertCurrentAccess(context);storeCalls.push('read');return secrets.has(ref(reference))?{status:'present',key:secrets.get(ref(reference))}:{status:'absent'};},
    async write(reference,key,context){lease.assertCurrentAccess(context);storeCalls.push('write');const state=current();assert.equal(state.record,null);assert.equal(state.journal.operation,'enroll');assert.equal(state.journal.phase,'intent');assert.equal(state.journal.desired.credential_ref,reference.credential_ref);secrets.set(ref(reference),key);return'stored';},
    async delete(reference,context){lease.assertCurrentAccess(context);storeCalls.push('delete');const state=current();assert.equal(state.record.state,'disabled');assert.equal(state.journal.operation,'remove');assert.equal(state.journal.phase,'intent');assert.equal(state.record.credential_ref,reference.credential_ref);secrets.delete(ref(reference));return'deleted';}};
  const engine=async()=>new NativeProfileTransactions({lease,snapshots:await createWindowsNativeSnapshots(lease),store,
    async readIdentity(origin,key,context){lease.assertCurrentAccess(context);assert.equal(origin,'https://api.example.invalid');assert.equal(key,bearer);return identity;}});
  try {
    let runtime=await engine();const ready=await runtime.enroll({name:'profile-a',apiOrigin:'https://api.example.invalid',key:bearer},ctx);
    assert.equal(ready.state,'ready');assert.equal(current().journal,null);assert.equal(secrets.size,1);
    lease.close();lease=await openWindowsNativeLease(nativeRoot,ctx);runtime=await engine();
    assert.deepEqual(await runtime.withCredential('profile-a',{},ctx,async(credential,context)=>{assert.equal(context,ctx);assert.equal(credential.apiKey,bearer);assert.equal(credential.source,'store');lease.assertCurrentAccess(context);await new Promise(resolve=>setImmediate(resolve));return{ok:true,project:credential.identity.project_id};}),{ok:true,project:identity.project_id});
    assert.equal((await runtime.remove('profile-a',ctx)).state,'removed');assert.equal(secrets.size,0);assert.equal(current().journal,null);
    const before=storeCalls.length;lease.close();lease=await openWindowsNativeLease(nativeRoot,ctx);runtime=await engine();
    assert.equal((await runtime.remove('profile-a',ctx)).state,'removed');assert.equal(storeCalls.length,before);
    await assert.rejects(runtime.enroll({name:'profile-a',apiOrigin:'https://api.example.invalid',key:bearer},ctx),error=>error.code==='profile_exists');
    assert.equal(storeCalls.filter(value=>value==='write').length,1);assert.equal(storeCalls.filter(value=>value==='delete').length,1);
    for(const name of [WINDOWS_SNAPSHOT_DATABASE,WINDOWS_SNAPSHOT_JOURNAL])assert.equal(fs.readFileSync(path.join(nativeRoot,name)).includes(Buffer.from(bearer)),false);
  } finally {lease.close();}
});
