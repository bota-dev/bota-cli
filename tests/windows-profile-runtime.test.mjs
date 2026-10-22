import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { bindWindowsKnownFolderApi, bindWindowsProfileDirectoryApi, createWindowsKnownFolderApi, WindowsNativeError } from '../src/windows-native-api.ts';
import { bindWindowsProfileRuntime, getWindowsProfileRoot } from '../src/windows-profile-runtime.ts';
import { qualifyWindowsSnapshotRuntime } from '../src/windows-native-snapshots.ts';

const errorCode = code => error => { assert.equal(error.code, code); assert.equal(error.cause, undefined); return true; };
function context() {
  const controller = new AbortController(); let expired = false;
  return { signal: controller.signal, controller, expire() { expired = true; }, budget: { assertActive() { if (expired) throw new Error('private-budget-canary'); } } };
}
function knownFolder(value = 'C:\\Users\\Synthetic\\AppData\\Local', profile = false) {
  let memory = Buffer.from(`${value}\0`, 'utf16le'); const base = 0x10000n;
  const h = { memory, calls: [], result: 0, nullOutput: false, poisoned: false,
    freeFault: false, lookupFault: false, viewFault: false, tokenFault: false, closeTokenFault: false };
  const bindings = {
    assertHealthy() { if (h.poisoned) throw new WindowsNativeError('windows_native_poisoned'); },
    poison() { h.poisoned = true; },
    openCurrentToken() { h.calls.push('token'); if (h.tokenFault) throw new Error('private-native-canary'); return { value: 17n }; },
    closeToken(token) { assert.equal(token.value, 17n); token.value = null; h.calls.push('close-token'); if (h.closeTokenFault) throw new Error('private-native-canary'); },
    lookup(guid, flags, token, output) {
      assert.equal(guid.toString('hex'), profile ? '8f856c5e220e60479afeea3317b67173' : '8527b3f1ba6fcf4f9d557b8e7f157091'); assert.equal(flags, 0); assert.equal(token, 17n);
      h.calls.push('lookup'); if (!h.nullOutput) output.writeBigUInt64LE(base);
      if (h.lookupFault) throw new Error('private-native-canary'); return h.result;
    },
    view(address, length) {
      if (h.viewFault) throw new Error('private-native-canary');
      assert.equal(length, 2); const offset = Number(address - base); const bytes = h.memory.subarray(offset, offset + length);
      return Uint8Array.from(bytes).buffer;
    },
    free(address) { assert.equal(address, base); h.calls.push('free'); if (h.freeFault) throw new Error('private-native-canary'); },
  };
  h.api = profile ? bindWindowsProfileDirectoryApi(bindings) : bindWindowsKnownFolderApi(bindings); return h;
}
test('KnownFolder uses exact current-user GUID/default flags, copies bounded UTF16 and frees once', () => {
  const h = knownFolder('D:\\Users\\账户\\AppData\\Local');
  assert.equal(h.api.localAppData(), 'D:\\Users\\账户\\AppData\\Local'); assert.deepEqual(h.calls, ['token', 'lookup', 'free', 'close-token']);
  assert.equal(Object.isFrozen(h.api), true);
});
for (const value of ['\\\\server\\share\\Local', 'C:\\unsafe\\..\\Local', 'C:/Users/Local', 'C:\\Users\\Local\\', 'C:\\unsafe:stream', 'C:\\Local\nprivate']) {
  test(`KnownFolder refuses unsupported returned spelling ${JSON.stringify(value)} and frees the returned allocation`, () => {
    const h = knownFolder(value); assert.throws(() => h.api.localAppData(), errorCode('windows_native_untrusted'));
    assert.deepEqual(h.calls, ['token', 'lookup', 'free', 'close-token']);
  });
}
test('KnownFolder failure HRESULT still frees a returned allocation; null result is unavailable', () => {
  const h = knownFolder(); h.result = -2147467259;
  assert.throws(() => h.api.localAppData(), errorCode('windows_native_unavailable')); assert.deepEqual(h.calls, ['token', 'lookup', 'free', 'close-token']);
  const missing = knownFolder(); missing.nullOutput = true;
  assert.throws(() => missing.api.localAppData(), errorCode('windows_native_unavailable')); assert.deepEqual(missing.calls, ['token', 'lookup', 'close-token']);
});
test('KnownFolder unterminated and malformed native results refuse, with no unbounded decoding', () => {
  const h = knownFolder(); h.memory = Buffer.alloc(4098, 65);
  assert.throws(() => h.api.localAppData(), errorCode('windows_native_untrusted')); assert.equal(h.calls.filter(value => value === 'free').length, 1);
  const malformed = knownFolder(); malformed.result = undefined;
  assert.throws(() => malformed.api.localAppData(), errorCode('windows_native_unavailable')); assert.equal(malformed.poisoned, true);
  assert.equal(malformed.calls.filter(value => value === 'free').length, 1);
});
for (const fault of ['tokenFault', 'lookupFault', 'viewFault', 'freeFault', 'closeTokenFault']) {
  test(`KnownFolder ${fault} emits fixed private errors and poisons later lookups`, () => {
    const h = knownFolder(); h[fault] = true;
    assert.throws(() => h.api.localAppData(), error => {
      errorCode(fault === 'freeFault' || fault === 'closeTokenFault' ? 'windows_native_close_unknown' : 'windows_native_unavailable')(error);
      assert.ok(!String(error).includes('canary')); return true;
    });
    const calls = h.calls.length;
    assert.throws(() => h.api.localAppData(), errorCode('windows_native_poisoned')); assert.equal(h.calls.length, calls);
    assert.equal(h.calls.filter(value => value === 'free').length, fault === 'lookupFault' || fault === 'tokenFault' ? 0 : 1);
    assert.equal(h.calls.filter(value => value === 'close-token').length, fault === 'tokenFault' ? 0 : 1);
  });
}
function fixture() {
  const ctx = context(), calls = [], secrets = new Map(); let snapshot = null, active = false;
  const h = { ctx, calls, secrets, local: 'C:\\Synthetic\\Local', hook: undefined, closeFault: undefined, closed: false };
  const identity = { project_id: 'synthetic-project', organization_id: 'synthetic-org', key_id: 'synthetic-key-id',
    key_type: 'restricted', scope_mode: 'restricted', is_test_mode: true, scopes: [] };
  const record = stage => { calls.push(stage); h.hook?.(stage); };
  const lease = { async runExclusive(_store, _name, operation, work) {
    assert.equal(operation, ctx); assert.equal(h.closed, false); assert.equal(active, false); active = true;
    try { return await work(); } finally { active = false; }
  }, close() { record('close'); if (h.closeFault) throw h.closeFault; h.closed = true; } };
  const reference = value => `${value.profile_id}/${value.credential_ref}`;
  const checked = operation => { assert.equal(operation, ctx); assert.equal(active, true); };
  const store = { id: 'windows-credential-manager', async read(ref, operation) { checked(operation); record('read'); return secrets.has(reference(ref)) ? { status: 'present', key: secrets.get(reference(ref)) } : { status: 'absent' }; },
    async write(ref, key, operation) { checked(operation); record('write'); secrets.set(reference(ref), key); return 'stored'; },
    async delete(ref, operation) { checked(operation); record('delete'); secrets.delete(reference(ref)); return 'deleted'; } };
  const snapshots = { async load(_name, operation) { checked(operation); return snapshot; },
    async publish(_name, expected, next, operation) { checked(operation); assert.equal(snapshot?.revision ?? null, expected); snapshot = next; return 'committed'; } };
  h.ports = { qualify() { record('qualify'); }, async localAppData() { record('folder'); return h.local; },
    async openLease(root, operation) { assert.equal(operation, ctx); assert.equal(root, path.win32.join(h.local, 'BotaDeveloperToolchain')); record('lease'); return lease; },
    async createStore(value) { assert.equal(value, lease); record('store'); return store; },
    async createSnapshots(value) { assert.equal(value, lease); record('snapshots'); return snapshots; },
    async readIdentity(origin, key, operation) { checked(operation); record('identity'); assert.equal(origin, 'https://api.example.invalid'); assert.equal(key, 'synthetic-enrollment-only'); return identity; } };
  h.factory = bindWindowsProfileRuntime(h.ports); return h;
}
test('runtime fixes one leaf beneath OS-selected LocalAppData; lookup does not acquire a lease', async () => {
  const h = fixture(); assert.equal(await h.factory.root(h.ctx), 'C:\\Synthetic\\Local\\BotaDeveloperToolchain'); assert.deepEqual(h.calls, ['folder']);
});
test('runtime construction only assembles adapters; engine forwards the exact invocation context and identity', async () => {
  const h = fixture(), runtime = await h.factory.create(h.ctx);
  assert.equal(Object.isFrozen(runtime), true); assert.deepEqual(h.calls, ['qualify', 'folder', 'lease', 'store', 'snapshots']);
  await runtime.engine.enroll({ name: 'synthetic', apiOrigin: 'https://api.example.invalid', key: 'synthetic-enrollment-only' }, h.ctx);
  assert.equal(h.secrets.size, 1);
  await runtime.engine.withCredential('synthetic', {}, h.ctx, async (credential, operation) => {
    assert.equal(operation, h.ctx); assert.equal(credential.apiKey, 'synthetic-enrollment-only'); return { ok: true };
  });
  runtime.close(); runtime.close(); assert.equal(h.calls.filter(value => value === 'close').length, 1);
});
test('runtime refuses unsafe or oversized folder output before acquiring any root or store', async () => {
  for (const value of ['\\\\server\\share', 'C:\\Local\\..\\Other', 'C:\\Local\\', 'C:\\' + 'a'.repeat(2025)]) {
    const h = fixture(); h.local = value;
    await assert.rejects(h.factory.create(h.ctx), errorCode('windows_native_untrusted')); assert.deepEqual(h.calls, ['qualify', 'folder']);
  }
});
test('runtime pre-cancel/deadline refuses before even resolving the OS folder', async () => {
  for (const mode of ['abort', 'expire']) {
    const h = fixture(); if (mode === 'abort') h.ctx.controller.abort('private'); else h.ctx.expire();
    await assert.rejects(h.factory.create(h.ctx), errorCode(mode === 'abort' ? 'profile_cancelled' : 'profile_deadline')); assert.deepEqual(h.calls, []);
  }
});
for (const stage of ['qualify', 'folder', 'lease', 'store', 'snapshots']) {
  test(`runtime cancellation after ${stage} joins any acquired lease without credential access`, async () => {
    const h = fixture(); h.hook = actual => { if (actual === stage) h.ctx.controller.abort('private'); };
    await assert.rejects(h.factory.create(h.ctx), errorCode('profile_cancelled'));
    assert.equal(h.calls.includes('read') || h.calls.includes('write') || h.calls.includes('identity'), false);
    assert.equal(h.calls.filter(value => value === 'close').length, ['qualify', 'folder'].includes(stage) ? 0 : 1);
  });
}
test('runtime assembly failure joins lease and emits no arbitrary diagnostics', async () => {
  const h = fixture(); h.ports.createSnapshots = async () => { throw new Error('private-assembly-canary'); };
  await assert.rejects(h.factory.create(h.ctx), error => { errorCode('windows_native_unavailable')(error); assert.ok(!String(error).includes('canary')); return true; });
  assert.equal(h.calls.filter(value => value === 'close').length, 1);
});
test('runtime close ambiguity is retired once; known pre-close busy may be tried after callback joins', async () => {
  const h = fixture(), runtime = await h.factory.create(h.ctx); h.closeFault = new Error('private-close-canary');
  assert.throws(() => runtime.close(), errorCode('windows_native_unavailable')); runtime.close(); assert.equal(h.calls.filter(value => value === 'close').length, 1);
  const busy = fixture(), selected = await busy.factory.create(busy.ctx); busy.closeFault = new WindowsNativeError('windows_native_busy');
  assert.throws(() => selected.close(), errorCode('windows_native_busy')); busy.closeFault = undefined; selected.close(); selected.close();
  assert.equal(busy.calls.filter(value => value === 'close').length, 2);
});

const windows = process.platform === 'win32' && process.arch === 'x64';
test('unsupported snapshot qualification refuses before canonical folder, lease or adapter admission', async () => {
  const h = fixture();
  h.ports.qualify = () => { h.calls.push('qualify-refused'); throw Error('private-runtime-canary'); };
  await assert.rejects(h.factory.create(h.ctx), errorCode('windows_native_unavailable'));
  assert.deepEqual(h.calls, ['qualify-refused']);
});

test('qualified snapshot runtime performs only an in-memory source-id check', { skip: !windows }, () => {
  qualifyWindowsSnapshotRuntime();
});

test('unsupported exact Node runtime qualification does not construct any SQLite database', { skip: !windows }, () => {
  const url = pathToFileURL(fileURLToPath(new URL('../src/windows-native-snapshots.ts', import.meta.url))).href;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    `import {createRequire} from 'node:module';import {qualifyWindowsSnapshotRuntime} from ${JSON.stringify(url)};const s=createRequire(import.meta.url)('node:sqlite');let calls=0;const real=s.DatabaseSync;s.DatabaseSync=class{constructor(){calls++;throw Error('must-not-open');}};Object.defineProperty(process,'version',{value:'v99.0.0'});let refused=false;try{qualifyWindowsSnapshotRuntime();}catch(e){refused=e.code==='profile_busy';}s.DatabaseSync=real;if(!refused||calls!==0)process.exitCode=1;`],
  { cwd: fileURLToPath(new URL('..', import.meta.url)), windowsHide: true, encoding: 'utf8', timeout: 10000, maxBuffer: 8192 });
  assert.equal(child.status, 0);
});

test('uncertain in-memory qualification close poisons subsequent admission in that process', { skip: !windows }, () => {
  const url = pathToFileURL(fileURLToPath(new URL('../src/windows-native-snapshots.ts', import.meta.url))).href;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    `import {createRequire} from 'node:module';import {qualifyWindowsSnapshotRuntime} from ${JSON.stringify(url)};const s=createRequire(import.meta.url)('node:sqlite');let closes=0;const real=s.DatabaseSync.prototype.close;s.DatabaseSync.prototype.close=function(){closes++;real.call(this);throw Error('private-close');};let first=false,second=false;try{qualifyWindowsSnapshotRuntime();}catch(e){first=e.code==='profile_busy';}s.DatabaseSync.prototype.close=real;try{qualifyWindowsSnapshotRuntime();}catch(e){second=e.code==='profile_busy';}if(!first||!second||closes!==1)process.exitCode=1;`],
  { cwd: fileURLToPath(new URL('..', import.meta.url)), windowsHide: true, encoding: 'utf8', timeout: 10000, maxBuffer: 8192 });
  assert.equal(child.status, 0);
});
test('unsupported OS refuses canonical production lookup without opening a profile root', { skip: windows }, async () => {
  await assert.rejects(getWindowsProfileRoot(context()), errorCode('windows_native_unsupported'));
});
test('actual Windows KnownFolder lookup is read-only and independent of profile environment overrides', { skip: !windows }, async () => {
  const actual = (await createWindowsKnownFolderApi()).localAppData();
  assert.equal(path.win32.basename(await getWindowsProfileRoot(context())), 'BotaDeveloperToolchain');
  const url = pathToFileURL(fileURLToPath(new URL('../src/windows-native-api.ts', import.meta.url))).href;
  const env = {};
  for (const name of ['SystemRoot', 'windir', 'TEMP', 'TMP']) if (process.env[name] !== undefined) env[name] = process.env[name];
  Object.assign(env, { PATH: path.dirname(process.execPath), HOME: 'C:\\ignored-home', USERPROFILE: 'C:\\ignored-profile',
    APPDATA: 'C:\\ignored-appdata', LOCALAPPDATA: 'C:\\ignored-local' });
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    `import {createWindowsKnownFolderApi} from ${JSON.stringify(url)};process.stdout.write(JSON.stringify((await createWindowsKnownFolderApi()).localAppData()));`],
  { cwd: fileURLToPath(new URL('..', import.meta.url)), env, windowsHide: true, encoding: 'utf8', timeout: 10000, maxBuffer: 8192 });
  assert.equal(child.status, 0); assert.equal(child.stderr, '');
  assert.ok(JSON.parse(child.stdout) === actual, 'OS KnownFolder selection must not follow process profile overrides');
  // No lease/runtime factory is constructed; the canonical Bota leaf is untouched.
});

test('delegated Profile folder uses its own fixed GUID and explicit token, with joined cleanup', () => {
  const h = knownFolder('D:\\Users\\Synthetic', true);
  assert.equal(h.api.profileDirectory(), 'D:\\Users\\Synthetic');
  assert.deepEqual(h.calls, ['token', 'lookup', 'free', 'close-token']);
  assert.equal(h.api.localAppData, undefined);
  const failed = knownFolder('D:\\Users\\Synthetic', true); failed.result = -2147467259;
  assert.throws(() => failed.api.profileDirectory(), errorCode('windows_native_unavailable'));
  assert.deepEqual(failed.calls, ['token', 'lookup', 'free', 'close-token']);
});
