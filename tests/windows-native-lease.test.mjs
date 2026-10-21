import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WindowsNativeLease, openWindowsNativeLease, WINDOWS_NATIVE_STORE_ID } from '../src/windows-native-lease.ts';
import { WindowsNativeError, nativeLeaseRootPath } from '../src/windows-native-api.ts';

function context() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error('opaque-budget'); } } };
}
const errorCode = code => error => { assert.equal(error.code, code); assert.equal(error.cause, undefined); return true; };
function fakeApi() {
  let sequence = 0;
  const entries = new Map(), calls = [];
  const h = { calls, entries, closeFault: false, wrongPath: false, badSize: false, badLinks: false, reparse: false, badAcl: false };
  const opened = (filename, kind) => {
    const handle = { value: BigInt(++sequence) }; entries.set(handle, { filename, kind }); calls.push(['open', filename]); return handle;
  };
  h.api = {
    currentSid: 'synthetic', assertHealthy() {},
    openDirectory(filename) { return opened(filename, 'directory'); },
    createPrivateDirectory(filename) { calls.push(['create', filename]); },
    openLease(filename) { return opened(filename, 'file'); },
    facts(handle) {
      const item = entries.get(handle);
      return { attributes: (item.kind === 'directory' ? 0x10 : 0) | (h.reparse ? 0x400 : 0),
        size: h.badSize ? 1n : 0n, links: h.badLinks ? 2 : 1, identity: String(handle.value),
        finalPath: `\\\\?\\${item.filename}${h.wrongPath ? '-other' : ''}` };
    },
    trust(handle, kind) { calls.push(['trust', kind]); if (h.badAcl) throw new WindowsNativeError('windows_native_untrusted'); },
    localNtfs() {},
    close(handle) {
      if (handle.value === null) return;
      const value = handle.value; handle.value = null; calls.push(['close', value]);
      if (h.closeFault) { h.closeFault = false; throw new Error('opaque native reason'); }
    },
  };
  return h;
}
test('root paths refuse devices, streams, traversal, aliases and unsupported spellings', () => {
  for (const value of ['', null, '/tmp/root', '\\\\server\\root', '\\\\?\\C:\\root', 'C:\\root\\',
    'C:\\root\\..\\other', 'C:\\root\\.', 'C:\\root\\file:stream', 'C:\\root\\con',
    'C:\\root\\file.', 'C:\\root\\file ', 'C:/root', 'C:\\root\nother']) {
    assert.throws(() => nativeLeaseRootPath(value), errorCode('windows_native_untrusted'));
  }
  assert.equal(nativeLeaseRootPath('C:\\synthetic\\root'), 'C:\\synthetic\\root');
});
test('injected lease owns root/namespace/profile through callback and closes in reverse order once', async () => {
  const h = fakeApi(), ctx = context(); const lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
  assert.throws(() => { lease.rootDirectory = 'C:\\untrusted\\redirect'; }, TypeError);
  assert.throws(() => Object.defineProperty(lease, 'rootDirectory', { value: 'C:\\untrusted\\redirect' }), TypeError);
  const value = { safe: true };
  const result = await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'project-a', ctx, async () => {
    const names = h.calls.filter(row => row[0] === 'open').map(row => row[1]);
    assert.match(names.at(-2), /store-windows-credential-manager\.lease$/);
    assert.match(names.at(-1), /profile-70726f6a6563742d61\.lease$/);
    assert.equal(h.calls.filter(row => row[0] === 'close').length, 0);
    assert.throws(() => lease.close(), errorCode('windows_native_busy'));
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'other', ctx, async () => {}), errorCode('windows_native_busy'));
    return value;
  });
  assert.equal(result, value); assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n]);
  lease.close(); const count = h.calls.length; lease.close(); assert.equal(h.calls.length, count);
  assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n, 3n, 2n, 1n]);
});
test('invalid names/store, cancellation and expired budget refuse before new native handles', async () => {
  const expiredApi = fakeApi(), expired = context(); expired.expire();
  assert.throws(() => WindowsNativeLease.open(expiredApi.api, 'C:\\synthetic\\root', expired), errorCode('windows_native_deadline'));
  assert.equal(expiredApi.calls.length, 0);
  const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
  const before = h.calls.length;
  await assert.rejects(lease.runExclusive('foreign', 'valid', ctx, async () => {}), errorCode('windows_native_untrusted'));
  for (const name of ['../escape', 'A', '', 'a'.repeat(65)]) await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, name, ctx, async () => {}), errorCode('windows_native_untrusted'));
  ctx.controller.abort('private cancellation reason');
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => {}), errorCode('windows_native_cancelled'));
  assert.equal(h.calls.length, before); lease.close();
});

test('adapter access is bound to the exact live callback, context and lease instance', async () => {
  const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
  const other = WindowsNativeLease.open(fakeApi().api, 'C:\\synthetic\\other', ctx);
  assert.throws(() => lease.assertCurrentAccess(ctx), errorCode('windows_native_untrusted'));
  await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'selected', ctx, async () => {
    const binding = lease.assertCurrentAccess(ctx);
    assert.deepEqual(binding, { name: 'selected', storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: 'C:\\synthetic\\root' });
    assert.equal(Object.isFrozen(binding), true);
    assert.throws(() => { binding.name = 'other'; }, TypeError);
    assert.throws(() => lease.assertCurrentAccess(context()), errorCode('windows_native_untrusted'));
    assert.throws(() => other.assertCurrentAccess(ctx), errorCode('windows_native_untrusted'));
    await Promise.resolve();
    assert.equal(lease.assertCurrentAccess(ctx), binding);
  });
  assert.throws(() => lease.assertCurrentAccess(ctx), errorCode('windows_native_untrusted'));
  other.close(); lease.close();
  assert.throws(() => lease.assertCurrentAccess(ctx), errorCode('windows_native_unavailable'));
});

for (const throws of [false, true]) {
  test(`async descendants cannot reuse a retired ticket after callback ${throws ? 'failure' : 'success'} or during a successor`, async () => {
    const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
    let release, stale;
    const retired = lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'first', ctx, async () => {
      stale = new Promise(resolve => { release = resolve; }).then(() => {
        assert.throws(() => lease.assertCurrentAccess(ctx), errorCode('windows_native_untrusted'));
      });
      if (throws) throw new Error('synthetic callback');
    });
    if (throws) await assert.rejects(retired, /synthetic callback/); else await retired;
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'second', ctx, async () => {
      assert.equal(lease.assertCurrentAccess(ctx).name, 'second'); release(); await stale;
      assert.equal(lease.assertCurrentAccess(ctx).name, 'second');
    });
    lease.close();
  });
}
test('deadline/cancellation after caller completion still closes both leases without extending budget', async () => {
  for (const mode of ['expire', 'abort']) {
    const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => {
      if (mode === 'expire') ctx.expire(); else ctx.controller.abort('private'); return 'late';
    }), errorCode(mode === 'expire' ? 'windows_native_deadline' : 'windows_native_cancelled'));
    assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n]); lease.close();
  }
});
test('native closure ambiguity retires once, releases remaining handles and permanently poisons this lease', async () => {
  const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
  h.closeFault = true;
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => true), errorCode('windows_native_close_unknown'));
  const count = h.calls.length;
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => assert.fail()), errorCode('windows_native_poisoned'));
  assert.equal(h.calls.length, count);
  assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n]); lease.close();
  assert.equal(h.calls.filter(row => row[0] === 'close' && row[1] === 5n).length, 1);
});
test('callback failure and partial-acquisition cancellation still join owned handles', async () => {
  const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx);
  const reason = new Error('caller safe failure');
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => { throw reason; }), error => error === reason);
  assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n]);
  const original = h.api.openLease; h.api.openLease = filename => { const handle = original(filename); ctx.controller.abort(); return handle; };
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => assert.fail()), errorCode('windows_native_cancelled'));
  assert.deepEqual(h.calls.filter(row => row[0] === 'close').map(row => row[1]), [5n, 4n, 6n]); lease.close();
});
test('root handle close ambiguity is attempted once and refuses future callbacks', async () => {
  const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx); h.closeFault = true;
  assert.throws(() => lease.close(), errorCode('windows_native_close_unknown')); const count = h.calls.length;
  lease.close(); assert.equal(h.calls.length, count);
  await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => assert.fail()), errorCode('windows_native_poisoned'));
});
for (const kind of ['wrongPath', 'reparse', 'badAcl']) {
  test(`root admission refuses ${kind} and joins opened handles`, () => {
    const h = fakeApi(); h[kind] = true;
    assert.throws(() => WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', context()), errorCode('windows_native_untrusted'));
    assert.equal(h.calls.filter(row => row[0] === 'open').length, h.calls.filter(row => row[0] === 'close').length);
  });
}
for (const kind of ['badSize', 'badLinks', 'reparse', 'badAcl', 'wrongPath']) {
  test(`lease-file admission refuses ${kind} before callback`, async () => {
    const h = fakeApi(), ctx = context(), lease = WindowsNativeLease.open(h.api, 'C:\\synthetic\\root', ctx); h[kind] = true;
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'valid', ctx, async () => assert.fail()), errorCode('windows_native_untrusted'));
    assert.equal(h.calls.filter(row => row[0] === 'close').length, 1); h[kind] = false; lease.close();
  });
}

const windows = process.platform === 'win32' && process.arch === 'x64';
const workspace = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const artifactRoot = path.join(workspace, '.artifacts', 'developer-toolchain-20261020');
async function temporary() { await fs.mkdir(artifactRoot, { recursive: true }); return fs.mkdtemp(path.join(artifactRoot, 'win-lease-test-')); }
async function cleanup(directory) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), artifactRoot); assert.match(path.basename(resolved), /^win-lease-test-/);
  await fs.rm(resolved, { recursive: true, force: true });
}
test('unsupported operating systems refuse before Koffi/native evaluation', { skip: windows }, async () => {
  await assert.rejects(openWindowsNativeLease('C:\\synthetic\\root', context()), errorCode('windows_native_unsupported'));
});
test('actual protected fresh Windows root, persistent empty leases and known close are reusable', { skip: !windows }, async () => {
  const directory = await temporary(), root = path.join(directory, 'private'); let lease;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(root, ctx);
    assert.equal(await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => 'safe'), 'safe');
    const before = await fs.readdir(root); assert.equal(before.length, 2);
    for (const name of before) assert.equal((await fs.stat(path.join(root, name))).size, 0);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {});
    assert.deepEqual(await fs.readdir(root), before);
    const cancelled = context();
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', cancelled, async () => {
      cancelled.controller.abort('private reason');
    }), errorCode('windows_native_cancelled'));
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', context(), async () => {});
    lease.close(); lease = await openWindowsNativeLease(root, ctx);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {});
  } finally { lease?.close(); await cleanup(directory); }
});
test('actual inherited/untrusted DACL and reparse roots refuse without changing existing contents', { skip: !windows }, async () => {
  const directory = await temporary();
  try {
    const inherited = path.join(directory, 'inherited'); await fs.mkdir(inherited); await fs.writeFile(path.join(inherited, 'retained'), 'synthetic');
    await assert.rejects(openWindowsNativeLease(inherited, context()), errorCode('windows_native_untrusted'));
    assert.equal(await fs.readFile(path.join(inherited, 'retained'), 'utf8'), 'synthetic');
    const target = path.join(directory, 'target'), junction = path.join(directory, 'junction'); await fs.mkdir(target);
    await fs.symlink(target, junction, 'junction');
    await assert.rejects(openWindowsNativeLease(junction, context()), errorCode('windows_native_untrusted'));
    assert.deepEqual(await fs.readdir(target), []);
    const privateRoot = path.join(directory, 'private'); const lease = await openWindowsNativeLease(privateRoot, context()); lease.close();
    await promisify(execFile)('C:\\Windows\\System32\\icacls.exe', [privateRoot, '/grant', '*S-1-1-0:(OI)(CI)F'], { windowsHide: true, timeout: 5000, maxBuffer: 8192 });
    await assert.rejects(openWindowsNativeLease(privateRoot, context()), errorCode('windows_native_untrusted'));
  } finally { await cleanup(directory); }
});
test('actual nonempty, multiply-linked and directory lease entries refuse before work', { skip: !windows }, async () => {
  const directory = await temporary(), root = path.join(directory, 'private'); let lease;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(root, ctx);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {}); lease.close(); lease = undefined;
    const store = path.join(root, 'store-windows-credential-manager.lease'); await fs.writeFile(store, 'x');
    lease = await openWindowsNativeLease(root, ctx);
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => assert.fail()), errorCode('windows_native_untrusted')); lease.close(); lease = undefined;
    await fs.writeFile(store, ''); await fs.link(store, path.join(directory, 'other-link'));
    lease = await openWindowsNativeLease(root, ctx);
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => assert.fail()), errorCode('windows_native_untrusted')); lease.close(); lease = undefined;
    await fs.unlink(path.join(directory, 'other-link')); await fs.unlink(store); await fs.mkdir(store);
    lease = await openWindowsNativeLease(root, ctx);
    await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => assert.fail()));
  } finally { lease?.close(); await cleanup(directory); }
});

async function scopedChild(source, message = 'HELD\n') {
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source], { cwd: fileURLToPath(new URL('..', import.meta.url)), windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', stderr = ''; child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', value => { output += value; assert.ok(output.length <= 128); });
  child.stderr.on('data', value => { stderr += value; assert.ok(stderr.length <= 8192); });
  const exited = once(child, 'exit');
  const limit = setTimeout(() => child.kill(), 15000);
  try {
    await Promise.race([new Promise(resolve => child.stdout.on('data', () => { if (output === message) resolve(); })), exited.then(() => { throw new Error('Synthetic lease owner exited before admission: ' + stderr); })]);
  } catch (error) { child.kill(); await exited; clearTimeout(limit); throw error; }
  return { child, exited, finish: async killed => { if (killed) child.kill(); else child.stdin.end(); await exited; clearTimeout(limit); } };
}
async function owner(root) {
  const module = pathToFileURL(fileURLToPath(new URL('../src/windows-native-lease.ts', import.meta.url))).href;
  return scopedChild(`import {openWindowsNativeLease,WINDOWS_NATIVE_STORE_ID} from ${JSON.stringify(module)};
    const context={signal:new AbortController().signal,budget:{assertActive(){}}};
    const lease=await openWindowsNativeLease(${JSON.stringify(root)},context);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID,'held',context,async()=>{
      process.stdout.write('HELD\\n'); process.stdin.resume(); await new Promise(resolve=>process.stdin.once('end',resolve));
    }); lease.close();`);
}
test('actual child owners exclude same/different profiles; process death releases without stale-file deletion', { skip: !windows }, async () => {
  const directory = await temporary(), root = path.join(directory, 'private'); let lease, child;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(root, ctx); child = await owner(root);
    for (const name of ['held', 'different']) await assert.rejects(lease.runExclusive(WINDOWS_NATIVE_STORE_ID, name, ctx, async () => assert.fail()), errorCode('windows_native_busy'));
    const before = await fs.readdir(root); await child.finish(true); child = undefined;
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'held', ctx, async () => {});
    assert.deepEqual(await fs.readdir(root), before);
    child = await owner(root); await child.finish(false); child = undefined;
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'held', ctx, async () => {});
  } finally { if (child) await child.finish(true); lease?.close(); await cleanup(directory); }
});
test('loader diagnostic/code-loading overrides refuse before native loading and never print values', { skip: !windows }, async () => {
  const module = pathToFileURL(fileURLToPath(new URL('../src/windows-native-api.ts', import.meta.url))).href;
  for (const name of ['DEBUG_CALLS', 'DEBUG_ASYNC', 'RANDOMIZE_MEMORY', 'DUMP_CALLS', 'LOG_TIMES', 'LOG_DEBUG', 'OVERRIDE_CORES', 'KOFFI_UNREVIEWED', 'NODE_PATH']) {
    const canary = 'native_environment_canary';
    const result = await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
      `import {createWindowsLeaseApi} from ${JSON.stringify(module)}; try{await createWindowsLeaseApi();process.exitCode=1;}catch(e){if(e.code!=='windows_native_environment')throw e;console.log('REFUSED');}`],
    { cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env, [name]: canary }, windowsHide: true, timeout: 10000, maxBuffer: 8192 });
    assert.equal(result.stdout.trim(), 'REFUSED'); assert.equal(result.stderr, ''); assert.ok(!JSON.stringify(result).includes(canary));
  }
});
for (const fault of ['facts', 'descriptor-free']) {
  test(`isolated raw FFI ${fault} failure is fixed/poisoned and acquired handles join before owner exit`, { skip: !windows }, async () => {
    const directory = await temporary(), root = path.join(directory, 'private'); let lease, child;
    try {
      const ctx = context(); lease = await openWindowsNativeLease(root, ctx);
      const module = pathToFileURL(fileURLToPath(new URL('../src/windows-native-api.ts', import.meta.url))).href;
      const source = `import assert from 'node:assert/strict'; import {createRequire} from 'node:module';
        import {createWindowsLeaseApi} from ${JSON.stringify(module)};
        const require=createRequire(import.meta.url), koffi=require('koffi'), original=koffi.load;
        let enabled=false;
        koffi.load=(filename)=>{const library=original(filename);return {func:(definition)=>{
          const fn=library.func(definition);
          if(${JSON.stringify(fault)}==='facts'&&definition.includes('GetFileType'))return (...args)=>{
            if(enabled)throw new Error('ffi_raw_canary'); return fn(...args);};
          if(${JSON.stringify(fault)}==='descriptor-free'&&definition.includes('LocalFree'))return (...args)=>{
            if(enabled){enabled=false;fn(...args);throw new Error('ffi_raw_canary');}return fn(...args);};
          return fn;}};};
        const api=await createWindowsLeaseApi();
        let handle;if(${JSON.stringify(fault)}==='facts')handle=api.openDirectory(${JSON.stringify(root)});
        enabled=true;try{
          if(${JSON.stringify(fault)}==='facts')api.facts(handle);
          else api.openLease(${JSON.stringify(path.join(root, 'store-windows-credential-manager.lease'))});
          assert.fail('fault was not refused');
        }catch(e){assert.equal(e.code,${JSON.stringify(fault === 'facts' ? 'windows_native_unavailable' : 'windows_native_close_unknown')});
          assert.ok(!String(e).includes('ffi_raw_canary'));assert.equal(e.cause,undefined);}
        if(handle)api.close(handle);
        assert.throws(()=>api.assertHealthy(),e=>e.code==='windows_native_poisoned');
        process.stdout.write('REFUSED\\n');process.stdin.resume();await new Promise(resolve=>process.stdin.once('end',resolve));`;
      child = await scopedChild(source, 'REFUSED\n');
      // Child is still alive. Acquisition therefore proves joined cleanup,
      // rather than relying on Windows closing handles at process termination.
      await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {});
      await child.finish(false); child = undefined;
    } finally { if (child) await child.finish(true); lease?.close(); await cleanup(directory); }
  });
}
test('unexpected post-native startup failure poisons the next factory without retrying unknown resource cleanup', { skip: !windows }, async () => {
  const module = pathToFileURL(fileURLToPath(new URL('../src/windows-native-api.ts', import.meta.url))).href;
  const source = `import assert from 'node:assert/strict';import {createRequire} from 'node:module';
    import {createWindowsLeaseApi} from ${JSON.stringify(module)};
    const require=createRequire(import.meta.url),koffi=require('koffi'),original=koffi.load;
    let attempts=0;
    koffi.load=filename=>{const library=original(filename);return {func:definition=>{
      const fn=library.func(definition);
      if(definition.includes('OpenProcessToken'))return (...args)=>{
        attempts++;assert.notEqual(fn(...args),0);throw new Error('startup_raw_canary');};return fn;}};};
    await assert.rejects(createWindowsLeaseApi(),e=>{
      assert.equal(e.code,'windows_native_unavailable');assert.equal(e.cause,undefined);
      assert.ok(!String(e).includes('startup_raw_canary'));return true;});
    await assert.rejects(createWindowsLeaseApi(),e=>e.code==='windows_native_poisoned');
    assert.equal(attempts,1);console.log('REFUSED');
    // The isolated process now exits: Windows owns release of the unknown
    // captured token. The fixture never guesses or closes a numeric handle.
  `;
  const result = await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source],
    { cwd: fileURLToPath(new URL('..', import.meta.url)), windowsHide: true, timeout: 10000, maxBuffer: 8192 });
  assert.equal(result.stdout.trim(), 'REFUSED'); assert.equal(result.stderr, '');
});
