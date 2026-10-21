import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { Command } from 'commander';
import { registerSecureProfiles, sanitizeSecureProfileCommandError, SecureProfileCommandError } from '../src/commands/secure-profiles.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';
import { WindowsNativeError } from '../src/windows-native-api.ts';

const key = 'rk_COMMAND_SECRET_CANARY';
const childEnvironment = () => Object.fromEntries(['SystemRoot', 'WINDIR', 'ComSpec', 'PATH', 'PATHEXT', 'TEMP', 'TMP']
  .filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
const record = Object.freeze({ format_version: 2, name: 'work', store_id: 'windows-credential-manager',
  profile_id: 'PROFILE_REFERENCE_CANARY', credential_ref: 'CREDENTIAL_REFERENCE_CANARY',
  api_origin: 'https://api.example.invalid', project_id: 'project\x1b\u202e', organization_id: 'organization\u0085', key_id: 'key_id_opaque',
  allow_http_loopback: false, state: 'ready', bearer: key });
class Input extends EventEmitter {
  constructor() { super(); this.isTTY = false; this.paused = true; }
  isPaused() { return this.paused; }
  pause() { this.paused = true; return this; }
  resume() { this.paused = false; queueMicrotask(() => { this.emit('data', Buffer.from(`${key}\n`)); this.emit('end'); }); return this; }
}
const context = () => ({ signal: new AbortController().signal, budget: { assertActive() {} } });
function fixture(overrides = {}, input = {}) {
  const calls = [];
  const service = {
    async enrollSecureProfile(request) { calls.push(['enroll', request]); calls.push(['key', await request.readKey(context())]); return record; },
    async migrateEnvironmentProfile(request) { calls.push(['migrate', request]); calls.push(['key', await request.readKey(context())]); return record; },
    async listSecureProfiles() { calls.push(['list']); return [{ name: record.name, snapshot: { record, journal: null } }]; },
    async inspectSecureProfile(name) { calls.push(['show', name]); return { record, journal: null, revision: 'REVISION_CANARY' }; },
    async removeSecureProfile(name) { calls.push(['remove', name]); return { ...record, state: 'removed' }; },
    async recoverSecureProfile(name) { calls.push(['recover', name]); return record; }, ...overrides,
  };
  const program = new Command('bota').exitOverride().option('--api-url <url>').option('--json');
  const auth = program.command('auth');
  registerSecureProfiles(auth, program, service, { input: new Input(), ...input });
  const overrideExits = command => { command.exitOverride(); for (const child of command.commands) overrideExits(child); };
  overrideExits(program);
  return { program, calls };
}
async function parse(fixture, args) {
  const stdout = [], stderr = [], oldLog = console.log, oldError = console.error;
  console.log = (...args) => stdout.push(args.join(' ')); console.error = (...args) => stderr.push(args.join(' '));
  let error;
  try { await fixture.program.parseAsync(['node', 'bota', ...args]); } catch (caught) { error = caught; }
  finally { console.log = oldLog; console.error = oldError; }
  return { stdout: stdout.join('\n'), stderr: stderr.join('\n'), error };
}
const add = (...args) => ['--api-url', record.api_origin, 'auth', 'secure-profiles', 'add', 'work', ...args];
const migrate = (...args) => ['--api-url', record.api_origin, 'auth', 'secure-profiles', 'migrate', 'work', ...args];

test('secure enrollment explicitly selects one input mode and keeps key acquisition deferred to the provider', async () => {
  const f = fixture(); const result = await parse(f, add('--key-stdin'));
  assert.equal(result.error, undefined); assert.equal(result.stderr, '');
  assert.equal(f.calls[0][0], 'enroll'); assert.equal(f.calls[0][1].name, 'work');
  assert.equal(f.calls[0][1].apiOrigin, record.api_origin); assert.equal(Object.hasOwn(f.calls[0][1], 'key'), false);
  assert.deepEqual(f.calls[1], ['key', key]);
  const shown = JSON.parse(result.stdout);
  assert.equal(shown.credential_source, 'windows-credential-manager'); assert.equal(shown.key_id, record.key_id);
  assert.doesNotMatch(result.stdout, /SECRET_CANARY|REFERENCE_CANARY|REVISION_CANARY|bearer|profile_id|credential_ref/);
  assert.ok(result.stdout.includes('\\u202e')); assert.ok(result.stdout.includes('\\u0085')); assert.doesNotMatch(result.stdout, /[\x1b\u0085\u202e]/);
});

test('missing API origin and missing/conflicting source selections refuse before provider and secret input', async () => {
  for (const args of [add(), add('--key-stdin', '--from-env'), add('--key-stdin', '--key-prompt'), add('--from-env', '--key-prompt'),
    ['auth', 'secure-profiles', 'add', 'work', '--key-stdin']]) {
    const f = fixture(); const result = await parse(f, args);
    assert.ok(result.error instanceof SecureProfileCommandError); assert.equal(f.calls.length, 0); assert.equal(result.stdout, '');
    assert.doesNotMatch(String(result.error), /CANARY/);
  }
});

test('environment key enrollment is explicit and never selected as a fallback from an invalid pipe', async () => {
  const f = fixture({}, { env: { BOTA_API_KEY: key } });
  assert.equal((await parse(f, add('--from-env', '--allow-http-loopback'))).error, undefined);
  assert.equal(f.calls[0][1].allowHttpLoopback, true); assert.deepEqual(f.calls[1], ['key', key]);
  const invalid = new Input(); invalid.resume = function () { queueMicrotask(() => this.emit('end')); return this; };
  const g = fixture({}, { input: invalid, env: { BOTA_API_KEY: key } });
  const result = await parse(g, add('--key-stdin'));
  assert.equal(result.error.code, 'secure_key_invalid'); assert.equal(g.calls.length, 1); assert.equal(result.stdout, '');
});

test('unsupported or colliding provider can refuse before the key reader starts', async () => {
  for (const error of [new WindowsNativeError('windows_native_unsupported'), new NativeProfileTransactionError('profile_exists')]) {
    const input = new Input(); input.resume = () => assert.fail('Provider must be able to reject before reading a key');
    const f = fixture({ async enrollSecureProfile() { throw error; } }, { input });
    const result = await parse(f, add('--key-stdin'));
    assert.equal(result.error.code, error.code); assert.equal(result.stdout, '');
  }
});

test('migration explicitly reads only the environment through a deferred reader and projects safe returned metadata', async () => {
  const input = new Input(); input.isTTY = true;
  input.resume = () => assert.fail('Migration must never consume stdin');
  input.setRawMode = () => assert.fail('Migration must never prompt');
  const output = { write() { assert.fail('Migration must not write a prompt'); } };
  const f = fixture({}, { input, output, env: { BOTA_API_KEY: key } });
  const result = await parse(f, migrate('--from-env', '--allow-http-loopback'));
  assert.equal(result.error, undefined); assert.equal(result.stderr, '');
  assert.equal(f.calls[0][0], 'migrate');
  const request = f.calls[0][1];
  assert.deepEqual(Object.keys(request).sort(), ['allowHttpLoopback', 'apiOrigin', 'name', 'readKey']);
  assert.equal(request.name, 'work'); assert.equal(request.apiOrigin, record.api_origin); assert.equal(request.allowHttpLoopback, true);
  assert.deepEqual(f.calls[1], ['key', key]);
  assert.equal(JSON.parse(result.stdout).state, 'ready');
  assert.doesNotMatch(result.stdout, /CANARY|profile_id|credential_ref|revision|transaction_id|bearer/);
  assert.ok(result.stdout.includes('\\u202e')); assert.ok(result.stdout.includes('\\u0085'));
});

test('migration requires explicit API origin/from-env and privately refuses key arguments or other input modes', async () => {
  for (const args of [migrate(), migrate('--key-stdin'), migrate('--key-prompt'), migrate('--from-env', '--key-stdin'),
    migrate('--from-env', '--key-prompt'), migrate('--from-env', key), migrate('--from-env', `--${key}`),
    ['auth', 'secure-profiles', 'migrate', 'work', '--from-env']]) {
    const f = fixture({}, { env: { BOTA_API_KEY: key } });
    const result = await parse(f, args);
    assert.ok(result.error); assert.equal(f.calls.length, 0); assert.equal(result.stdout, '');
    assert.doesNotMatch(result.stderr, /CANARY/);
    if (!(result.error instanceof SecureProfileCommandError)) assert.match(result.stderr, /Invalid secure profile command/);
  }
});

test('migration service can refuse missing/mismatched source or occupied native target before acquiring an environment key', async () => {
  const env = new Proxy({}, { getOwnPropertyDescriptor() { assert.fail('Rejected migration must not inspect an environment credential'); } });
  for (const code of ['profile_not_found', 'profile_origin_mismatch', 'profile_identity_mismatch', 'profile_exists']) {
    let requests = 0;
    const f = fixture({ async migrateEnvironmentProfile(_input, options) {
      requests++; assert.ok(options.signal instanceof AbortSignal); throw new NativeProfileTransactionError(code);
    } }, { env });
    const result = await parse(f, migrate('--from-env'));
    assert.equal(requests, 1); assert.equal(result.error.code, code); assert.equal(result.stdout, '');
    assert.doesNotMatch(String(result.error), /CANARY/);
  }
});

test('failed migration never prints successful metadata or arbitrary source/key details', async () => {
  for (const error of [Error(key), new NativeProfileTransactionError('profile_identity_mismatch'), new NativeProfileTransactionError('profile_state_unknown', true)]) {
    const f = fixture({ async migrateEnvironmentProfile(request, options) {
      assert.equal(await request.readKey({ signal: options.signal, budget: { assertActive() {} } }), key); throw error;
    } }, { env: { BOTA_API_KEY: key } });
    const result = await parse(f, migrate('--from-env'));
    assert.ok(result.error); assert.equal(result.stdout, ''); assert.equal(result.error.cause, undefined);
    assert.doesNotMatch(String(result.error), /CANARY/);
  }
});

test('show includes safe ready or pending state without credential references and does not acquire any key', async () => {
  for (const snapshot of [null, { record, journal: null }, { record: null, journal: { desired: record, operation: 'enroll', phase: 'intent' } }]) {
    const f = fixture({ async inspectSecureProfile() { return snapshot; } });
    const result = await parse(f, ['auth', 'secure-profiles', 'show', 'work']);
    assert.equal(result.error, undefined); const value = JSON.parse(result.stdout);
    if (snapshot === null) assert.deepEqual(value, { name: 'work', state: 'absent' });
    else assert.equal(value.recovery_required, snapshot.journal !== null);
    assert.doesNotMatch(result.stdout, /CANARY|profile_id|credential_ref|revision|transaction_id/);
    assert.equal(f.calls.length, 0);
  }
});

test('metadata-only list sorts ready, pending, disabled and removed projections without key/identity input or internals', async () => {
  const rows = [
    { name: 'a-ready', snapshot: { record: { ...record, name: 'a-ready' }, journal: null } },
    { name: 'b-pending', snapshot: { record: null, journal: { operation: 'enroll', phase: 'intent', transaction_id: 'TRANSACTION_CANARY',
      desired: { ...record, name: 'b-pending' } } } },
    { name: 'c-disabled', snapshot: { record: { ...record, name: 'c-disabled', state: 'disabled' }, journal: { operation: 'remove', phase: 'intent',
      transaction_id: 'TRANSACTION_CANARY', desired: { ...record, name: 'c-disabled', state: 'disabled' } } } },
    { name: 'd-removed', snapshot: { record: { ...record, name: 'd-removed', state: 'removed' }, journal: null } },
  ].map(entry => ({ ...entry, snapshot: { ...entry.snapshot, revision: 'REVISION_CANARY' } }));
  const env = new Proxy({}, { getOwnPropertyDescriptor() { assert.fail('List must not inspect credentials'); } });
  const input = new Input(); input.resume = () => assert.fail('List must not read stdin');
  let calls = 0;
  const f = fixture({ async listSecureProfiles(options) { calls++; assert.ok(options.signal instanceof AbortSignal); return [...rows].reverse(); } }, { input, env });
  const result = await parse(f, ['--json', 'auth', 'secure-profiles', 'list']);
  assert.equal(result.error, undefined); assert.equal(result.stderr, ''); assert.equal(calls, 1);
  const output = JSON.parse(result.stdout);
  assert.deepEqual(output.map(entry => entry.name), rows.map(entry => entry.name));
  assert.deepEqual(output.map(entry => entry.state), ['ready', 'ready', 'disabled', 'removed']);
  assert.deepEqual(output.map(entry => entry.recovery_required), [false, true, true, false]);
  assert.equal(output[1].pending_operation, 'enroll'); assert.equal(output[2].pending_operation, 'remove');
  assert.doesNotMatch(result.stdout, /CANARY|profile_id|credential_ref|revision|transaction_id|bearer|journal/);
  assert.ok(result.stdout.includes('\\u202e')); assert.ok(result.stdout.includes('\\u0085'));
  assert.equal(f.calls.length, 0);
});

test('empty list is an empty metadata array and list failures expose no partial output or arbitrary details', async () => {
  const empty = fixture({ async listSecureProfiles() { return []; } });
  const result = await parse(empty, ['auth', 'secure-profiles', 'list']);
  assert.equal(result.error, undefined); assert.deepEqual(JSON.parse(result.stdout), []);
  for (const error of [Error(key), new NativeProfileTransactionError('profile_busy')]) {
    const f = fixture({ async listSecureProfiles() { throw error; } });
    const failure = await parse(f, ['auth', 'secure-profiles', 'list']);
    assert.equal(failure.stdout, ''); assert.ok(failure.error); assert.doesNotMatch(String(failure.error), /CANARY/);
  }
});

test('list accepts no name or secret input flags and keeps parser errors private', async () => {
  for (const extra of [['work'], [key], ['--key-stdin'], ['--key-prompt'], ['--from-env'], [`--${key}`]]) {
    const f = fixture(); const result = await parse(f, ['auth', 'secure-profiles', 'list', ...extra]);
    assert.ok(result.error); assert.equal(result.stdout, ''); assert.equal(f.calls.length, 0);
    assert.match(result.stderr, /Invalid secure profile command/); assert.doesNotMatch(result.stderr, /CANARY/);
  }
});

test('remove and explicit recover invoke only their named service and keep returned internals private', async () => {
  for (const action of ['remove', 'recover']) {
    const f = fixture(); const result = await parse(f, ['auth', 'secure-profiles', action, 'work']);
    assert.equal(result.error, undefined); assert.deepEqual(f.calls, [[action, 'work']]);
    assert.doesNotMatch(result.stdout, /CANARY|profile_id|credential_ref|revision|transaction_id/);
    if (action === 'remove') assert.deepEqual(JSON.parse(result.stdout), { name: 'work', state: 'removed', removed: true });
  }
});

test('unknown flags, extra positional keys, missing arguments and unexpected commands print a fixed private parser error', async () => {
  for (const args of [add('--key-stdin', key), add(`--${key}`), ['auth', 'secure-profiles', key],
    ['auth', 'secure-profiles', 'show'], ['auth', 'secure-profiles', 'remove', 'work', key], ['auth', 'secure-profiles', 'recover', `--${key}`]]) {
    const f = fixture(); const result = await parse(f, args);
    assert.ok(result.error); assert.equal(result.stdout, ''); assert.match(result.stderr, /Invalid secure profile command/);
    assert.doesNotMatch(result.stderr, /CANARY/); assert.equal(f.calls.length, 0);
  }
});

test('arbitrary provider exceptions and hostile error shapes cannot leak secrets through command failures', async () => {
  const accessor = Object.defineProperty({}, 'code', { get() { assert.fail('Error getter must not run'); } });
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { assert.fail('Error proxy must not run'); } });
  for (const error of [Error(key), key, { code: key, message: key }, accessor, proxy]) {
    const f = fixture({ async removeSecureProfile() { throw error; } });
    const result = await parse(f, ['auth', 'secure-profiles', 'remove', 'work']);
    assert.ok(result.error instanceof SecureProfileCommandError); assert.equal(result.error.code, 'secure_profile_failed');
    assert.doesNotMatch(String(result.error), /CANARY/); assert.equal(result.error.cause, undefined);
  }
});

test('known recovery errors retain only fixed safe diagnostics after sanitization', () => {
  const input = new NativeProfileTransactionError('profile_state_unknown', true, true); input.message = key;
  const error = sanitizeSecureProfileCommandError(input);
  assert.notEqual(error, input); assert.equal(error.code, 'profile_state_unknown');
  assert.equal(error.recovery_required, true); assert.equal(error.operation_may_have_executed, true);
  assert.doesNotMatch(String(error), /CANARY/);
});

test('public command boundaries forward SIGINT/SIGTERM and remove listeners before process exit', () => {
  const commandUrl = new URL('../src/commands/secure-profiles.ts', import.meta.url).href;
  const transactionUrl = new URL('../src/native-profile-transaction.ts', import.meta.url).href;
  const script = `import {Command} from 'commander';
    import {registerSecureProfiles} from ${JSON.stringify(commandUrl)};
    import {NativeProfileTransactionError} from ${JSON.stringify(transactionUrl)};
    const signalName=process.argv[1], action=process.argv[2];
    const before={SIGINT:process.listenerCount('SIGINT'),SIGTERM:process.listenerCount('SIGTERM')};
    let forwarded=false,writes=0;
    const operation=async (_request,options)=>{
      forwarded=options.signal instanceof AbortSignal;
      setImmediate(()=>process.emit(signalName));
      await new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new NativeProfileTransactionError('profile_cancelled')),{once:true}));
      writes++; throw Error('Unreachable');
    };
    const service={enrollSecureProfile:operation,migrateEnvironmentProfile:operation,listSecureProfiles:options=>operation(null,options),inspectSecureProfile:operation,removeSecureProfile:operation,recoverSecureProfile:operation};
    const program=new Command('bota').option('--api-url <url>');
    registerSecureProfiles(program.command('auth'),program,service);
    let code;try{await program.parseAsync(['node','bota','--api-url','https://api.example.invalid','auth','secure-profiles',action,...(action==='list'?[]:['fixture']),...(['add','migrate'].includes(action)?['--from-env']:[])]);}catch(error){code=error.code;}
    console.log(JSON.stringify({code,forwarded,writes,joined:process.listenerCount('SIGINT')===before.SIGINT&&process.listenerCount('SIGTERM')===before.SIGTERM}));`;
  for (const signal of ['SIGINT', 'SIGTERM']) for (const action of ['add', 'migrate', 'list', 'show', 'remove', 'recover']) {
    const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script, signal, action],
      { cwd: new URL('..', import.meta.url), env: childEnvironment(), encoding: 'utf8', timeout: 5000, windowsHide: true });
    assert.equal(child.error, undefined); assert.equal(child.status, signal === 'SIGINT' ? 130 : 143);
    assert.deepEqual(JSON.parse(child.stdout), { code: 'profile_cancelled', forwarded: true, writes: 0, joined: true });
    assert.equal(child.stderr, '');
  }
});

test('raw Ctrl-C becomes cancelled with exit130, restores the terminal and never reaches enrollment write', () => {
  const commandUrl = new URL('../src/commands/secure-profiles.ts', import.meta.url).href;
  const script = `import {Command} from 'commander';import {EventEmitter} from 'node:events';
    import {registerSecureProfiles} from ${JSON.stringify(commandUrl)};
    class Input extends EventEmitter{isTTY=true;isRaw=false;readableFlowing=null;paused=true;setRawMode(value){this.isRaw=value;return this;}pause(){this.paused=true;return this;}resume(){this.paused=false;queueMicrotask(()=>this.emit('data',Buffer.from([3])));return this;}}
    class Output extends EventEmitter{isTTY=true;write(_value,done){queueMicrotask(()=>done?.());return true;}}
    const input=new Input(),output=new Output();let writes=0;
    const service={async enrollSecureProfile(request,options){await request.readKey({signal:options.signal,budget:{assertActive(){}}});writes++;throw Error('Unreachable');}};
    const program=new Command('bota').option('--api-url <url>');registerSecureProfiles(program.command('auth'),program,service,{input,output});
    let code;try{await program.parseAsync(['node','bota','--api-url','https://api.example.invalid','auth','secure-profiles','add','fixture','--key-prompt']);}catch(error){code=error.code;}
    console.log(JSON.stringify({code,writes,rawRestored:input.isRaw===false,paused:input.paused,joined:input.listenerCount('data')===0&&output.listenerCount('error')===0}));`;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), env: childEnvironment(), encoding: 'utf8', timeout: 5000, windowsHide: true });
  assert.equal(child.error, undefined); assert.equal(child.status, 130);
  assert.deepEqual(JSON.parse(child.stdout), { code: 'profile_cancelled', writes: 0, rawRestored: true, paused: true, joined: true });
  assert.equal(child.stderr, '');
});
