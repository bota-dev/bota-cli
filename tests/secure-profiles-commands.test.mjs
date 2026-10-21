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
    const service={enrollSecureProfile:operation,inspectSecureProfile:operation,removeSecureProfile:operation,recoverSecureProfile:operation};
    const program=new Command('bota').option('--api-url <url>');
    registerSecureProfiles(program.command('auth'),program,service);
    let code;try{await program.parseAsync(['node','bota','--api-url','https://api.example.invalid','auth','secure-profiles',action,'fixture',...(action==='add'?['--from-env']:[])]);}catch(error){code=error.code;}
    console.log(JSON.stringify({code,forwarded,writes,joined:process.listenerCount('SIGINT')===before.SIGINT&&process.listenerCount('SIGTERM')===before.SIGTERM}));`;
  for (const signal of ['SIGINT', 'SIGTERM']) for (const action of ['add', 'show', 'remove', 'recover']) {
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
