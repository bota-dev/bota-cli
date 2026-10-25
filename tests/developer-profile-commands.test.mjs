import assert from 'node:assert/strict';
import test from 'node:test';
import { Command } from 'commander';
import { registerAuth } from '../src/commands/auth.ts';
import { registerDeveloperProfiles, chooseDeveloperScopes, developerCommandBoundary, publishDeveloperMetadata } from '../src/commands/developer-profiles.ts';
import { registerMcp } from '../src/commands/mcp.ts';
import { withCommandAuth, bindDeveloperMcpRequestAuth } from '../src/invocation-auth.ts';
import { DeveloperProfileError, developerProfileFailure } from '../src/developer-profile-error.ts';
const deployment = { version: 1, issuer: 'https://issuer.example.test', endpoints: { authorization: 'https://issuer.example.test/oauth/authorize', token: 'https://issuer.example.test/oauth/token', revocation: 'https://issuer.example.test/oauth/revoke' },
  resources: { rest: 'https://rest.example.test/v1', mcp: 'https://mcp.example.test/mcp' }, client: { clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } };
const profile = { name: 'work', state: 'ready', attemptId: null, familyKey: { storeId: 'portable', issuer: deployment.issuer, clientId: 'registered-cli', familyId: '00000000-0000-4000-8000-000000000001' }, pendingFamilyKey: null, deployment };
const refused = code => error => { assert.equal(developerProfileFailure(error)?.code, code); return true; };
function setup(writer = async (channel, text) => { (channel === 'stdout' ? console.log : console.error)(text); }) { const calls = [], service = { configuration() { calls.push('configuration'); return deployment; },
  async login(name, selection, options) { calls.push({ op: 'login', name, selection, options }); return { ...profile, name }; },
  async logout(name, options) { calls.push({ op: 'logout', name, options }); return { ...profile, name, state: 'removed' }; },
  async inspect(name, options) { calls.push({ op: 'inspect', name, options }); return { ...profile, name }; },
  async list(options) { calls.push({ op: 'list', options }); return [profile]; },
  async recover(name, options) { calls.push({ op: 'recover', name, options }); return { ...profile, name }; },
  async status(name, options) { calls.push({ op: 'status', name, options }); return { profile: name, credential_type: 'developer_delegation', projectId: 'proj_fixture' }; },
  async run(name, kind, action, options, expected) { calls.push({ op: 'run', name, kind, options, expected }); return action(); },
  async pin(name, options) { calls.push({ op: 'pin', name, options }); return profile.familyKey; } };
  const program = new Command().exitOverride().option('--developer-profile <name>').option('--developer-deployment <name>').option('--profile <name>').option('--secure-profile <name>').option('--api-url <url>').option('--dashboard-url <url>').option('--json');
  const auth = registerAuth(program, service, writer); registerDeveloperProfiles(auth, program, service, writer); return { program, calls, service }; }
async function silence(work) { const original = console.log, errors = console.error, output = [], stderr = [];
  console.log = value => output.push(value); console.error = value => stderr.push(value);
  try { return { value: await work(), output, stderr }; } finally { console.log = original; console.error = errors; } }

test('no-key login uses explicit selected scopes and no credential argument', async () => {
  const f = setup(); const result = await silence(() => f.program.parseAsync(['node', 'bota', '--json', 'auth', 'login', '--name', 'work', '--scope', 'devices:read']));
  const call = f.calls.find(value => value.op === 'login'); assert.equal(call.name, 'work'); assert.deepEqual(call.selection.scopes, ['devices:read']);
  assert.deepEqual(call.selection.grantResourceKinds, ['rest', 'mcp']); assert.equal(JSON.parse(result.output[0]).credential_type, 'developer_delegation');
  assert.doesNotMatch(result.output.join(''), /credentialId|storeId|attemptId|refreshToken/);
});
test('missing production config is checked before any interactive scope prompt', async () => {
  const f = setup(); f.service.configuration = () => { throw new DeveloperProfileError('developer_configuration_unavailable'); };
  await assert.rejects(f.program.parseAsync(['node', 'bota', 'auth', 'login']), refused('developer_configuration_unavailable'));
  assert.equal(f.calls.length, 0);
});

test('DEV login guidance retains the explicit deployment for future selection and logout', async () => {
  const output = [], f = setup(async (channel, text) => output.push({ channel, text }));
  await f.program.parseAsync(['node', 'bota', '--developer-deployment', 'dev', 'auth', 'login', '--name', 'work', '--identity-only']);
  const guidance = output.find(value => value.channel === 'stderr').text;
  assert.match(guidance, /--developer-deployment dev --developer-profile work/);
  assert.match(guidance, /bota --developer-deployment dev auth developer-profiles logout work/);
  assert.deepEqual(f.calls.find(value => value.op === 'login').selection.grantResourceKinds, ['rest', 'mcp']);
});

test('legacy key login rejects an explicit developer deployment before config writes', async () => {
  const f = setup();
  await assert.rejects(f.program.parseAsync(['node', 'bota', '--developer-deployment', 'dev', 'auth', 'login', 'PRIVATE_CANARY']), refused('developer_profile_invalid'));
  assert.deepEqual(f.calls, []);
});
test('scope choice is explicit, bounded and never accepts arbitrary secret-looking input', async () => {
  const signal = new AbortController().signal;
  assert.deepEqual(await chooseDeveloperScopes({}, signal, async () => '2,3'), ['devices:read', 'recordings:read']);
  assert.deepEqual(await chooseDeveloperScopes({}, signal, async () => '0'), []);
  await assert.rejects(chooseDeveloperScopes({}, signal, async () => 'PRIVATE_KEY_CANARY'), refused('developer_login_scope_required'));
  await assert.rejects(chooseDeveloperScopes({ scope: ['devices:read'], identityOnly: true }, signal), refused('developer_profile_invalid'));
});
test('developer logout uses only the explicit session selector', async () => {
  const f = setup(); await silence(() => f.program.parseAsync(['node', 'bota', '--developer-profile', 'work', 'auth', 'logout']));
  assert.equal(f.calls[0].op, 'logout'); assert.equal(f.calls[0].name, 'work');
});
test('metadata commands project only safe fields and join the service before output', async () => {
  for (const command of [['list'], ['show', 'work'], ['recover', 'work'], ['logout', 'work']]) {
    const f = setup(), result = await silence(() => f.program.parseAsync(['node', 'bota', 'auth', 'developer-profiles', ...command]));
    assert.equal(f.calls.length, 1); assert.doesNotMatch(result.output.join(''), /familyKey|pendingFamilyKey|attemptId|storeId/);
  }
});

test('metadata command awaits the writer and reports a fixed failure before declaring success', async () => {
  let release, entered, settled = false;
  const writing = new Promise(resolve => { entered = resolve; }), held = new Promise(resolve => { release = resolve; });
  const f = setup(async () => { entered(); await held; throw Error('PRIVATE_STDOUT_FAILURE'); });
  const running = f.program.parseAsync(['node', 'bota', 'auth', 'developer-profiles', 'show', 'work']).finally(() => { settled = true; });
  void running.catch(() => {}); await writing; await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  release(); await assert.rejects(running, refused('developer_operation_failed')); assert.equal(f.calls[0].op, 'inspect');
});

test('status metadata publication rechecks authoritative expiry after joined output', async () => {
  const original = Date.now, expiry = Math.floor(original() / 1000) + 1, signal = new AbortController().signal;
  try { await assert.rejects(publishDeveloperMetadata({ expiresAtSeconds: expiry }, signal, async () => { Date.now = () => expiry * 1000; }, expiry), refused('developer_deadline')); }
  finally { Date.now = original; }
});

test('pending metadata acknowledgement cancels without publishing success after a late callback', async () => {
  const controller = new AbortController(); let enter, release, ready = false;
  const entered = new Promise(resolve => { enter = resolve; }), held = new Promise(resolve => { release = resolve; });
  const running = publishDeveloperMetadata({ state: 'ready' }, controller.signal, async () => { enter(); await held; }).then(() => { ready = true; });
  void running.catch(() => {}); await entered; controller.abort('PRIVATE_REASON');
  await assert.rejects(running, error => { refused('developer_cancelled')(error);
    assert.equal(developerProfileFailure(error).operation_may_have_executed, true); return true; });
  release(); await new Promise(resolve => setImmediate(resolve)); assert.equal(ready, false);
});

test('authoritative metadata expiry withdraws a stalled acknowledgement before its late return', async () => {
  const original = Date.now, expiry = Math.floor(original() / 1000) + 10; let enter, release;
  const entered = new Promise(resolve => { enter = resolve; }), held = new Promise(resolve => { release = resolve; });
  const running = publishDeveloperMetadata({ expiresAtSeconds: expiry }, new AbortController().signal, async () => { enter(); await held; }, expiry);
  void running.catch(() => {});
  try { await entered; Date.now = () => expiry * 1000; await assert.rejects(running, error => {
    refused('developer_deadline')(error); assert.equal(developerProfileFailure(error).operation_may_have_executed, true); return true;
  }); }
  finally { Date.now = original; release(); }
});

test('login guidance acknowledgement cannot outlive cancellation or trigger another enrollment', async () => {
  const previous = process.exitCode; let enter, release, ready = false;
  const entered = new Promise(resolve => { enter = resolve; }), held = new Promise(resolve => { release = resolve; });
  const output = [], f = setup(async (channel, text) => { output.push({ channel, text }); if (channel === 'stderr') { enter(); await held; } });
  const running = f.program.parseAsync(['node', 'bota', 'auth', 'login', '--name', 'work', '--identity-only']).then(() => { ready = true; });
  void running.catch(() => {});
  try {
    await entered; process.emit('SIGINT'); await assert.rejects(running, error => { refused('developer_cancelled')(error);
      assert.equal(developerProfileFailure(error).operation_may_have_executed, true); return true; });
    release(); await new Promise(resolve => setImmediate(resolve)); assert.equal(ready, false); assert.equal(process.exitCode, 130);
    assert.equal(f.calls.filter(value => value.op === 'login').length, 1); assert.equal(output.length, 2);
  } finally { process.exitCode = previous; release(); }
});
test('CLI wrapper selects the REST service without consulting an API-key profile', async () => {
  const f = setup(); f.program.parseOptions(['--developer-profile', 'work']);
  assert.equal(await withCommandAuth(f.program, async value => value + 1, f.service)(4), 5);
  assert.equal(f.calls[0].op, 'run'); assert.equal(f.calls[0].kind, 'rest');
});
test('mixed profile or URL authority refuses before service access', async () => {
  for (const flag of ['--profile', '--secure-profile', '--api-url', '--dashboard-url']) {
    const f = setup(); f.program.parseOptions(['--developer-profile', 'work', flag, 'PRIVATE_CANARY']);
    await assert.rejects(withCommandAuth(f.program, async () => {}, f.service)(), refused('developer_profile_invalid'));
    assert.equal(f.calls.length, 0);
  }
});
test('MCP startup pins metadata once and each request reacquires exact MCP authority', async () => {
  const f = setup(), authenticate = await bindDeveloperMcpRequestAuth(f.service)('work');
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].op, 'pin');
  for (let index = 0; index < 2; index++) await authenticate(new AbortController().signal, async () => index);
  const actions = f.calls.filter(value => value.op === 'run'); assert.equal(actions.length, 2);
  assert.ok(actions.every(value => value.kind === 'mcp' && value.expected === profile.familyKey));
});
test('selected developer MCP refuses legacy inventory before any profile or key access', async () => {
  const f = setup(); let calls = 0;
  registerMcp(f.program, { async createRequestAuth() { calls++; throw Error('PRIVATE_KEY_ACCESS'); }, async createDeveloperRequestAuth() { calls++; throw Error('PRIVATE_STORE_ACCESS'); } });
  await assert.rejects(f.program.parseAsync(['node', 'bota', '--developer-profile', 'work', 'mcp']), refused('developer_mcp_hosted_required'));
  assert.equal(calls, 0);
});

test('public CLI wrapper forwards interrupts, joins the action and removes its listeners', async () => {
  const previous = process.exitCode;
  try {
    for (const [signal, exitCode] of [['SIGINT', 130], ['SIGTERM', 143]]) {
      const f = setup(), beforeInt = process.listenerCount('SIGINT'), beforeTerm = process.listenerCount('SIGTERM'); let settled = false, activeSignal, release;
      const held = new Promise(resolve => { release = resolve; });
      f.program.parseOptions(['--developer-profile', 'work']);
      f.service.run = async (_name, _kind, action, options) => { activeSignal = options.signal; await held;
        if (activeSignal.aborted) throw new DeveloperProfileError('developer_cancelled'); return action(); };
      const running = withCommandAuth(f.program, async () => { throw Error('PRIVATE_ACTION_MUST_NOT_START'); }, f.service)().finally(() => { settled = true; });
      void running.catch(() => {}); assert.equal(activeSignal.aborted, false); process.emit(signal);
      await new Promise(resolve => setImmediate(resolve)); assert.equal(activeSignal.aborted, true); assert.equal(settled, false);
      release(); await assert.rejects(running, refused('developer_cancelled')); assert.equal(process.exitCode, exitCode);
      assert.equal(process.listenerCount('SIGINT'), beforeInt); assert.equal(process.listenerCount('SIGTERM'), beforeTerm);
    }
  } finally { process.exitCode = previous; }
});

test('login management boundary preserves SIGTERM status while joining cancellation cleanup', async () => {
  const previous = process.exitCode, beforeInt = process.listenerCount('SIGINT'), beforeTerm = process.listenerCount('SIGTERM'); let release, entered;
  const started = new Promise(resolve => { entered = resolve; }), held = new Promise(resolve => { release = resolve; }); let settled = false;
  try {
    const running = developerCommandBoundary(async signal => { entered(); await held; assert.equal(signal.aborted, true); throw new DeveloperProfileError('developer_cancelled'); }).finally(() => { settled = true; });
    void running.catch(() => {}); await started; process.emit('SIGTERM'); await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
    release(); await assert.rejects(running, refused('developer_cancelled')); assert.equal(process.exitCode, 143);
    assert.equal(process.listenerCount('SIGINT'), beforeInt); assert.equal(process.listenerCount('SIGTERM'), beforeTerm);
  } finally { process.exitCode = previous; }
});
