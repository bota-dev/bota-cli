import assert from 'node:assert/strict';
import test from 'node:test';
import { Command } from 'commander';
import { handleCommandFailure, printError } from '../src/output.ts';
import { BotaApiError } from '../src/client.ts';
import { withInvocationCredential } from '../src/config.ts';
import { createSecureProfileService } from '../src/secure-profiles.ts';
import { NativeProfileTransactions, NativeProfileTransactionError } from '../src/native-profile-transaction.ts';
import { registerEndUsers } from '../src/commands/end-users.ts';
import { registerDevices } from '../src/commands/devices.ts';
import { registerRecordings } from '../src/commands/recordings.ts';
import { registerIntegrations } from '../src/commands/integrations.ts';
import { showAuthStatus } from '../src/commands/auth-status.ts';

const key = 'rk_COMMAND_FAILURE_CANARY', origin = 'https://api.example.invalid';
const identity = { project_id: 'project:synthetic', organization_id: 'organization:synthetic', key_id: 'key:synthetic',
  key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false };
const credential = { apiKey: key, apiOrigin: origin, source: 'store', profile: {}, identity };
function operation() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, context: { signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error(key); } } } };
}
function service(h) {
  const record = { format_version: 2, name: 'work', store_id: 'synthetic', api_origin: origin,
    project_id: identity.project_id, organization_id: identity.organization_id, key_id: identity.key_id,
    allow_http_loopback: false, state: 'ready', profile_id: '00000000-0000-4000-8000-000000000001',
    credential_ref: '00000000-0000-4000-8000-000000000002' };
  return createSecureProfileService({ async createRuntime() {
    const engine = new NativeProfileTransactions({
      lease: { async runExclusive(_store, _name, _context, action) {
        h.events.push('lease-enter'); try { return await action(); } finally { h.events.push('lease-close'); }
      } },
      snapshots: { async load() { return { format_version: 1, revision: '00000000-0000-4000-8000-000000000003', record, journal: null }; },
        async publish() { assert.fail('read-only fixture must not publish'); } },
      store: { id: 'synthetic', async read() { return { status: 'present', key }; },
        async write() { assert.fail('read-only fixture must not write'); }, async delete() { assert.fail('read-only fixture must not delete'); } },
      async readIdentity() { return identity; },
    });
    return { engine, close() { assert.equal(h.errors.length, 0, 'no inner catch may print before joined provider cleanup'); h.events.push('runtime-close'); } };
  } });
}
function runner() {
  const program = new Command().exitOverride().option('--json').option('--api-url <url>');
  registerEndUsers(program); registerDevices(program); registerRecordings(program); registerIntegrations(program);
  return program;
}
function capture(t) {
  const original = console.error, exitCode = process.exitCode; const errors = [];
  console.error = (...args) => errors.push(args.join(' ')); process.exitCode = undefined;
  t.after(() => { console.error = original; process.exitCode = exitCode; }); return errors;
}

test('secure command failure helper throws a fresh fixed error without printing or running a compatibility mapper', async t => {
  const errors = capture(t); let mappings = 0;
  await withInvocationCredential(credential, operation().context, async () => {
    const original = new NativeProfileTransactionError('profile_state_unknown', true, true); original.message = key;
    assert.throws(() => handleCommandFailure(original, true, () => { mappings++; return key; }), error => {
      assert.notEqual(error, original); assert.equal(error.code, 'profile_state_unknown');
      assert.equal(error.recovery_required, true); assert.equal(error.operation_may_have_executed, true);
      assert.doesNotMatch(String(error) + JSON.stringify(error), /COMMAND_FAILURE_CANARY/); return true;
    });
    assert.throws(() => handleCommandFailure(new Error(key), true), error => {
      assert.equal(error.code, 'profile_operation_failed'); assert.equal(error.recovery_required, false);
      assert.equal(error.operation_may_have_executed, true); return true;
    });
  });
  assert.equal(errors.length, 0); assert.equal(mappings, 0); assert.equal(process.exitCode, undefined);
});

test('compatibility failure helper retains its selected renderer and exit behavior', t => {
  const errors = capture(t);
  handleCommandFailure(new Error('legacy-detail'), true, () => new BotaApiError(403, { message: 'safe-compatibility', code: 'insufficient_permissions' }));
  assert.equal(errors.length, 1); const detail = JSON.parse(errors[0]).error;
  assert.equal(detail.message, 'safe-compatibility'); assert.equal(detail.status, 403); assert.equal(detail.code, 'insufficient_permissions');
  assert.equal(process.exitCode, 1);
});

test('public cloud command catches defer business errors to one diagnostic after provider cleanup', async t => {
  const errors = capture(t), originalFetch = globalThis.fetch; t.after(() => { globalThis.fetch = originalFetch; });
  for (const argv of [['end-users', 'list'], ['devices', 'list'], ['recordings', 'list'], ['integrations', 'list']]) {
    errors.length = 0; const h = { errors, events: [] }, op = operation();
    globalThis.fetch = async () => Response.json({ error: { message: key, code: key } }, { status: 403 });
    const selected = service(h); const program = runner();
    let failure;
    try { await selected.run('work', { context: op.context, env: {} }, (value, context) =>
      withInvocationCredential(value, context, () => program.parseAsync(['node', 'bota', '--json', ...argv]))); }
    catch (error) { failure = error; printError(error, true); }
    assert.equal(failure.code, 'profile_operation_failed'); assert.equal(errors.length, 1);
    assert.equal(JSON.parse(errors[0]).error.operation_may_have_executed, true);
    assert.deepEqual(h.events.slice(-2), ['lease-close', 'runtime-close']); assert.doesNotMatch(errors[0], /COMMAND_FAILURE_CANARY/);
  }
});

test('deadline and cancellation failures render once after read-only command cleanup with uncertainty intact', async t => {
  const errors = capture(t), originalFetch = globalThis.fetch; t.after(() => { globalThis.fetch = originalFetch; });
  for (const condition of ['deadline', 'cancelled']) {
    errors.length = 0; const h = { errors, events: [] }, op = operation();
    globalThis.fetch = async () => { if (condition === 'deadline') op.expire(); else op.controller.abort(key); throw new Error(key); };
    let failure;
    try { await service(h).run('work', { context: op.context, env: {} }, (value, context) =>
      withInvocationCredential(value, context, () => runner().parseAsync(['node', 'bota', '--json', 'devices', 'list']))); }
    catch (error) { failure = error; printError(error, true); }
    assert.equal(failure.code, `profile_${condition}`); assert.equal(errors.length, 1);
    const detail = JSON.parse(errors[0]).error; assert.equal(detail.operation_may_have_executed, true);
    assert.equal(detail.recovery_required, false); assert.doesNotMatch(errors[0], /COMMAND_FAILURE_CANARY/);
    assert.deepEqual(h.events.slice(-2), ['lease-close', 'runtime-close']);
  }
});

test('auth status failure inside a secure invocation also defers to the single joined provider boundary', async t => {
  const errors = capture(t), originalFetch = globalThis.fetch; t.after(() => { globalThis.fetch = originalFetch; });
  const h = { errors, events: [] }, op = operation();
  globalThis.fetch = async () => Response.json({ error: { message: key } }, { status: 401 });
  let failure;
  try { await service(h).run('work', { context: op.context, env: {} }, (value, context) =>
    withInvocationCredential(value, context, () => showAuthStatus({ apiKey: key, apiUrl: origin, json: true }))); }
  catch (error) { failure = error; printError(error, true); }
  assert.equal(failure.code, 'profile_operation_failed'); assert.equal(errors.length, 1);
  assert.doesNotMatch(errors[0], /COMMAND_FAILURE_CANARY/); assert.equal(h.events.at(-1), 'runtime-close');
});
