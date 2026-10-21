import assert from 'node:assert/strict';
import test from 'node:test';
import { Command } from 'commander';
import { bindMcpRequestAuth } from '../src/invocation-auth.ts';
import { registerMcp } from '../src/commands/mcp.ts';
import { getApiKey, getApiUrl } from '../src/config.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const record = () => ({ format_version: 2, name: 'fixture', store_id: 'windows-credential-manager', state: 'ready',
  api_origin: 'https://api.example.invalid', project_id: 'project-fixture', organization_id: 'organization-fixture', key_id: 'key-fixture',
  profile_id: 'b435b8d5-78cd-4ba6-9e1d-7464f9acbf02', credential_ref: '26391329-36dd-4ed8-958d-34377503c78a', allow_http_loopback: false });
const identity = { project_id: 'project-fixture', organization_id: 'organization-fixture', key_id: 'key-fixture', key_type: 'restricted',
  scope_mode: 'restricted', scopes: ['devices:read'], is_test_mode: true };

test('bound MCP authentication inspects only metadata at startup and resolves anew for every request with the original binding', async () => {
  const profile = record(), calls = [], key = 'rk_MCP_FACTORY_FAKE_KEY'; let identities = 0;
  const create = bindMcpRequestAuth({
    async inspect(name) { calls.push(['inspect', name]); return { record: profile, journal: null }; },
    async run(name, options, action) {
      identities++; calls.push(['run', name, options]);
      const context = { signal: options.signal, budget: { assertActive() {} } };
      return action({ apiOrigin: 'https://api.example.invalid', apiKey: key, identity, profile, source: 'store' }, context);
    },
  });
  const authenticate = await create('fixture', 'https://api.example.invalid');
  assert.equal(identities, 0); assert.deepEqual(calls, [['inspect', 'fixture']]);
  profile.profile_id = 'f6ac952a-fd62-4aae-90d3-35e5a8848f0d';
  for (let index = 0; index < 2; index++) {
    const controller = new AbortController();
    assert.equal(await authenticate(controller.signal, async () => {
      assert.equal(getApiKey(), key); assert.equal(getApiUrl(), 'https://api.example.invalid');
      return index;
    }), index);
    assert.equal(identities, index + 1);
    const options = calls[index + 1][2];
    assert.equal(options.signal, controller.signal); assert.equal(options.timeoutMs, 30000);
    assert.equal(options.apiUrlOverride, 'https://api.example.invalid'); assert.ok(Object.isFrozen(options.expectedBinding));
    assert.deepEqual(options.expectedBinding, { profile_id: 'b435b8d5-78cd-4ba6-9e1d-7464f9acbf02', api_origin: 'https://api.example.invalid',
      project_id: 'project-fixture', organization_id: 'organization-fixture' });
  }
});

test('startup absent, pending and disabled metadata refuses before any request-time credential resolution', async () => {
  for (const [snapshot, code] of [[null, 'profile_not_found'], [{ record: record(), journal: { phase: 'committed' } }, 'profile_pending_recovery'],
    [{ record: { ...record(), state: 'removed' }, journal: null }, 'profile_disabled']]) {
    const create = bindMcpRequestAuth({ async inspect() { return snapshot; }, async run() { assert.fail('Unexpected native credential selection'); } });
    await assert.rejects(create('fixture'), error => { assert.equal(error.code, code); return true; });
  }
});

test('MCP command accepts an explicit trusted factory in code and preserves mode refusal before it runs', async () => {
  let calls = 0;
  const program = new Command('bota').exitOverride().option('--secure-profile <name>').option('--api-url <url>');
  registerMcp(program, { async createRequestAuth(name, apiUrl) {
    calls++; assert.equal(name, 'fixture'); assert.equal(apiUrl, 'https://api.example.invalid');
    throw new NativeProfileTransactionError('profile_disabled');
  } });
  await assert.rejects(program.parseAsync(['node', 'bota', '--secure-profile', 'fixture', '--api-url', 'https://api.example.invalid', 'mcp', '--mode', 'legacy']),
    error => { assert.equal(error.code, 'profile_disabled'); return true; });
  assert.equal(calls, 1);
  const invalid = new Command('bota').exitOverride().option('--secure-profile <name>');
  registerMcp(invalid, { async createRequestAuth() { assert.fail('Invalid mode must not invoke auth'); } });
  await assert.rejects(invalid.parseAsync(['node', 'bota', '--secure-profile', 'fixture', 'mcp', '--mode', 'invalid']), /--mode must be legacy or hosted/);
});
