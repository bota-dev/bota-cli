import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { fixture, isolatedEnvironment, workspace } from './helpers.mjs';

async function invoke(t, apiUrl, args, initial, overrides = true) {
  const env = await isolatedEnvironment(t, apiUrl);
  env.BOTA_API_KEY = 'rk_ENVIRONMENT_CANARY';
  const path = join(env.USERPROFILE, '.bota', 'config.json');
  const original = JSON.stringify(initial) + '\n';
  await mkdir(join(env.USERPROFILE, '.bota'));
  await writeFile(path, original);
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', ...(overrides ? ['--api-url', apiUrl,
    '--dashboard-url', apiUrl + '/DASHBOARD_CANARY'] : []), ...args], { cwd: workspace, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const timer = setTimeout(() => child.kill(), 8000);
  try {
    const [code, signal] = await once(child, 'close');
    assert.equal(signal, null, 'command must settle without a callback or browser');
    return { code, stdout, stderr, original, saved: await readFile(path, 'utf8') };
  } finally { clearTimeout(timer); }
}

test('unconfigured Platform login fails before native/browser access and preserves legacy credentials', async t => {
  const api = await fixture(t, (_req, res) => { res.writeHead(500); res.end(); });
  for (const args of [['auth', 'login'], ['--json', 'auth', 'login']]) {
    const result = await invoke(t, api.url, args, { apiKey: 'sk_live_SAVED_CANARY', arbitrary: 'PRESERVE_CANARY' }, false);
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    assert.equal(result.saved, result.original);
    assert.match(result.stderr, /developer_configuration_unavailable/);
    assert.doesNotMatch(result.stderr, /CANARY|https?:\/\/|Opening browser|[?&]key=/);
    if (args[0] === '--json') assert.equal(JSON.parse(result.stderr).error.code, 'developer_configuration_unavailable');
  }
  assert.equal(api.requests.length, 0);
});

test('legacy URL overrides cannot retarget Platform login', async t => {
  const api = await fixture(t, (_req, res) => { res.writeHead(500); res.end(); });
  const result = await invoke(t, api.url, ['--json', 'auth', 'login'], { arbitrary: 'PRESERVE_CANARY' });
  assert.equal(result.code, 1); assert.equal(result.saved, result.original); assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr).error.code, 'developer_profile_invalid');
  assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//); assert.equal(api.requests.length, 0);
});

test('developer selection and private parser failures never expose accidental credentials', async t => {
  const api = await fixture(t, (_req, res) => { res.writeHead(500); res.end(); });
  const attempts = [
    ['--developer-profile', 'work', '--profile', 'PRIVATE_SELECTOR_CANARY', 'devices', 'list'],
    ['--developer-profile', 'work', 'mcp'],
    ['auth', 'login', '--unknown-PRIVATE_FLAG_CANARY'],
    ['auth', 'login', 'sk_test_PRIVATE_ARGUMENT_CANARY', 'PRIVATE_EXTRA_CANARY'],
    ['auth', 'developer-profiles', 'show', 'work', 'PRIVATE_EXTRA_CANARY'],
    ['auth', 'developer-profiles', 'recover', 'work', '--PRIVATE_FLAG_CANARY'],
  ];
  for (const args of attempts) {
    const result = await invoke(t, api.url, ['--json', ...args], { apiKey: 'sk_live_SAVED_CANARY', arbitrary: 'PRESERVE_CANARY' }, false);
    assert.equal(result.code, 1); assert.equal(result.stdout, ''); assert.equal(result.saved, result.original);
    assert.doesNotMatch(result.stderr, /PRIVATE_|CANARY|https?:\/\/|Opening browser/);
    const code = JSON.parse(result.stderr).error.code; assert.ok(['developer_profile_invalid', 'developer_mcp_hosted_required'].includes(code));
  }
  assert.equal(api.requests.length, 0);
});

test('explicit legacy key enrollment and logout preserve their compatibility behavior', async t => {
  const api = await fixture(t, (_req, res) => { res.writeHead(500); res.end(); });
  const login = await invoke(t, api.url, ['auth', 'login', 'sk_test_SYNTHETIC'], { arbitrary: 'retained' });
  assert.equal(login.code, 0); assert.equal(login.stderr, '');
  assert.deepEqual(JSON.parse(login.saved), { arbitrary: 'retained', apiKey: 'sk_test_SYNTHETIC', apiUrl: api.url });
  const logout = await invoke(t, api.url, ['auth', 'logout'], { arbitrary: 'retained', apiKey: 'sk_test_SYNTHETIC' });
  assert.equal(logout.code, 0); assert.equal(logout.stderr, '');
  assert.deepEqual(JSON.parse(logout.saved), { arbitrary: 'retained' });
  assert.equal(api.requests.length, 0);
});
