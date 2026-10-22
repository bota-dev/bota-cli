import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { fixture, isolatedEnvironment, workspace } from './helpers.mjs';

async function invoke(t, apiUrl, args, initial) {
  const env = await isolatedEnvironment(t, apiUrl);
  env.BOTA_API_KEY = 'rk_ENVIRONMENT_CANARY';
  const path = join(env.USERPROFILE, '.bota', 'config.json');
  const original = JSON.stringify(initial) + '\n';
  await mkdir(join(env.USERPROFILE, '.bota'));
  await writeFile(path, original);
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--api-url', apiUrl,
    '--dashboard-url', apiUrl + '/DASHBOARD_CANARY', ...args], { cwd: workspace, env, stdio: ['ignore', 'pipe', 'pipe'] });
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

test('retired browser login fails locally without changing saved credentials or contacting the dashboard', async t => {
  const api = await fixture(t, (_req, res) => { res.writeHead(500); res.end(); });
  for (const args of [['auth', 'login'], ['--json', 'auth', 'login']]) {
    const result = await invoke(t, api.url, args, { apiKey: 'sk_live_SAVED_CANARY', arbitrary: 'PRESERVE_CANARY' });
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    assert.equal(result.saved, result.original);
    assert.match(result.stderr, /platform_login_unavailable/);
    assert.match(result.stderr, /BOTA_API_KEY/);
    assert.doesNotMatch(result.stderr, /CANARY|https?:\/\/|Opening browser|[?&]key=/);
    if (args[0] === '--json') assert.equal(JSON.parse(result.stderr).error.code, 'platform_login_unavailable');
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
