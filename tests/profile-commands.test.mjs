import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fixture, json, workspace } from './helpers.mjs';

const key = 'rk_PROFILE_CREDENTIAL_CANARY';
const identity = { project_id: 'proj_profile', organization_id: 'org_profile', key_id: 'sk_profile',
  key_type: 'restricted', is_test_mode: false, scope_mode: 'restricted', scopes: ['devices:read'] };
const environment = new Set(['path', 'pathext', 'systemroot', 'systemdrive', 'windir', 'comspec', 'temp', 'tmp', 'os']);

async function home(t, url) {
  const directory = await mkdtemp(join(tmpdir(), 'bota-profile-commands-'));
  t.after(async () => {
    const path = relative(tmpdir(), directory);
    assert.ok(path && !path.startsWith('..') && !isAbsolute(path));
    await rm(directory, { recursive: true, force: true });
  });
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => environment.has(name.toLowerCase()))),
    HOME: directory, USERPROFILE: directory, BOTA_API_KEY: key, BOTA_API_URL: url, NO_COLOR: '1', FORCE_COLOR: '0' };
  const marker = join(directory, 'legacy-access.txt');
  const guard = join(directory, 'legacy-guard.mjs');
  await writeFile(guard, `import fs from 'node:fs';\nimport { syncBuiltinESMExports } from 'node:module';\nconst read = fs.readFileSync; const write = fs.writeFileSync;\nfor (const method of ['readFileSync', 'writeFileSync']) {\n const original = fs[method]; fs[method] = function(path, ...args) {\n if (typeof path === 'string' && /[\\\\/]\\.bota[\\\\/]config\\.json$/.test(path)) write(${JSON.stringify(marker)}, method);\n return original.call(this, path, ...args);\n };\n}\nsyncBuiltinESMExports();\n`);
  return { env, directory, marker, guard: pathToFileURL(guard).href };
}

async function untouchedLegacy(state) {
  await assert.rejects(readFile(state.marker), { code: 'ENOENT' }, 'selected profile commands must never touch legacy config');
}

async function cli(t, state, args, { env = {}, legacy = false, input } = {}) {
  const child = spawn(process.execPath, ['--import', state.guard, '--import', 'tsx', 'src/index.ts', ...args], {
    cwd: workspace, env: { ...state.env, ...env }, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], windowsHide: true,
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
  if (child.stdin) { child.stdin.on('error', () => undefined); child.stdin.end(input); }
  const timer = setTimeout(() => child.kill(), 15_000);
  try {
    const [code, signal] = await once(child, 'close');
    assert.equal(signal, null, stderr);
    if (!legacy) await untouchedLegacy(state);
    return { code, stdout, stderr };
  } finally { clearTimeout(timer); }
}

async function add(t, state, url, name = 'work') {
  const result = await cli(t, state, ['--api-url', url, 'auth', 'profiles', 'add', name, '--from-env', '--allow-http-loopback', '--json']);
  assert.equal(result.code, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function rpc(req, res) {
  if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
  const message = JSON.parse(req.body);
  if (message.method === 'initialize') return json(res, { jsonrpc: '2.0', id: message.id, result: {
    protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'profile-fixture', version: '1' },
  } });
  if (message.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
  const result = message.method === 'tools/list' ? { tools: [{ name: 'get_project_identity', inputSchema: { type: 'object' } }] }
    : { content: [{ type: 'text', text: JSON.stringify({ success: true, identity }) }], structuredContent: { identity } };
  json(res, { jsonrpc: '2.0', id: message.id, result });
}

test('profile enrollment stores metadata only, list/remove are credential-free and never select a default', { timeout: 30_000 }, async t => {
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.headers.authorization, `Bearer ${key}`); json(res, identity); });
  const state = await home(t, api.url);
  const metadata = await add(t, state, api.url);
  assert.deepEqual(metadata, { name: 'work', format_version: 1, api_origin: api.url, project_id: identity.project_id,
    organization_id: identity.organization_id, credential_source: 'environment', allow_http_loopback: true });
  const directory = join(state.directory, '.bota', 'profiles');
  const names = await readdir(directory);
  assert.equal(names.length, 1);
  const stored = await readFile(join(directory, names[0]), 'utf8');
  assert.deepEqual(JSON.parse(stored), metadata); assert.doesNotMatch(stored + JSON.stringify(metadata), /CANARY|apiKey|key_id|scopes/);
  const missing = { BOTA_API_KEY: '', BOTA_API_URL: 'https://UNSELECTED_ORIGIN_CANARY.invalid' };
  const listed = await cli(t, state, ['auth', 'profiles', 'list', '--json'], { env: missing });
  assert.equal(listed.code, 0, listed.stderr); assert.deepEqual(JSON.parse(listed.stdout), [metadata]);
  const removed = await cli(t, state, ['auth', 'profiles', 'remove', 'work', '--json'], { env: missing });
  assert.equal(removed.code, 0, removed.stderr); assert.deepEqual(JSON.parse(removed.stdout), { removed: true });
  assert.deepEqual(await readdir(directory), []); assert.equal(api.requests.length, 1);
});

test('profile enrollment and list escape terminal controls while preserving opaque Unicode identity exactly', { timeout: 20_000 }, async t => {
  const opaque = { ...identity, project_id: '記録/opaque\u009b31m\u007f\n\u001b[31m\u2028\u202e\u2066',
    organization_id: '組織:opaque\u061c\u200f\u2029\u2069\r\t' };
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); json(res, opaque); });
  const state = await home(t, api.url);
  const enrolled = await cli(t, state, ['--api-url', api.url, 'auth', 'profiles', 'add', 'unicode', '--from-env', '--allow-http-loopback', '--json']);
  assert.equal(enrolled.code, 0, enrolled.stderr);
  const metadata = JSON.parse(enrolled.stdout);
  assert.equal(metadata.project_id, opaque.project_id); assert.equal(metadata.organization_id, opaque.organization_id);
  const listed = await cli(t, state, ['auth', 'profiles', 'list', '--json'], { env: { BOTA_API_KEY: undefined } });
  assert.equal(listed.code, 0, listed.stderr); assert.deepEqual(JSON.parse(listed.stdout), [metadata]);
  for (const result of [enrolled, listed]) {
    assert.equal(result.stderr, ''); assert.match(result.stdout, /\\u009b31m/);
    assert.doesNotMatch(result.stdout, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/);
  }
  assert.equal(api.requests.length, 1, 'listing metadata requires neither a credential nor another identity call');
});

test('profile enrollment requires explicit API origin and env opt-in; parser failures never echo credentials', { timeout: 30_000 }, async t => {
  const api = await fixture(t, () => assert.fail('Invalid enrollment must stay local'));
  const state = await home(t, api.url);
  const cases = [
    [['auth', 'profiles', 'add', 'work', '--from-env'], 'profile_api_url_required'],
    [['--api-url', api.url, 'auth', 'profiles', 'add', 'work'], 'invalid_profile_command'],
    [['--api-url', api.url, 'auth', 'profiles', 'add', 'work', '--from-env', 'ARGV_CREDENTIAL_CANARY'], 'invalid_profile_command'],
    [['auth', 'profiles', 'list', '--KEY_CREDENTIAL_CANARY'], 'invalid_profile_command'],
    [['--profile', 'SECRET_PROFILE_CANARY', 'auth', 'profiles', 'list'], 'profile_selection_not_applicable'],
  ];
  for (const [args, code] of cases) {
    const result = await cli(t, state, ['--json', ...args]);
    assert.notEqual(result.code, 0); assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, code); assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//);
  }
  assert.equal(api.requests.length, 0);
});

test('selected auth status verifies once, returns verified context and ignores legacy credentials entirely', { timeout: 30_000 }, async t => {
  let value = identity;
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.headers.authorization, `Bearer ${key}`); json(res, value); });
  const state = await home(t, api.url); await add(t, state, api.url);
  await writeFile(join(state.directory, '.bota', 'config.json'), JSON.stringify({ apiKey: 'sk_live_LEGACY_CANARY', apiUrl: 'https://LEGACY_ORIGIN_CANARY.invalid' }));
  value = { ...identity, scopes: ['integrations:write', 'custom\u009b31m'] };
  const before = api.requests.length;
  const result = await cli(t, state, ['--profile', 'work', 'auth', 'status', '--json']);
  assert.equal(result.code, 0, result.stderr); assert.equal(result.stderr, ''); assert.deepEqual(JSON.parse(result.stdout), value);
  assert.equal(api.requests.length - before, 1); assert.match(result.stdout, /\\u009b31m/); assert.doesNotMatch(result.stdout, /CANARY|https?:\/\//);
});

test('selected profiles refuse origin overrides, missing credentials and identity mismatch without fallback or effects', { timeout: 45_000 }, async t => {
  let value = identity;
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); json(res, value); });
  const foreign = await fixture(t, () => assert.fail('No cross-origin credential'));
  const state = await home(t, api.url); await add(t, state, api.url);
  const cases = [
    { args: ['--api-url', foreign.url], code: 'profile_origin_mismatch' },
    { env: { BOTA_API_URL: foreign.url }, code: 'profile_origin_mismatch' },
    { env: { BOTA_API_KEY: undefined }, code: 'profile_key_required' },
    { env: { BOTA_API_KEY: '' }, code: 'profile_invalid_key' },
    { name: 'missing', code: 'profile_not_found' },
  ];
  const before = api.requests.length;
  for (const row of cases) {
    const result = await cli(t, state, ['--profile', row.name ?? 'work', ...(row.args ?? []), 'devices', 'list', '--json'], { env: row.env });
    assert.equal(result.code, 1); assert.equal(JSON.parse(result.stderr).error.code, row.code); assert.equal(result.stdout, '');
    assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//);
  }
  assert.equal(api.requests.length, before); assert.equal(foreign.requests.length, 0);
  value = { ...identity, project_id: 'proj_other' };
  const mismatch = await cli(t, state, ['--profile', 'work', 'devices', 'list', '--json']);
  assert.equal(mismatch.code, 1); assert.equal(JSON.parse(mismatch.stderr).error.code, 'profile_identity_mismatch');
  assert.equal(api.requests.length, before + 1);
});

test('selected invalid credentials never fall back to legacy keys, business reads or browser login', { timeout: 30_000 }, async t => {
  let rejected = false;
  const api = await fixture(t, (req, res) => {
    assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.headers.authorization, `Bearer ${key}`);
    json(res, rejected ? { error: { message: 'SERVER_CANARY', code: 'SERVER_CANARY' } } : identity, rejected ? 401 : 200);
  });
  const state = await home(t, api.url); await add(t, state, api.url); rejected = true;
  const original = JSON.stringify({ apiKey: 'sk_live_LEGACY_CANARY', apiUrl: api.url });
  const legacy = join(state.directory, '.bota', 'config.json'); await writeFile(legacy, original);
  for (const args of [['devices', 'list'], ['auth', 'status'], ['auth', 'login'], ['auth', 'logout']]) {
    const before = api.requests.length;
    const result = await cli(t, state, ['--profile', 'work', ...args, '--json']);
    assert.equal(result.code, 1); assert.equal(result.stdout, ''); assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//);
    assert.equal(JSON.parse(result.stderr).error.code, args[0] === 'auth' && args[1] !== 'status' ? 'profile_legacy_auth_unavailable' : 'profile_identity_failed');
    assert.equal(api.requests.length - before, args[0] === 'auth' && args[1] !== 'status' ? 0 : 1);
  }
  assert.equal(await readFile(legacy, 'utf8'), original);
});

test('all REST command families and hosted trigger share the selected origin and environment key', { timeout: 45_000 }, async t => {
  const api = await fixture(t, (req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${key}`);
    const path = new URL(req.url, 'http://fixture').pathname;
    if (path === '/v1/auth/identity') return json(res, identity);
    if (path === '/mcp') return rpc(req, res);
    if (['/v1/end-users', '/v1/devices', '/v1/recordings', '/v1/transcriptions', '/v1/summaries', '/v1/integrations'].includes(path)) return json(res, { data: [], has_more: false });
    json(res, { id: 'fixture', status: 'uploaded' });
  });
  const state = await home(t, api.url); await add(t, state, api.url);
  const cases = [['end-users', 'list'], ['end-users', 'get', 'eu_fixture'], ['devices', 'list'], ['devices', 'inspect', 'dev_fixture'],
    ['devices', 'stats'], ['recordings', 'list'], ['recordings', 'get', 'rec_fixture'], ['integrations', 'list'],
    ['trigger', 'recording.uploaded', '--webhook', 'wh_fixture']];
  for (const args of cases) {
    const before = api.requests.length;
    const result = await cli(t, state, ['--profile', 'work', ...args, '--json']);
    assert.equal(result.code, 0, `${args.join(' ')}: ${result.stderr}`);
    const requests = api.requests.slice(before);
    assert.equal(requests.filter(req => req.url === '/v1/auth/identity').length, 1);
    assert.ok(requests.length >= 2);
  }
});

for (const mode of ['legacy', 'hosted']) {
  test(`selected ${mode} MCP verifies once before stdio and shares the selected context`, { timeout: 30_000 }, async t => {
    const api = await fixture(t, (req, res) => {
      assert.equal(req.headers.authorization, `Bearer ${key}`);
      if (req.url === '/v1/auth/identity') return json(res, identity);
      if (req.url === '/mcp') return rpc(req, res);
      assert.equal(new URL(req.url, 'http://fixture').pathname, '/v1/devices'); json(res, { data: [], has_more: false });
    });
    const state = await home(t, api.url); await add(t, state, api.url);
    const before = api.requests.length;
    const transport = new StdioClientTransport({ command: process.execPath,
      args: ['--import', state.guard, '--import', 'tsx', 'src/index.ts', '--profile', 'work', 'mcp', '--mode', mode],
      env: state.env, cwd: workspace, stderr: 'pipe' });
    const client = new Client({ name: 'profile-context-test', version: '1' });
    t.after(() => client.close()); await client.connect(transport);
    const tools = await client.listTools();
    assert.ok(tools.tools.some(tool => tool.name === (mode === 'legacy' ? 'list_devices' : 'get_project_identity')));
    const result = await client.callTool({ name: mode === 'legacy' ? 'list_devices' : 'get_project_identity', arguments: {} });
    assert.equal(result.isError, undefined);
    await client.close(); await untouchedLegacy(state);
    assert.equal(api.requests.slice(before).filter(req => req.url === '/v1/auth/identity').length, 1);
  });
}

test('profile help, unknown MCP mode and local-only webhook commands do not resolve credentials', { timeout: 30_000 }, async t => {
  const api = await fixture(t, () => assert.fail('No identity or cloud operation expected'));
  const state = await home(t, api.url); delete state.env.BOTA_API_KEY;
  for (const args of [['--help'], ['auth', 'profiles', '--help'], ['devices', 'list', '--help']]) {
    const result = await cli(t, state, ['--profile', 'missing', ...args]);
    assert.equal(result.code, 0, result.stderr);
  }
  const mode = await cli(t, state, ['--profile', 'missing', 'mcp', '--mode', 'MODE_CANARY']);
  assert.equal(mode.code, 1); assert.match(mode.stderr, /--mode must be legacy or hosted/); assert.doesNotMatch(mode.stderr, /CANARY/);
  const webhooks = await cli(t, state, ['--profile', 'missing', 'webhooks', 'list']);
  assert.equal(webhooks.code, 1); assert.match(webhooks.stderr, /Bota Platform/);
  assert.equal(api.requests.length, 0);
});

test('manual listen remains credential-free with an unused profile selection and joins shutdown', { timeout: 20_000 }, async t => {
  const api = await fixture(t, () => assert.fail('Manual listening must not preflight identity'));
  const receiver = await fixture(t, (req, res) => { assert.equal(req.headers.authorization, undefined); json(res, { received: true }); });
  const state = await home(t, api.url); delete state.env.BOTA_API_KEY;
  const child = spawn(process.execPath, ['--import', state.guard, '--import', 'tsx', '--import', './tests/fixtures/signal-relay.mjs',
    'src/index.ts', '--profile', 'missing', 'listen', '--manual', '--forward-to', receiver.url, '--port', '0'], {
    cwd: workspace, env: state.env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true,
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
  const exited = once(child, 'close'); let finished = false; void exited.then(() => { finished = true; });
  t.after(async () => { if (!finished) child.kill(); await exited; });
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.stdout.off('data', check); reject(new Error('Manual listener startup timed out')); }, 10_000);
    const check = () => {
      const match = stdout.match(/Manual webhook listener: (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); child.stdout.off('data', check); resolve(match[1]); }
    };
    child.stdout.on('data', check); check();
    void exited.then(() => { clearTimeout(timer); reject(new Error(`Manual listener exited: ${stderr}`)); });
  });
  assert.equal((await fetch(url, { method: 'POST', body: '{}' })).status, 200);
  child.send('SIGTERM');
  assert.deepEqual(await exited, [0, null]); await untouchedLegacy(state);
  assert.equal(api.requests.length, 0); assert.equal(receiver.requests.length, 1); assert.equal(stderr, '');
});

test('no-profile auth keeps saved-key precedence and performs no profile lookup', { timeout: 30_000 }, async t => {
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.headers.authorization, 'Bearer sk_live_LEGACY_CANARY'); json(res, identity); });
  const state = await home(t, api.url);
  await mkdir(join(state.directory, '.bota')); await writeFile(join(state.directory, '.bota', 'config.json'), JSON.stringify({ apiKey: 'sk_live_LEGACY_CANARY', apiUrl: api.url }));
  await mkdir(join(state.directory, '.bota', 'profiles')); await writeFile(join(state.directory, '.bota', 'profiles', 'corrupt.json'), 'PROFILE_CANARY');
  const result = await cli(t, state, ['auth', 'status', '--json'], { legacy: true });
  assert.equal(result.code, 0, result.stderr); assert.deepEqual(JSON.parse(result.stdout), identity); assert.equal(api.requests.length, 1);
  assert.equal(await readFile(state.marker, 'utf8'), 'readFileSync');
});
