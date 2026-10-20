import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { fixture, isolatedEnvironment, json, workspace } from './helpers.mjs';

const ids = { project_id: 'proj_0123456789abcdefghijklmn', organization_id: 'org_0123456789abcdefghijklmn', key_id: 'sk_0123456789abcdefghijklmn' };
const identity = (scopes = ['devices:read']) => ({ ...ids, key_type: 'restricted', is_test_mode: false, scope_mode: 'restricted', scopes });

async function status(t, apiUrl, args = [], options = {}) {
  const env = await isolatedEnvironment(t, apiUrl);
  env.BOTA_API_KEY = options.key ?? 'rk_CREDENTIAL_CANARY';
  if (options.missing) delete env.BOTA_API_KEY;
  const path = join(env.USERPROFILE, '.bota', 'config.json');
  const saved = options.config === undefined ? undefined : `${JSON.stringify(options.config)}\n`;
  if (saved !== undefined) { await mkdir(join(env.USERPROFILE, '.bota')); await writeFile(path, saved); }
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--api-url', apiUrl, 'auth', 'status', ...args], {
    cwd: workspace, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const timer = setTimeout(() => child.kill(), 12_000);
  try {
    const [code, signal] = await once(child, 'close');
    assert.equal(signal, null);
    if (saved !== undefined) assert.equal(await readFile(path, 'utf8'), saved, 'status must not rewrite credential configuration');
    return { code, stdout, stderr };
  } finally { clearTimeout(timer); }
}

test('auth status resolves device-only, integration-only and empty restricted grants without business-read permission', { timeout: 15_000 }, async t => {
  let scopes = ['devices:read'];
  const api = await fixture(t, (req, res) => {
    assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.method, 'GET');
    assert.equal(req.headers.authorization, 'Bearer rk_CREDENTIAL_CANARY');
    json(res, { ...identity(scopes), key_hint: 'HINT_CANARY', api_key: 'RESPONSE_CREDENTIAL_CANARY', metadata: { secret: 'METADATA_CANARY' } });
  });
  for (scopes of [['devices:read'], ['integrations:write'], []]) {
    const result = await status(t, api.url, ['--json']);
    assert.equal(result.code, 0); assert.equal(result.stderr, ''); assert.deepEqual(JSON.parse(result.stdout), identity(scopes));
    assert.doesNotMatch(result.stdout, /CANARY|https?:\/\//);
  }
  assert.equal(api.requests.length, 3);
});

test('auth status uses resolved secret identity and renders arbitrary stored scope strings safely', { timeout: 15_000 }, async t => {
  let value = { ...ids, key_type: 'secret', is_test_mode: true, scope_mode: 'project_secret', scopes: null };
  const api = await fixture(t, (req, res) => { assert.equal(req.url, '/v1/auth/identity'); json(res, value); });
  const broad = await status(t, api.url, ['--json'], { key: 'sk_live_CREDENTIAL_CANARY' });
  assert.equal(broad.code, 0); assert.deepEqual(JSON.parse(broad.stdout), value); assert.equal(broad.stderr, '');
  const human = await status(t, api.url, [], { key: 'sk_live_CREDENTIAL_CANARY' });
  assert.equal(human.code, 0); assert.match(human.stdout, /Credential type: secret/); assert.match(human.stdout, /Key test flag: true/);
  assert.doesNotMatch(human.stdout, /CREDENTIAL_CANARY|https?:\/\/|isolated|sandbox/i);
  value = identity(['custom:future', 'custom:future', 'unknown grant\n\u001b[31m\r\t\u009b31m\u007f\u2028\u202e\u2066']);
  const structured = await status(t, api.url, ['--json']);
  assert.equal(structured.code, 0); assert.deepEqual(JSON.parse(structured.stdout), value);
  assert.match(structured.stdout, /\\u009b31m/); assert.doesNotMatch(structured.stdout, /[\u007f-\u009f\u2028-\u202e\u2066-\u206f]/);
  const escaped = await status(t, api.url);
  assert.equal(escaped.code, 0);
  assert.deepEqual(JSON.parse(escaped.stdout.split('\n').find(line => line.startsWith('Scopes: ')).slice(8)), value.scopes);
  assert.match(escaped.stdout, /\\u009b31m/); assert.doesNotMatch(escaped.stdout, /[\u001b\r\t\u007f-\u009f\u2028-\u202e\u2066-\u206f]/);
  assert.equal(api.requests.length, 4);
});

test('auth status preserves saved-config credential precedence over the environment without rewriting it', { timeout: 15_000 }, async t => {
  const api = await fixture(t, (req, res) => {
    assert.equal(req.headers.authorization, 'Bearer sk_live_CONFIG_CREDENTIAL_CANARY');
    assert.equal(req.url, '/v1/auth/identity'); json(res, identity(['integrations:read']));
  });
  const result = await status(t, api.url, ['--json'], { config: { apiKey: 'sk_live_CONFIG_CREDENTIAL_CANARY', apiUrl: 'https://CONFIG_URL_CANARY.invalid' } });
  assert.equal(result.code, 0); assert.deepEqual(JSON.parse(result.stdout), identity(['integrations:read']));
  assert.doesNotMatch(result.stdout + result.stderr, /CANARY/); assert.equal(api.requests.length, 1);
});

test('auth status missing credentials fails locally with structured or human diagnostics on stderr', { timeout: 15_000 }, async t => {
  const api = await fixture(t, () => assert.fail('No unauthenticated request expected'));
  for (const args of [[], ['--json']]) {
    const result = await status(t, api.url, args, { missing: true });
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    if (args.length) assert.deepEqual(JSON.parse(result.stderr), { error: { code: 'not_authenticated', message: 'No credential is selected. Run: bota auth login, or supply BOTA_API_KEY.' } });
    else assert.match(result.stderr, /No credential is selected/);
  }
  assert.equal(api.requests.length, 0);
});

for (const [httpStatus, code] of [[401, 'invalid_credential'], [403, 'permission_denied'], [423, 'organization_access_quarantined'], [429, 'rate_limit_exceeded'], [404, 'identity_http_error'], [500, 'identity_service_unavailable'], [503, 'identity_service_unavailable']]) {
  test(`auth status distinguishes HTTP ${httpStatus} without echoing server errors, credentials or URLs`, { timeout: 15_000 }, async t => {
    const api = await fixture(t, (req, res) => {
      assert.equal(req.url, '/v1/auth/identity');
      res.setHeader('X-Request-Id', 'HEADER_CANARY'); res.setHeader('Retry-After', 'RETRY_CANARY');
      json(res, { error: { code: 'CODE_CANARY', message: 'CREDENTIAL_CANARY https://URL_CANARY.invalid', param: 'PARAM_CANARY', request_id: 'REQUEST_CANARY' }, debug: 'BODY_CANARY' }, httpStatus);
    });
    for (const args of [[], ['--json']]) {
      const result = await status(t, api.url, args);
      assert.equal(result.code, 1); assert.equal(result.stdout, ''); assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//);
      if (args.length) { const error = JSON.parse(result.stderr).error; assert.equal(error.code, code); assert.equal(error.status, httpStatus); assert.deepEqual(Object.keys(error).sort(), ['code', 'message', 'status']); }
      else { assert.match(result.stderr, new RegExp(`HTTP ${httpStatus}`)); assert.match(result.stderr, new RegExp(`code: ${code}`)); }
    }
    assert.equal(api.requests.length, 2, 'one attempt per command, without business-route fallback');
  });
}

test('auth status rejects malformed identity payloads and non-JSON successes without reflecting response content', { timeout: 30_000 }, async t => {
  let payload, httpStatus = 200;
  const api = await fixture(t, (req, res) => {
    assert.equal(req.url, '/v1/auth/identity');
    if (httpStatus === 204) { res.writeHead(204); res.end(); return; }
    if (payload === undefined) { res.writeHead(httpStatus, { 'Content-Type': 'text/plain' }); res.end('NON_JSON_CANARY'); }
    else json(res, payload, httpStatus);
  });
  for (payload of [undefined, [], { ...identity(), key_id: 7, debug: 'MALFORMED_CANARY' }, { ...identity(), key_type: 'device_token' }, { ...identity(), scope_mode: 'project_secret' }, { ...identity(), scopes: [false] }, { ...identity(), is_test_mode: 'MODE_CANARY' }]) {
    const result = await status(t, api.url, ['--json']);
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, 'invalid_identity_response'); assert.doesNotMatch(result.stderr, /CANARY|device_token/);
  }
  for ([httpStatus, payload] of [[204, undefined], [201, { ...identity(), key_id: false }], [201, undefined]]) {
    const result = await status(t, api.url, ['--json']);
    const error = JSON.parse(result.stderr).error;
    assert.equal(result.code, 1); assert.equal(error.code, 'invalid_identity_response');
    assert.equal(error.status, httpStatus === 201 && payload === undefined ? 201 : undefined,
      'schema failures must not invent a 200 status; non-JSON transport failures retain their actual status');
    assert.doesNotMatch(result.stderr, /CANARY/);
  }
  assert.equal(api.requests.length, 10);
});

test('auth status network and invalid-origin failures remain fixed and never expose configured URLs', { timeout: 15_000 }, async t => {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve));
  for (const apiUrl of [`http://127.0.0.1:${port}/NETWORK_URL_CANARY`, 'http://URL_CREDENTIAL_CANARY@127.0.0.1', 'URL_PARSE_CANARY']) {
    const result = await status(t, apiUrl, ['--json']);
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, 'identity_request_failed'); assert.doesNotMatch(result.stderr, /CANARY|https?:\/\//);
  }
});
