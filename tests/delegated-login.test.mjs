import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { getEventListeners, once } from 'node:events';
import { request } from 'node:http';
import { connect } from 'node:net';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { DELEGATED_LOGIN_LIMITS, DELEGATED_LOGIN_STAGE, DelegatedLoginError,
  parseDelegatedLoginDeployment, readDelegatedLoginExchangeBinding, startDelegatedLoginAttempt } from '../src/delegated-login.ts';

const canary = 'PRIVATE_LOGIN_CANARY';
const config = () => ({ version: 1, issuer: 'https://login.example.test',
  endpoints: { authorization: 'https://login.example.test/oauth/authorize', token: 'https://login.example.test/oauth/token', revocation: 'https://login.example.test/oauth/revoke' },
  resources: { rest: 'https://api.example.test/v1', mcp: 'https://agents.example.test/mcp' },
  client: { clientId: 'registered-cli', kind: 'native', redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const choose = () => ({ resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read', 'recordings:read'], loopbackHost: '127.0.0.1' });
const code = () => 'bota_dc1_' + randomBytes(32).toString('base64url');
const state = attempt => new URL(attempt.authorizationUrl).searchParams.get('state');
const target = (attempt, value = code()) => `/oauth/callback?code=${value}&state=${state(attempt)}`;
function failure(expected) {
  return error => { assert.ok(error instanceof DelegatedLoginError); assert.equal(error.code, expected);
    assert.doesNotMatch(String(error), /PRIVATE_LOGIN_CANARY|example\.test|bota_dc1_|state=/); assert.equal(error.cause, undefined); return true; };
}
async function start(options = {}, selection = choose(), deployment = config()) {
  return startDelegatedLoginAttempt(deployment, selection, { timeoutMs: 5000, ...options });
}
async function send(attempt, path = target(attempt), options = {}) {
  const url = new URL(attempt.redirectUri);
  return new Promise((resolve, reject) => {
    const req = request({ host: url.hostname.replace(/^\[|\]$/g, ''), port: url.port, path, method: options.method ?? 'GET',
      agent: false, headers: { Host: url.host, ...options.headers } }, response => {
      let body = '';
      response.setEncoding('utf8'); response.on('data', part => { body += part; assert.ok(body.length <= 2048); });
      response.on('end', () => resolve({ status: response.statusCode, body, headers: response.headers }));
      response.on('error', reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error('owned_request_timeout')));
    req.on('error', reject); req.end(options.body);
  });
}
async function raw(attempt, bytes, { idle = false } = {}) {
  const url = new URL(attempt.redirectUri);
  const socket = connect({ host: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port) });
  socket.on('error', () => undefined);
  await once(socket, 'connect');
  const closed = new Promise(resolve => socket.once('close', resolve));
  if (bytes) socket.write(bytes);
  if (idle) return { socket, closed };
  let response = ''; socket.setEncoding('utf8'); socket.on('data', chunk => { response += chunk; });
  await closed; return response;
}
async function closed(attempt) {
  const url = new URL(attempt.redirectUri);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port) });
    socket.setTimeout(1000, () => { socket.destroy(); reject(new Error('closed_port_probe_timeout')); });
    socket.on('connect', () => { socket.destroy(); reject(new Error('listener_still_open')); });
    socket.on('error', error => { assert.ok(['ECONNREFUSED', 'ECONNRESET'].includes(error.code)); resolve(); });
  });
}
async function rejectThenSucceed(paths, options = {}) {
  const attempt = await start();
  try {
    for (const build of paths) {
      const response = await send(attempt, typeof build === 'function' ? build(attempt) : build, options);
      assert.equal(response.status, 400); assert.equal(response.body, 'Authorization response rejected.\n');
      assert.equal(response.headers['cache-control'], 'no-store'); assert.equal(response.headers['referrer-policy'], 'no-referrer');
      assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete'));
    }
    const value = code(); assert.equal((await send(attempt, target(attempt, value))).status, 200);
    assert.deepEqual(await attempt.result, { code: value }); await closed(attempt);
  } finally { await attempt.cancel(); }
}

test('inactive deployment has no defaults and copies/freezes explicit native registration', () => {
  const input = config(), parsed = parseDelegatedLoginDeployment(input);
  input.issuer = canary; input.endpoints.token = canary; input.client.redirectUris[0] = canary; input.resources.rest = canary;
  assert.equal(parsed.issuer, 'https://login.example.test'); assert.equal(parsed.resources.rest, 'https://api.example.test/v1');
  assert.equal(parsed.client.redirectUris[0], 'http://127.0.0.1/oauth/callback');
  for (const value of [parsed, parsed.client, parsed.client.redirectUris, parsed.client.resourceKinds, parsed.resources, parsed.endpoints]) assert.ok(Object.isFrozen(value));
  assert.equal(DELEGATED_LOGIN_STAGE, 'inactive-client-contract');
  assert.deepEqual(DELEGATED_LOGIN_LIMITS, { defaultTimeoutMs: 120000, maxTimeoutMs: 300000, maxRequestBytes: 2048,
    maxHeaderBytes: 8192, maxRequests: 32, maxConnections: 8, maxTotalConnections: 64 });
});

test('deployment rejects absent, inferred, normalized, non-TLS and conflicting authority', () => {
  const mutations = [v => { delete v.issuer; }, v => { delete v.endpoints; }, v => { delete v.client; }, v => { v.version = 2; },
    v => { v.extra = canary; }, v => { v.issuer = 'https://login.example.test/'; }, v => { v.issuer = 'https://LOGIN.example.test'; },
    v => { v.endpoints.token = 'https://elsewhere.example.test/oauth/token'; }, v => { v.endpoints.authorization += '?secret=' + canary; },
    v => { v.endpoints.revocation = 'https://login.example.test/custom'; }, v => { v.resources.rest = v.resources.mcp; },
    v => { v.resources.rest = 'https://login.example.test/.well-known/oauth-authorization-server'; },
    v => { v.resources.rest = v.endpoints.token; }, v => { v.resources.rest = 'http://127.0.0.1:1234'; },
    v => { v.resources.rest = 'https://api.example.test/%76%31'; }, v => { v.resources.rest = 'https://api.example.test/v1/'; },
    v => { v.resources.rest = 'https://a:b@api.example.test/v1'; }, v => { v.client.kind = 'remote'; },
    v => { v.client.clientId = 'x\n' + canary; }, v => { v.client.clientId = 'registered-cli\n'; }, v => { v.client.pkceMethod = 'plain'; },
    v => { v.client.redirectUris = ['http://localhost/oauth/callback']; }, v => { v.client.redirectUris = ['http://127.0.0.1:4242/oauth/callback']; },
    v => { v.client.redirectUris = ['http://127.0.0.1/callback']; }, v => { v.client.resourceKinds = []; },
    v => { v.client.resourceKinds = ['rest', 'rest']; }, v => { v.client.redirectUris.push(v.client.redirectUris[0]); }];
  for (const mutate of mutations) { const input = config(); mutate(input); assert.throws(() => parseDelegatedLoginDeployment(input), failure('login_configuration_invalid')); }
  for (const value of [undefined, null, canary, [], new Proxy(config(), {}), Object.create(config())]) {
    assert.throws(() => parseDelegatedLoginDeployment(value), failure('login_configuration_invalid'));
  }
});

test('configuration never evaluates getters, proxy hooks, sparse arrays or coercion', () => {
  let calls = 0;
  for (const key of ['issuer', 'endpoints', 'client']) {
    const input = config(); Object.defineProperty(input, key, { enumerable: true, get() { calls++; throw new Error(canary); } });
    assert.throws(() => parseDelegatedLoginDeployment(input), failure('login_configuration_invalid'));
  }
  const input = config(); input.client.redirectUris = new Array(1);
  assert.throws(() => parseDelegatedLoginDeployment(input), failure('login_configuration_invalid'));
  const getter = config(); Object.defineProperty(getter.client.redirectUris, '0', { enumerable: true, get() { calls++; throw new Error(canary); } });
  assert.throws(() => parseDelegatedLoginDeployment(getter), failure('login_configuration_invalid')); assert.equal(calls, 0);
  const revoked = Proxy.revocable([], {}); revoked.revoke(); const unsafe = config(); unsafe.client.redirectUris = revoked.proxy;
  assert.throws(() => parseDelegatedLoginDeployment(unsafe), failure('login_configuration_invalid'));
});

test('invalid selection/options refuse before binding without implicit project, scopes or resource', async () => {
  const mutations = [v => { delete v.scopes; }, v => { delete v.grantResourceKinds; }, v => { v.grantResourceKinds = ['mcp']; },
    v => { v.scopes = ['devices:write']; }, v => { v.scopes = ['devices:read', 'devices:read']; },
    v => { v.loopbackHost = 'localhost'; }, v => { v.loopbackHost = '0.0.0.0'; }, v => { v.loopbackHost = '[::1]'; },
    v => { v.resourceKind = 'https://elsewhere.example.test'; }, v => { v.projectId = canary; }];
  for (const mutate of mutations) { const value = choose(); mutate(value); await assert.rejects(start({}, value), failure('login_configuration_invalid')); }
  for (const timeoutMs of [0, -1, 300001, 1.5, NaN, Infinity, null, canary]) await assert.rejects(start({ timeoutMs }), failure('login_configuration_invalid'));
  let calls = 0; const options = Object.defineProperty({}, 'timeoutMs', { enumerable: true, get() { calls++; throw Error(canary); } });
  await assert.rejects(startDelegatedLoginAttempt(config(), choose(), options), failure('login_configuration_invalid')); assert.equal(calls, 0);
  const revoked = Proxy.revocable([], {}); revoked.revoke();
  await assert.rejects(start({}, { ...choose(), grantResourceKinds: revoked.proxy }), failure('login_configuration_invalid'));
  await assert.rejects(start({ signal: Object.create(AbortSignal.prototype) }), failure('login_configuration_invalid'));
  const deployment = config(); deployment.client.redirectUris = ['http://[::1]/oauth/callback'];
  await assert.rejects(start({}, choose(), deployment), failure('login_configuration_invalid'));
});

test('real owned IPv4 callback captures only a canonical code and closes before settlement', async () => {
  const controller = new AbortController(), input = config(), selected = choose();
  const attempt = await start({ signal: controller.signal }, selected, input);
  assert.ok(Object.isFrozen(attempt)); assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete'));
  const authorization = new URL(attempt.authorizationUrl), redirect = new URL(attempt.redirectUri);
  assert.equal(redirect.hostname, '127.0.0.1'); assert.ok(Number(redirect.port) > 0); assert.equal(redirect.pathname, '/oauth/callback');
  assert.equal(authorization.origin + authorization.pathname, 'https://login.example.test/oauth/authorize');
  assert.deepEqual([...authorization.searchParams.keys()], ['response_type', 'client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'resource', 'resource', 'scope']);
  assert.deepEqual(authorization.searchParams.getAll('resource'), [input.resources.rest, input.resources.mcp]);
  assert.equal(authorization.searchParams.get('response_type'), 'code'); assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('scope'), 'devices:read recordings:read');
  input.endpoints.token = canary; selected.resourceKind = 'mcp'; selected.grantResourceKinds.length = 0; selected.scopes.length = 0;
  const value = code(), response = await send(attempt, target(attempt, value), { headers: { 'Sec-Fetch-Site': 'cross-site' } });
  assert.equal(response.status, 200); assert.doesNotMatch(response.body, /bota_dc1_|state=|Authenticated|login complete/i);
  const result = await attempt.result; assert.deepEqual(result, { code: value }); assert.ok(Object.isFrozen(result)); await closed(attempt);
  const binding = readDelegatedLoginExchangeBinding(attempt); assert.ok(Object.isFrozen(binding));
  assert.equal(binding.tokenEndpoint, 'https://login.example.test/oauth/token'); assert.equal(binding.resource, 'https://api.example.test/v1');
  assert.deepEqual(binding.scopes, ['devices:read', 'recordings:read']); assert.deepEqual(binding.grantResources, ['https://api.example.test/v1', 'https://agents.example.test/mcp']);
  assert.equal(binding.redirectUri, attempt.redirectUri); assert.match(binding.verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(binding.verifier, state(attempt));
  assert.equal(createHash('sha256').update(binding.verifier, 'ascii').digest('base64url'), authorization.searchParams.get('code_challenge'));
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0); await attempt.cancel();
  assert.throws(() => readDelegatedLoginExchangeBinding({ ...attempt }), failure('login_not_complete'));
});

test('real owned IPv6 callback uses registered exact bracketed authority and resource-specific exchange', async () => {
  const selected = { ...choose(), resourceKind: 'mcp', grantResourceKinds: ['mcp'], scopes: [], loopbackHost: '::1' };
  const attempt = await start({}, selected);
  try {
    assert.match(attempt.redirectUri, /^http:\/\/\[::1\]:[1-9][0-9]*\/oauth\/callback$/);
    const authorization = new URL(attempt.authorizationUrl); assert.equal(authorization.searchParams.has('scope'), false);
    assert.deepEqual(authorization.searchParams.getAll('resource'), ['https://agents.example.test/mcp']);
    const value = code(); assert.equal((await send(attempt, target(attempt, value))).status, 200); assert.deepEqual(await attempt.result, { code: value });
    assert.equal(readDelegatedLoginExchangeBinding(attempt).resource, 'https://agents.example.test/mcp'); await closed(attempt);
  } finally { await attempt.cancel(); }
});

test('raw target aliases and absolute-form requests cannot consume the legitimate attempt', async () => {
  await rejectThenSucceed([
    '/favicon.ico', a => target(a).replace('/oauth/callback', '/oauth/callback/'), a => target(a).replace('/oauth/callback', '/oauth/%63allback'),
    a => target(a).replace('/oauth/callback', '/x/../oauth/callback'), a => target(a).replace('/oauth/callback', '//oauth/callback'),
    a => 'http://127.0.0.1' + target(a), a => target(a) + '#fragment', a => target(a).replace('/oauth/', '/OAUTH/'),
  ]);
});

test('duplicate, encoded, empty and extra credential parameters never become a captured code', async () => {
  await rejectThenSucceed([
    a => `${target(a)}&code=${code()}`, a => `${target(a)}&state=${state(a)}`, a => target(a).replace('code=', '%63ode='),
    a => target(a).replace('code=bota_', 'code=%62ota_'), a => target(a).replace('state=', 'state=%'),
    a => `/oauth/callback?code=&state=${state(a)}`, a => `/oauth/callback?state=${state(a)}`,
    a => `${target(a)}&access_token=${canary}`, a => `${target(a)}&refresh_token=${canary}`, a => `${target(a)}&key=${canary}`,
    a => `${target(a)}&api_key=${canary}`, a => `${target(a)}&error=access_denied`, a => `${target(a)}&unknown=${canary}`,
    a => `${target(a)}&error_description=${canary}`, a => target(a).replace('bota_dc1_', 'bota_da1_'),
    a => `/oauth/callback?code=bota_dc1_${'A'.repeat(42)}B&state=${state(a)}`,
  ]);
});

test('state precedes OAuth error handling and wrong-state errors do not cancel the real attempt', async () => {
  await rejectThenSucceed([
    a => target(a).replace(state(a), randomBytes(32).toString('base64url')),
    () => `/oauth/callback?error=access_denied&state=${randomBytes(32).toString('base64url')}`,
    a => `/oauth/callback?error=unrecognized&state=${state(a)}`,
    a => `/oauth/callback?error=access_denied&state=${state(a)}&error=server_error`,
  ]);
});

test('matching OAuth denial closes and exposes only a fixed error, never remote descriptions or URIs', async () => {
  const attempt = await start();
  const response = await send(attempt, `/oauth/callback?error=access_denied&state=${state(attempt)}&error_description=${canary}&error_uri=https%3A%2F%2F${canary}`);
  assert.equal(response.status, 400); assert.doesNotMatch(response.body, /PRIVATE_LOGIN_CANARY/);
  await assert.rejects(attempt.result, failure('login_denied')); await closed(attempt);
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete')); await attempt.cancel();
});

test('POST, GET bodies, credential headers and foreign Host are fixed refusals before a valid callback', async () => {
  for (const options of [{ method: 'POST' }, { headers: { 'Content-Length': '1' }, body: 'x' },
    { headers: { Authorization: 'Bearer ' + canary } }, { headers: { 'Transfer-Encoding': 'chunked' } },
    { headers: { Host: 'localhost:4242' } }, { headers: { Host: 'evil.example.test' } }]) {
    await rejectThenSucceed([a => target(a)], options);
  }
});

test('unrelated browser cookies are ignored without parsing, reflection or loss of exact callback checks', async () => {
  const attempt = await start();
  try {
    const value = code();
    const response = await send(attempt, target(attempt, value), { headers: { Cookie: `other_local_app=${canary}; state=untrusted; code=unused` } });
    assert.equal(response.status, 200); assert.doesNotMatch(response.body + JSON.stringify(response.headers), /PRIVATE_LOGIN_CANARY|other_local_app|untrusted|unused/);
    assert.deepEqual(await attempt.result, { code: value }); await closed(attempt);
  } finally { await attempt.cancel(); }
});

test('oversized request targets and duplicate Host headers cannot consume the callback', async () => {
  const attempt = await start();
  try {
    assert.equal((await send(attempt, target(attempt) + '&x=' + 'x'.repeat(2048))).status, 400);
    const authority = new URL(attempt.redirectUri).host;
    const response = await raw(attempt, `GET ${target(attempt)} HTTP/1.1\r\nHost: ${authority}\r\nHost: ${authority}\r\nConnection: close\r\n\r\n`);
    assert.match(response, /HTTP\/1\.1 400/);
    const value = code(); await send(attempt, target(attempt, value)); assert.deepEqual(await attempt.result, { code: value });
  } finally { await attempt.cancel(); }
});

test('actual header overflow and malformed HTTP receive fixed parser refusals without consuming the code', async () => {
  const attempt = await start();
  try {
    const authority = new URL(attempt.redirectUri).host;
    for (const bytes of [`GET /oauth/callback HTTP/1.1\r\nHost: ${authority}\r\nX-Overflow: ${'x'.repeat(9000)}\r\n\r\n`,
      `GET /oauth/callback HTTP/1.1\r\nHost: ${authority}\r\nInvalid Header: ${canary}\r\n\r\n`]) {
      const response = await raw(attempt, bytes); assert.match(response, /HTTP\/1\.1 400/); assert.doesNotMatch(response, /PRIVATE_LOGIN_CANARY|Overflow|Invalid Header/);
    }
    const value = code(); await send(attempt, target(attempt, value)); assert.deepEqual(await attempt.result, { code: value }); await closed(attempt);
  } finally { await attempt.cancel(); }
});

test('a hostless HTTP/1.0 callback with correct state is refused while the legitimate attempt remains pending', async () => {
  const attempt = await start();
  try {
    const response = await raw(attempt, `GET ${target(attempt)} HTTP/1.0\r\nConnection: close\r\n\r\n`);
    assert.match(response, /HTTP\/1\.1 400/); assert.match(response, /Authorization response rejected/);
    assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete'));
    const value = code(); await send(attempt, target(attempt, value)); assert.deepEqual(await attempt.result, { code: value }); await closed(attempt);
  } finally { await attempt.cancel(); }
});

test('simultaneous valid callbacks atomically preserve one code and join every accepted socket', async () => {
  const attempt = await start(), first = code(), second = code();
  const responses = await Promise.allSettled([send(attempt, target(attempt, first)), send(attempt, target(attempt, second))]);
  const result = await attempt.result; assert.ok([first, second].includes(result.code));
  assert.ok(responses.some(value => value.status === 'fulfilled' && value.value.status === 200));
  assert.equal(responses.filter(value => value.status === 'fulfilled' && value.value.status === 200).length, 1);
  await closed(attempt); await attempt.cancel();
});

test('request budget is bounded and preserves a fixed failure after all owned resources close', async () => {
  const attempt = await start();
  for (let index = 0; index <= DELEGATED_LOGIN_LIMITS.maxRequests; index++) assert.equal((await send(attempt, '/favicon.ico')).status, 400);
  await assert.rejects(attempt.result, failure('login_callback_invalid')); await closed(attempt); await attempt.cancel();
});

test('cancellation joins slowloris and keepalive sockets and removes the external signal listener', async () => {
  const controller = new AbortController(), attempt = await start({ signal: controller.signal });
  const partial = await raw(attempt, 'GET /oauth/callback HTTP/1.1\r\n', { idle: true });
  const idle = await raw(attempt, undefined, { idle: true });
  controller.abort(new Error(canary));
  await assert.rejects(attempt.result, failure('login_cancelled')); await Promise.all([partial.closed, idle.closed]);
  assert.equal(partial.socket.destroyed, true); assert.equal(idle.socket.destroyed, true); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  await closed(attempt); assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete')); await attempt.cancel();
});

test('connection cap closes overflow sockets while retaining the legitimate bounded attempt', async () => {
  const attempt = await start(), held = [];
  try {
    for (let index = 0; index < DELEGATED_LOGIN_LIMITS.maxConnections; index++) held.push(await raw(attempt, undefined, { idle: true }));
    const overflow = await raw(attempt, undefined, { idle: true }); await overflow.closed; assert.equal(overflow.socket.destroyed, true);
    for (const item of held) item.socket.destroy(); await Promise.all(held.map(item => item.closed));
    const value = code(); await send(attempt, target(attempt, value)); assert.deepEqual(await attempt.result, { code: value }); await closed(attempt);
  } finally { for (const item of held) item.socket.destroy(); await attempt.cancel(); }
});

test('total connection budget is bounded even when no connection supplies a complete request', async () => {
  const attempt = await start();
  for (let index = 0; index <= DELEGATED_LOGIN_LIMITS.maxTotalConnections; index++) {
    const owned = await raw(attempt, undefined, { idle: true }); owned.socket.destroy(); await owned.closed;
  }
  await assert.rejects(attempt.result, failure('login_callback_invalid')); await closed(attempt); await attempt.cancel();
});

test('aborted partial callback cannot claim a code and an already-connected socket is joined on success', async () => {
  const attempt = await start();
  const aborted = await raw(attempt, 'GET /oauth/callback?code=', { idle: true }); aborted.socket.destroy(); await aborted.closed;
  const idle = await raw(attempt, undefined, { idle: true });
  const value = code(); await send(attempt, target(attempt, value)); assert.deepEqual(await attempt.result, { code: value });
  await idle.closed; assert.equal(idle.socket.destroyed, true); await closed(attempt);
});

test('deadline closes idle and partially written requests; later code cannot revive the attempt', async () => {
  const attempt = await start({ timeoutMs: 180 });
  const partial = await raw(attempt, 'GET /oauth/callback?code=', { idle: true });
  await assert.rejects(attempt.result, failure('login_deadline')); await partial.closed; await closed(attempt);
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete')); await attempt.cancel();
});

test('pre-cancellation and immediate cancellation during bind leave no listener or signal hook', async () => {
  const pre = new AbortController(); pre.abort(new Error(canary)); await assert.rejects(start({ signal: pre.signal }), failure('login_cancelled'));
  assert.equal(getEventListeners(pre.signal, 'abort').length, 0);
  for (let index = 0; index < 5; index++) {
    const controller = new AbortController(), pending = start({ signal: controller.signal }); controller.abort(new Error(canary));
    await assert.rejects(pending, failure('login_cancelled')); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});

test('the original deadline also covers actual bind startup before an attempt can be exposed', async () => {
  const controller = new AbortController(), pending = start({ signal: controller.signal, timeoutMs: 1 });
  const until = performance.now() + 5; while (performance.now() < until) { /* Hold JS until the original deadline passes. */ }
  await assert.rejects(pending, failure('login_deadline')); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('explicit cancellation is idempotent, returns after cleanup and disallows binding access', async () => {
  const attempt = await start(); await Promise.all([attempt.cancel(), attempt.cancel()]);
  await assert.rejects(attempt.result, failure('login_cancelled')); await closed(attempt);
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete'));
});

test('late callback after cancellation cannot turn a failed attempt into code capture', async () => {
  const controller = new AbortController(), attempt = await start({ signal: controller.signal });
  const late = await raw(attempt, undefined, { idle: true }); controller.abort(new Error(canary));
  late.socket.write(`GET ${target(attempt)} HTTP/1.1\r\nHost: ${new URL(attempt.redirectUri).host}\r\n\r\n`);
  await assert.rejects(attempt.result, failure('login_cancelled')); await late.closed; await closed(attempt);
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete'));
});

test('explicit cancellation after capture also retires exchange binding access', async () => {
  const attempt = await start(); await send(attempt); await attempt.result;
  assert.ok(readDelegatedLoginExchangeBinding(attempt)); await attempt.cancel();
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete')); await closed(attempt);
});

test('successful capture cannot expose an expired exchange binding', async () => {
  const attempt = await start({ timeoutMs: 250 }); await send(attempt); await attempt.result;
  await new Promise(resolve => setTimeout(resolve, 280));
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), failure('login_not_complete')); await closed(attempt);
});

test('import and joined receiver cleanup exit naturally without browser, token exchange or credential storage', () => {
  const module = new URL('../src/delegated-login.ts', import.meta.url).href;
  const script = `import {startDelegatedLoginAttempt} from ${JSON.stringify(module)}; globalThis.fetch=()=>{throw Error(${JSON.stringify(canary)})}; const attempt=await startDelegatedLoginAttempt(${JSON.stringify(config())},${JSON.stringify(choose())},{timeoutMs:1000}); await attempt.cancel(); try{await attempt.result}catch(error){if(error.code!=='login_cancelled')throw error};`;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], { cwd: process.cwd(), timeout: 5000, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.signal, null); assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
