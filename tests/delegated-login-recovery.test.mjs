import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { request } from 'node:http';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { spawnSync } from 'node:child_process';
import nodeTest from 'node:test';
import { DelegatedLoginError, startDelegatedLoginAttempt, startRecoverableDelegatedLoginAttempt,
  readDelegatedLoginExchangeBinding, readDelegatedLoginRecoveryBinding, isRecoverableDelegatedLoginAttempt } from '../src/delegated-login.ts';

const test = (name, work) => nodeTest(name, { timeout: 10_000 }, work), canary = 'PRIVATE_RECOVERY_RETENTION_CANARY';
// Observe the genuine owned Server, rather than reconnecting its former numeric
// port: parallel test processes can legitimately reuse an ephemeral port after
// this listener has joined closure. The real Node constructor is never replaced
// with a fake server and the observation uses only public lifecycle APIs.
const realCreateServer = http.createServer, listeners = new Map();
const createServerObserver = nodeTest.mock.method(http, 'createServer', function (...args) {
  const server = Reflect.apply(realCreateServer, http, args), observed = { server, closed: false };
  server.once('close', () => { observed.closed = true; });
  server.once('listening', () => { const address = server.address();
    if (address && typeof address !== 'string') listeners.set(`http://${address.address === '::1' ? '[::1]' : address.address}:${address.port}/oauth/callback`, observed);
  });
  return server;
});
syncBuiltinESMExports();
nodeTest.after(() => { createServerObserver.mock.restore(); syncBuiltinESMExports(); });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const deployment = () => ({ version: 1, issuer: 'https://login.fixture.invalid', endpoints: {
  authorization: 'https://login.fixture.invalid/oauth/authorize', token: 'https://login.fixture.invalid/oauth/token', revocation: 'https://login.fixture.invalid/oauth/revoke' },
  resources: { rest: 'https://api.fixture.invalid/v1', mcp: 'https://mcp.fixture.invalid/mcp' }, client: { clientId: 'registered-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const selection = () => ({ resourceKind: 'rest', grantResourceKinds: ['rest', 'mcp'], scopes: ['devices:read'], loopbackHost: '127.0.0.1' });
const receipt = binding => Object.freeze({ status: 'retained', attemptId: binding.attemptId });
const challenge = verifier => createHash('sha256').update(verifier, 'ascii').digest('base64url');
function refused(code) { return error => { assert.ok(error instanceof DelegatedLoginError); if (code) assert.equal(error.code, code);
  assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_RECOVERY_RETENTION_CANARY|fixture\.invalid|bota_dc1_/); assert.equal(error.cause, undefined); return true; }; }
async function closed(uri) {
  const observed = listeners.get(uri); assert.ok(observed, 'actual_owned_listener_not_observed');
  assert.equal(observed.closed, true, 'owned_listener_close_event_not_joined');
  assert.equal(observed.server.listening, false, 'owned_listener_still_listening');
  assert.equal(observed.server.address(), null, 'owned_listener_address_not_released');
  await new Promise((resolve, reject) => observed.server.getConnections((error, count) => {
    if (error) return reject(error); assert.equal(count, 0, 'owned_listener_connections_not_joined'); resolve();
  }));
}
async function send(uri, target) { const url = new URL(uri); return new Promise((resolve, reject) => {
  const req = request({ host: url.hostname.replace(/^\[|\]$/g, ''), port: url.port, path: target, agent: false, headers: { Host: url.host } }, res => {
    let body = ''; res.setEncoding('utf8'); res.on('data', value => { body += value; }); res.on('end', () => resolve({ status: res.statusCode, body })); res.on('error', reject);
  }); req.on('error', reject); req.setTimeout(2000, () => req.destroy(Error('owned_http_timeout'))); req.end(); }); }
const target = (attempt, fields = {}) => { const values = new URLSearchParams({ state: new URL(attempt.authorizationUrl).searchParams.get('state'), ...fields }); return '/oauth/callback?' + values; };
async function captured(t, options = {}, choose = selection()) {
  let binding, context, calls = 0;
  const attempt = await startRecoverableDelegatedLoginAttempt(deployment(), choose, { async retain(value, issued) { binding = value; context = issued; calls++; return receipt(value); } }, { timeoutMs: 3000, ...options });
  t.after(() => attempt.cancel()); return { attempt, binding, context, calls };
}

test('retention acknowledgement gates handle/URL publication and child authority retires before publication', async t => {
  const gate = deferred(), entered = deferred(); let binding, context, settled = false;
  const pending = startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(value, issued) {
    binding = value; context = issued; entered.resolve(); return gate.promise;
  } }, { timeoutMs: 3000 }).finally(() => { settled = true; });
  await entered.promise; context.budget.assertActive(); assert.equal(context.signal.aborted, false); assert.equal(settled, false);
  const invalid = await send(binding.redirectUri, '/oauth/callback?code=bota_dc1_' + randomBytes(32).toString('base64url') + '&state=' + randomBytes(32).toString('base64url'));
  assert.equal(invalid.status, 400); assert.doesNotMatch(invalid.body, /recovery|verifier|PRIVATE_/);
  gate.resolve(receipt(binding)); const attempt = await pending; t.after(() => attempt.cancel());
  assert.equal(context.signal.aborted, true); assert.throws(() => context.budget.assertActive(), refused());
  assert.equal(isRecoverableDelegatedLoginAttempt(attempt), true);
  assert.ok(Object.isFrozen(context)); assert.ok(Object.isFrozen(context.budget)); assert.equal(readDelegatedLoginRecoveryBinding(attempt), binding);
  assert.throws(() => readDelegatedLoginExchangeBinding(attempt), refused('login_not_complete'));
});

test('independent recovery proof and PKCE produce exact all-three URL fields, never raw verifiers or enumerable proof', async t => {
  const f = await captured(t), url = new URL(f.attempt.authorizationUrl), binding = f.binding;
  assert.match(binding.attemptId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(binding.recoveryVerifier, /^[A-Za-z0-9_-]{43}$/); assert.match(binding.pkceVerifier, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(binding.recoveryVerifier, binding.pkceVerifier); assert.notEqual(binding.recoveryVerifier, url.searchParams.get('state'));
  assert.equal(url.searchParams.get('enrollment_attempt'), binding.attemptId); assert.equal(url.searchParams.get('recovery_challenge'), challenge(binding.recoveryVerifier));
  assert.equal(url.searchParams.get('recovery_challenge_method'), 'S256'); assert.equal(url.searchParams.get('code_challenge'), challenge(binding.pkceVerifier));
  assert.equal(url.searchParams.getAll('enrollment_attempt').length, 1); assert.equal(url.searchParams.getAll('recovery_challenge').length, 1);
  assert.deepEqual(binding.grantResources, [deployment().resources.rest, deployment().resources.mcp]); assert.deepEqual(binding.scopes, ['devices:read']);
  for (const value of [binding, binding.grantResources, binding.scopes, f.attempt]) assert.ok(Object.isFrozen(value));
  assert.deepEqual(Object.keys(f.attempt), ['stage', 'authorizationUrl', 'redirectUri', 'result', 'cancel']);
  for (const proof of [binding.recoveryVerifier, binding.pkceVerifier]) { assert.equal(f.attempt.authorizationUrl.includes(proof), false); assert.equal(JSON.stringify(f.attempt).includes(proof), false); }
  assert.equal(f.calls, 1);
});

test('exact matching acknowledgement is required; negative/unknown/malformed/foreign receipts close the owned listener', async () => {
  for (const build of [() => 'not_retained', () => 'unknown', () => 'retained', () => undefined, () => null, () => ({}),
    b => ({ status: 'retained', attemptId: b.attemptId + 'x' }), b => ({ status: 'unknown', attemptId: b.attemptId }),
    b => ({ ...receipt(b), extra: canary }), b => Object.create(receipt(b))]) {
    let binding, context, calls = 0;
    await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b, c) { binding = b; context = c; calls++; return build(b); } }, { timeoutMs: 3000 }), refused('login_unavailable'));
    assert.equal(calls, 1); assert.equal(context.signal.aborted, true); assert.throws(() => context.budget.assertActive(), refused()); await closed(binding.redirectUri);
  }
});

test('closure observation refuses a live actual owner and accepts it only after joined cancellation', async t => {
  const f = await captured(t);
  await assert.rejects(closed(f.attempt.redirectUri), /owned_listener_close_event_not_joined/);
  await f.attempt.cancel(); await closed(f.attempt.redirectUri);
});

test('retention port and acknowledgement validation evaluate no getters or proxy reflection hooks', async () => {
  let hooks = 0;
  const proxy = new Proxy({}, { getPrototypeOf() { hooks++; throw Error(canary); }, ownKeys() { hooks++; throw Error(canary); } });
  for (const port of [proxy, { get retain() { hooks++; throw Error(canary); } }, { retain: new Proxy(async () => {}, { apply() { hooks++; throw Error(canary); } }) }]) {
    await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), port), refused('login_configuration_invalid'));
  }
  for (const build of [() => proxy, b => ({ get status() { hooks++; throw Error(canary); }, attemptId: b.attemptId }),
    b => ({ status: 'retained', get attemptId() { hooks++; throw Error(canary); } })]) {
    let uri; await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b) { uri = b.redirectUri; return build(b); } }), refused('login_unavailable')); await closed(uri);
  }
  assert.equal(hooks, 0);
});

test('retention uses captured function without invoking its own call/bind getters', async t => {
  let hooks = 0; const retain = async binding => receipt(binding);
  Object.defineProperty(retain, 'call', { get() { hooks++; throw Error(canary); } }); Object.defineProperty(retain, 'bind', { get() { hooks++; throw Error(canary); } });
  const attempt = await startRecoverableDelegatedLoginAttempt(deployment(), selection(), { retain }, { timeoutMs: 3000 });
  t.after(() => attempt.cancel()); assert.equal(hooks, 0); assert.ok(readDelegatedLoginRecoveryBinding(attempt));
});

test('private upstream retention failures are fixed and never publish a handle or leave a listener', async () => {
  for (const error of [Object.assign(Error(canary), { cause: Error(canary) }), new Proxy({}, { getPrototypeOf() { throw Error(canary); } }), undefined, null]) {
    let uri; await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(binding) { uri = binding.redirectUri; throw error; } }), refused('login_unavailable')); await closed(uri);
  }
});

test('parent cancellation closes the listener while joining cooperative unfinished retention, with no late success', async () => {
  const controller = new AbortController(), entered = deferred(), cleanup = deferred(); let binding, context, settled = false;
  const pending = startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b, c) { binding = b; context = c; entered.resolve(); return cleanup.promise; } },
    { signal: controller.signal, timeoutMs: 3000 }).finally(() => { settled = true; });
  await entered.promise; controller.abort(Error(canary)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.equal(context.signal.aborted, true); assert.throws(() => context.budget.assertActive(), refused('login_cancelled')); await closed(binding.redirectUri);
  cleanup.resolve(receipt(binding)); await assert.rejects(pending, refused('login_cancelled')); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('one original deadline closes listener and withdraws retention before joined late acknowledgement', async () => {
  const entered = deferred(), interrupted = deferred(), cleanup = deferred(); let binding, context, settled = false;
  const pending = startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b, c) {
    binding = b; context = c; c.signal.addEventListener('abort', () => interrupted.resolve(), { once: true }); entered.resolve(); return cleanup.promise;
  } }, { timeoutMs: 180 }).finally(() => { settled = true; });
  await entered.promise; await interrupted.promise; await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.throws(() => context.budget.assertActive(), refused('login_deadline')); await closed(binding.redirectUri);
  cleanup.resolve(receipt(binding)); await assert.rejects(pending, refused('login_deadline'));
});

test('an early timer callback cannot withdraw retention before the original monotonic deadline', async t => {
  const controller = new AbortController(), entered = deferred(), cleanup = deferred();
  const schedule = globalThis.setTimeout; let initial, binding, context, scheduled = 0, settled = false;
  t.mock.method(globalThis, 'setTimeout', function (callback, delay, ...args) {
    scheduled++;
    const handle = Reflect.apply(schedule, globalThis, [callback, delay, ...args]);
    initial ??= { callback, handle };
    return handle;
  });
  const pending = startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b, c) {
    binding = b; context = c; entered.resolve(); return cleanup.promise;
  } }, { signal: controller.signal, timeoutMs: 30_000 }).finally(() => { settled = true; });
  t.after(async () => { controller.abort(); cleanup.resolve(binding && receipt(binding)); await pending.catch(() => undefined); });
  await entered.promise; assert.equal(typeof initial?.callback, 'function');
  // A fired native timer has already consumed its handle. Simulate that early
  // scheduling observation without replacing the genuine listener or clock.
  clearTimeout(initial.handle); initial.callback();
  assert.equal(context.signal.aborted, false); assert.doesNotThrow(() => context.budget.assertActive());
  assert.equal(settled, false); assert.equal(listeners.get(binding.redirectUri).server.listening, true);
  controller.abort(); await new Promise(resolve => setImmediate(resolve)); await closed(binding.redirectUri);
  cleanup.resolve(receipt(binding)); await assert.rejects(pending, refused('login_cancelled'));
  const retiredCount = scheduled; initial.callback(); assert.equal(scheduled, retiredCount);
});

test('parent authority loss caused by retention retirement cannot publish acknowledged handle', async () => {
  const controller = new AbortController(); let uri;
  await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), { async retain(b, c) {
    uri = b.redirectUri; c.signal.addEventListener('abort', () => controller.abort(), { once: true }); return receipt(b);
  } }, { signal: controller.signal }), refused('login_cancelled')); await closed(uri);
});

test('recovery binding exists before callback and remains after successful callback then explicit cancellation', async t => {
  const f = await captured(t), code = 'bota_dc1_' + randomBytes(32).toString('base64url');
  assert.equal((await send(f.attempt.redirectUri, target(f.attempt, { code }))).status, 200); assert.deepEqual(await f.attempt.result, { code });
  const exchange = readDelegatedLoginExchangeBinding(f.attempt); assert.equal(exchange.verifier, f.binding.pkceVerifier);
  await f.attempt.cancel(); assert.throws(() => readDelegatedLoginExchangeBinding(f.attempt), refused('login_not_complete'));
  assert.equal(readDelegatedLoginRecoveryBinding(f.attempt), f.binding); await closed(f.attempt.redirectUri);
  assert.equal(isRecoverableDelegatedLoginAttempt(f.attempt), true);
});

test('precallback cancellation, timeout and matching denial preserve recovery only', async t => {
  const cancelled = await captured(t); await cancelled.attempt.cancel(); await assert.rejects(cancelled.attempt.result, refused('login_cancelled'));
  assert.equal(readDelegatedLoginRecoveryBinding(cancelled.attempt), cancelled.binding);
  const expired = await captured(t, { timeoutMs: 180 }); await assert.rejects(expired.attempt.result, refused('login_deadline'));
  assert.equal(readDelegatedLoginRecoveryBinding(expired.attempt), expired.binding);
  const denied = await captured(t); await send(denied.attempt.redirectUri, target(denied.attempt, { error: 'access_denied' }));
  await assert.rejects(denied.attempt.result, refused('login_denied')); assert.equal(readDelegatedLoginRecoveryBinding(denied.attempt), denied.binding);
  for (const f of [cancelled, expired, denied]) { assert.throws(() => readDelegatedLoginExchangeBinding(f.attempt), refused('login_not_complete')); await closed(f.attempt.redirectUri); }
});

test('legacy attempts and fabricated/cloned/proxied handles cannot access recovery proofs', async t => {
  const attempt = await startDelegatedLoginAttempt(deployment(), selection(), { timeoutMs: 3000 }); t.after(() => attempt.cancel());
  assert.equal(new URL(attempt.authorizationUrl).searchParams.has('enrollment_attempt'), false);
  for (const value of [attempt, {}, { ...attempt }, new Proxy(attempt, { get() { throw Error(canary); } }), null]) {
    assert.equal(isRecoverableDelegatedLoginAttempt(value), false);
    assert.throws(() => readDelegatedLoginRecoveryBinding(value), refused('login_not_complete'));
  }
});

test('copied deployment/selection and independent attempts keep retained proof bindings stable', async t => {
  const d = deployment(), s = selection(); let binding;
  const attempt = await startRecoverableDelegatedLoginAttempt(d, s, { async retain(b) { binding = b; d.issuer = canary; d.resources.rest = canary; s.scopes[0] = canary; return receipt(b); } }, { timeoutMs: 3000 });
  t.after(() => attempt.cancel()); assert.equal(binding.issuer, deployment().issuer); assert.deepEqual(binding.scopes, ['devices:read']);
  const other = await captured(t); assert.notEqual(other.binding.attemptId, binding.attemptId); assert.notEqual(other.binding.recoveryVerifier, binding.recoveryVerifier);
  assert.equal(new URL(attempt.authorizationUrl).origin, deployment().issuer); assert.equal(readDelegatedLoginRecoveryBinding(attempt), binding);
});

test('pre-aborted and forged parent signals refuse before retention without invoking shadowed getters', async () => {
  let calls = 0, hooks = 0; const controller = new AbortController(); controller.abort();
  const port = { async retain(b) { calls++; return receipt(b); } };
  await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), port, { signal: controller.signal }), refused('login_cancelled'));
  const nested = Object.create(new Proxy(AbortSignal.prototype, { getPrototypeOf() { hooks++; throw Error(canary); } }));
  await assert.rejects(startRecoverableDelegatedLoginAttempt(deployment(), selection(), port, { signal: nested }), refused('login_configuration_invalid'));
  assert.equal(calls, 0); assert.equal(hooks, 0);
});

test('recoverable producer and joined listener/retention exit naturally without browser or credential operations', () => {
  const module = new URL('../src/delegated-login.ts', import.meta.url).href;
  const script = `import {startRecoverableDelegatedLoginAttempt,readDelegatedLoginRecoveryBinding} from ${JSON.stringify(module)}; globalThis.fetch=()=>{throw Error('unexpected_fetch')}; const attempt=await startRecoverableDelegatedLoginAttempt(${JSON.stringify(deployment())},${JSON.stringify(selection())},{async retain(b){return {status:'retained',attemptId:b.attemptId}}},{timeoutMs:3000}); await attempt.cancel(); try{await attempt.result}catch(e){if(e.code!=='login_cancelled')throw e}; if(!readDelegatedLoginRecoveryBinding(attempt))throw Error('missing_proof');`;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], { cwd: process.cwd(), encoding: 'utf8', timeout: 5000 });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.signal, null); assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
