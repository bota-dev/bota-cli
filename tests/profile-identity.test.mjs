import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { readProfileIdentity } from '../src/profile-identity.ts';
import { parseProjectIdentity } from '../src/client.ts';
import { ProfileError } from '../src/profiles.ts';

const identity = { project_id: 'proj_synthetic', organization_id: 'org_synthetic', key_id: 'key_synthetic',
  key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false };
const key = 'rk_SYNTHETIC_PROFILE_KEY';

async function fixture(t, handle) {
  const server = createServer(handle);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}

async function refused(operation) {
  await assert.rejects(operation, error => {
    assert.ok(error instanceof ProfileError);
    assert.equal(error.code, 'profile_identity_failed');
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.stack + JSON.stringify(error), /SYNTHETIC_PROFILE_KEY|BODY_CANARY|URL_CANARY|PARSE_CANARY/);
    return true;
  });
}

test('profile identity decoder preserves the seven-field secret/restricted contract without coercion', () => {
  for (const value of [identity, { ...identity, scopes: ['future:grant', 'future:grant'] },
    { ...identity, key_type: 'secret', scope_mode: 'project_secret', scopes: null, is_test_mode: true }]) {
    assert.deepEqual(parseProjectIdentity({ ...value, api_key: key }), value);
  }
  assert.throws(() => parseProjectIdentity({ ...identity, scopes: null }));
});

test('profile preflight performs one exact identity read and strips unrelated response fields', async t => {
  let count = 0;
  const url = await fixture(t, (req, res) => {
    count++; assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.method, 'GET');
    assert.equal(req.headers.authorization, `Bearer ${key}`); assert.equal(req.headers.cookie, undefined);
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ ...identity, api_key: key }));
  });
  assert.deepEqual(await readProfileIdentity(url, key), identity);
  assert.equal(count, 1);
});

test('profile preflight refuses a redirect before any request reaches its destination', async t => {
  let redirected = 0, attempts = 0;
  const destination = await fixture(t, (_req, res) => { redirected++; res.end('BODY_CANARY'); });
  const origin = await fixture(t, (_req, res) => { attempts++; res.writeHead(307, { Location: destination }); res.end(); });
  await refused(() => readProfileIdentity(origin, key));
  assert.equal(redirected, 0); assert.equal(attempts, 1);
});

test('profile preflight refuses HTTP failures and malformed/incorrect identity without response reflection or retries', async t => {
  let payload = '', status = 200, attempts = 0;
  const url = await fixture(t, (_req, res) => { attempts++; res.writeHead(status); res.end(payload); });
  const cases = [[401, JSON.stringify({ error: { message: key + ' BODY_CANARY' } })], [503, 'BODY_CANARY'],
    [204, ''], [201, JSON.stringify(identity)], [200, '{"PARSE_CANARY":'], [200, JSON.stringify({ ...identity, key_type: 'device_token' })],
    [200, JSON.stringify({ ...identity, is_test_mode: 'BODY_CANARY' })]];
  for ([status, payload] of cases) await refused(() => readProfileIdentity(url, key));
  assert.equal(attempts, cases.length);
});

test('profile preflight bounds both advertised and streamed bodies and closes the connection', { timeout: 10_000 }, async t => {
  let mode = 'advertised';
  const closed = [];
  const url = await fixture(t, (req, res) => {
    closed.push(new Promise(resolve => res.once('close', resolve)));
    if (mode === 'advertised') { res.writeHead(200, { 'Content-Length': 65_537 }); res.flushHeaders(); }
    else { res.writeHead(200); res.write('x'.repeat(65_537)); }
  });
  for (mode of ['advertised', 'streamed']) await refused(() => readProfileIdentity(url, key));
  await Promise.all(closed);
});

test('profile identity deadline covers an unfinished response body and joins its native cancellation', { timeout: 10_000 }, async t => {
  let attempts = 0, closed;
  const url = await fixture(t, (_req, res) => {
    attempts++;
    closed = new Promise(resolve => res.once('close', resolve));
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
  });
  await refused(() => readProfileIdentity(url, key, { timeoutMs: 1_000 }));
  await closed;
  assert.equal(attempts, 1);
  for (const timeoutMs of [0, -1, 30_001, Infinity, NaN]) {
    await refused(() => readProfileIdentity(url, key, { timeoutMs }));
  }
  assert.equal(attempts, 1, 'invalid budgets must fail before requesting');
});

test('profile preflight refuses invalid UTF-8 and partial bodies without retaining native errors', async t => {
  let mode = 'utf8';
  const url = await fixture(t, (_req, res) => {
    if (mode === 'utf8') { res.end(Buffer.from([0xff])); }
    else { res.writeHead(200, { 'Content-Length': 300 }); res.write('{'); setImmediate(() => res.destroy(new Error('BODY_CANARY'))); }
  });
  for (mode of ['utf8', 'partial']) await refused(() => readProfileIdentity(url, key));
});

test('profile identity never returns a bearer reflected inside a declared identifier or scope', async t => {
  let payload;
  const url = await fixture(t, (_req, res) => { res.end(JSON.stringify(payload)); });
  for (const field of ['project_id', 'organization_id', 'key_id', 'scopes']) {
    payload = { ...identity, [field]: field === 'scopes' ? [key] : `prefix_${key}` };
    await refused(() => readProfileIdentity(url, key));
  }
});
