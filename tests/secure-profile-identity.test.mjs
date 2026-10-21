import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { readSecureProfileIdentity } from '../src/secure-profile-identity.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const key = 'rk_SECURE_IDENTITY_CANARY';
const identity = { project_id: 'project:synthetic', organization_id: 'org:synthetic', key_id: 'key:synthetic',
  key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false };
function operation() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, context: { signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error(key); } } } };
}
async function fixture(t, handle) {
  const server = createServer(handle); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}
function refused(error) {
  assert.ok(error instanceof NativeProfileTransactionError); assert.equal(error.code, 'profile_identity_failed');
  assert.equal(error.cause, undefined);
  assert.doesNotMatch(error.stack + JSON.stringify(error), /IDENTITY_CANARY|BODY_CANARY|URL_CANARY|RAW_DETAIL/);
  return true;
}

test('secure identity performs one normalized exact read with no cookies or unrelated reflected fields', async t => {
  let count = 0;
  const origin = await fixture(t, (req, res) => {
    count++; assert.equal(req.url, '/v1/auth/identity'); assert.equal(req.method, 'GET');
    assert.equal(req.headers.authorization, `Bearer ${key}`); assert.equal(req.headers.cookie, undefined);
    res.end(JSON.stringify({ ...identity, api_key: key }));
  });
  assert.deepEqual(await readSecureProfileIdentity(origin, key, operation().context), identity); assert.equal(count, 1);
});

test('secure identity cancellation aborts a pending body and joins stream cleanup without exposing abort reasons', async t => {
  const started = Promise.withResolvers(), closed = Promise.withResolvers(); let attempts = 0;
  const origin = await fixture(t, (_req, res) => {
    attempts++; res.once('close', closed.resolve); res.writeHead(200); res.write('{'); started.resolve();
  });
  const op = operation(); const reading = readSecureProfileIdentity(origin, key, op.context);
  await started.promise; op.controller.abort(`${key} RAW_DETAIL`);
  await assert.rejects(reading, refused); await closed.promise; assert.equal(attempts, 1);
});

test('secure identity rejects an already cancelled or expired operation before network access', async t => {
  let attempts = 0; const origin = await fixture(t, (_req, res) => { attempts++; res.end(JSON.stringify(identity)); });
  const cancelled = operation(); cancelled.controller.abort(key);
  const expired = operation(); expired.expire();
  for (const context of [cancelled.context, expired.context, { signal: {}, budget: { assertActive() {} } }]) {
    await assert.rejects(readSecureProfileIdentity(origin, key, context), refused);
  }
  assert.equal(attempts, 0);
});

test('secure identity refuses redirects before any bearer reaches their destination', async t => {
  let destinationCalls = 0, originCalls = 0;
  const destination = await fixture(t, (_req, res) => { destinationCalls++; res.end('BODY_CANARY'); });
  const origin = await fixture(t, (_req, res) => { originCalls++; res.writeHead(307, { Location: destination }); res.end(); });
  await assert.rejects(readSecureProfileIdentity(origin, key, operation().context), refused);
  assert.equal(originCalls, 1); assert.equal(destinationCalls, 0);
});

test('secure identity refuses malformed origins/key values without issuing a request', async t => {
  let calls = 0; const origin = await fixture(t, (_req, res) => { calls++; res.end(JSON.stringify(identity)); });
  for (const url of [`${origin}/`, `${origin}/wrong`, `${origin}?URL_CANARY`, origin.replace('127.0.0.1', 'localhost'),
    `${origin.replace('://', '://user:pass@')}`, 'file:///RAW_DETAIL']) {
    await assert.rejects(readSecureProfileIdentity(url, key, operation().context), refused);
  }
  for (const value of ['', undefined, 'has space', 'x'.repeat(2561)]) {
    await assert.rejects(readSecureProfileIdentity(origin, value, operation().context), refused);
  }
  assert.equal(calls, 0);
});

test('secure identity bounds advertised/streamed bytes and malformed UTF-8/partial data without retries', async t => {
  let mode, calls = 0;
  const origin = await fixture(t, (_req, res) => {
    calls++;
    if (mode === 'advertised') { res.writeHead(200, { 'Content-Length': 65_537 }); res.flushHeaders(); }
    else if (mode === 'streamed') { res.writeHead(200); res.write('x'.repeat(65_537)); }
    else if (mode === 'utf8') res.end(Buffer.from([0xff]));
    else { res.writeHead(200, { 'Content-Length': 999 }); res.write('{'); setImmediate(() => res.destroy(new Error(key))); }
  });
  for (mode of ['advertised', 'streamed', 'utf8', 'partial']) {
    await assert.rejects(readSecureProfileIdentity(origin, key, operation().context), refused);
  }
  assert.equal(calls, 4);
});

test('secure identity strips arbitrary errors and rejects reflected identifiers/scopes and non-200 responses', async t => {
  let status = 200, payload, calls = 0;
  const origin = await fixture(t, (_req, res) => { calls++; res.writeHead(status); res.end(payload); });
  const cases = [[401, key], [503, 'BODY_CANARY'], [201, JSON.stringify(identity)], [204, ''], [200, '{RAW_DETAIL'],
    ...['project_id', 'organization_id', 'key_id', 'scopes'].map(field => [200, JSON.stringify({ ...identity,
      [field]: field === 'scopes' ? [key] : `prefix_${key}` })])];
  for ([status, payload] of cases) await assert.rejects(readSecureProfileIdentity(origin, key, operation().context), refused);
  assert.equal(calls, cases.length);
});

test('secure identity reevaluates the original budget after network/body work', async t => {
  const op = operation();
  const origin = await fixture(t, (_req, res) => { op.expire(); res.end(JSON.stringify(identity)); });
  await assert.rejects(readSecureProfileIdentity(origin, key, op.context), refused);
});
