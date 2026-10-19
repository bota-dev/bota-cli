import assert from 'node:assert/strict';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';
import { BotaClient, safeIntegrationTest } from '../src/client.ts';
import { MAX_INTEGRATION_KEY_BYTES, readIntegrationKey } from '../src/commands/integrations.ts';
import { fixture, json, runCli } from './helpers.mjs';

export const integration = {
  id: '11111111-1111-4111-8111-111111111111', project_id: '22222222-2222-4222-8222-222222222222',
  provider_type: 'asr', provider_name: 'deepgram', is_enabled: true,
  last_used_at: null, created_at: '2026-10-18T00:00:00.000Z', updated_at: '2026-10-19T00:00:00.000Z',
};
const safe = { ...integration, has_error: true };
const secret = 'PROVIDER_SECRET_SENTINEL';
const unsafe = { ...integration, last_error: `provider URL?key=${secret}`, api_key: secret, encrypted_key: secret, key_hint: secret, wrapped_dek: secret, key_nonce: secret };

test('integration CLI maps every management command and displays only safe metadata', async t => {
  const expected = [
    ['GET', '/v1/integrations', ''],
    ['GET', '/v1/integrations/asr/deepgram', ''],
    ['POST', '/v1/integrations', { provider_type: 'asr', provider_name: 'deepgram', api_key: secret }],
    ['PATCH', `/v1/integrations/${integration.id}`, { api_key: secret }],
    ['PATCH', `/v1/integrations/${integration.id}`, { is_enabled: true }],
    ['PATCH', `/v1/integrations/${integration.id}`, { is_enabled: false }],
    ['DELETE', `/v1/integrations/${integration.id}`, ''],
    ['DELETE', '/v1/integrations/asr/deepgram', ''],
    ['POST', '/v1/integrations/asr/deepgram/test', {}],
  ];
  const api = await fixture(t, (req, res) => {
    const [method, path, body] = expected.shift();
    assert.equal(req.method, method); assert.equal(req.url, path);
    assert.deepEqual(req.body ? JSON.parse(req.body) : '', body);
    assert.equal(req.headers['idempotency-key'], undefined);
    if (method === 'DELETE') { res.writeHead(204); res.end(); return; }
    if (path.endsWith('/test')) return json(res, { success: true, message: `unsafe ${secret}`, api_key: secret });
    json(res, path === '/v1/integrations' && method === 'GET' ? { data: [unsafe], secret } : unsafe);
  });
  const commands = [
    ['list'], ['get', 'asr', 'deepgram'], ['set', 'asr', 'deepgram', '--key-stdin'], ['rotate', integration.id, '--key-stdin'],
    ['enable', integration.id], ['disable', integration.id], ['delete', integration.id], ['delete-provider', 'asr', 'deepgram'], ['test', 'asr', 'deepgram'],
  ];
  for (const args of commands) {
    const result = await runCli(t, api.url, ['integrations', ...args, '--json'], args.includes('--key-stdin') ? `${secret}\r\n` : undefined);
    assert.equal(result.code, 0, result.stderr);
    assert.doesNotMatch(result.stdout + result.stderr, /PROVIDER_SECRET|last_error|encrypted_key|api_key|key_hint|wrapped_dek|key_nonce/);
    const value = JSON.parse(result.stdout);
    if (args[0] === 'list') assert.deepEqual(value, { data: [safe] });
    else if (args[0] === 'test') assert.deepEqual(value, { success: true, code: 'credential_valid', message: 'The provider accepted the basic credential check.' });
    else if (args[0].startsWith('delete')) assert.deepEqual(value, { deleted: true });
    else assert.deepEqual(value, safe);
  }
  assert.equal(expected.length, 0);
});

test('integration human output omits provider material and raw errors', async t => {
  const api = await fixture(t, (_req, res) => json(res, { data: [unsafe] }));
  const result = await runCli(t, api.url, ['integrations', 'list']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /has_error/);
  assert.match(result.stdout, /deepgram/);
  assert.doesNotMatch(result.stdout + result.stderr, /PROVIDER_SECRET|last_error|encrypted_key|key_hint|wrapped_dek|key_nonce/);
});

test('integration parser, identifiers, and stdin fail before network without echoing supplied values', async t => {
  const api = await fixture(t, (_req, res) => json(res, unsafe));
  const cases = [
    [['set', 'asr', 'deepgram'], undefined],
    [['set', 'asr', 'deepgram', `--api-key=${secret}`], undefined],
    [[secret], undefined],
    [['set', 'asr', 'deepgram', secret], undefined],
    [['get', secret, 'deepgram'], undefined],
    [['get', 'asr', secret], undefined],
    [['rotate', secret, '--key-stdin'], `${secret}\n`],
    [['set', 'asr', 'deepgram', '--key-stdin'], ''],
    [['set', 'asr', 'deepgram', '--key-stdin'], `${secret}\nsecond-line`],
    [['set', 'asr', 'deepgram', '--key-stdin'], Buffer.from([0xff, 0xfe])],
    [['set', 'asr', 'deepgram', '--key-stdin'], 'x'.repeat(MAX_INTEGRATION_KEY_BYTES + 1)],
    [['test', 'asr', 'deepgram', '--key-stdin'], `${secret}\n`],
  ];
  for (const [args, input] of cases) {
    const result = await runCli(t, api.url, ['integrations', ...args, '--json'], input);
    assert.equal(result.code, 1, result.stdout);
    assert.doesNotMatch(result.stdout + result.stderr, /PROVIDER_SECRET_SENTINEL|second-line/);
    assert.ok(JSON.parse(result.stderr).error.message);
  }
  assert.equal(api.requests.length, 0);
  const unrelated = await runCli(t, api.url, ['devices', 'list', '--not-an-option']);
  assert.match(unrelated.stderr, /unknown option/);
  assert.doesNotMatch(unrelated.stderr, /Invalid integration command/);
});

test('stdin input rejects TTY and timeout without leaving an active stream', async t => {
  const tty = new PassThrough(); tty.isTTY = true;
  await assert.rejects(readIntegrationKey(tty), /Pipe one provider API key/);
  tty.destroy();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const hanging = new PassThrough();
  const result = readIntegrationKey(hanging);
  t.mock.timers.tick(30_000);
  await assert.rejects(result, /timed out/);
  assert.equal(hanging.destroyed, true);
});

test('stdin counts bytes and keeps a single LF/CRLF terminator out of the request', async () => {
  assert.equal(await readIntegrationKey(Readable.from([Buffer.from(`${secret}\n`)])), secret);
  assert.equal(await readIntegrationKey(Readable.from([Buffer.from(`${secret}\r\n`)])), secret);
  await assert.rejects(readIntegrationKey(Readable.from([Buffer.from('é'.repeat(MAX_INTEGRATION_KEY_BYTES))])), /16 KiB/);
  await assert.rejects(readIntegrationKey(Readable.from([Buffer.from(`${secret}\n\n`)])), /one nonempty/);
});

test('integration client sanitizes errors and malformed credential-bearing responses', async t => {
  let malformed = false;
  const api = await fixture(t, (_req, res) => {
    if (malformed) return json(res, { ...unsafe, id: secret });
    res.setHeader('X-Request-Id', secret); res.setHeader('Retry-After', secret);
    json(res, { error: { code: 'insufficient_permissions', message: secret, param: secret, request_id: secret }, secret }, 403);
  });
  const result = await runCli(t, api.url, ['integrations', 'list', '--json']);
  assert.equal(result.code, 1);
  assert.deepEqual(JSON.parse(result.stderr), { error: { message: 'This credential does not grant the required integration scope.', status: 403, code: 'insufficient_permissions' } });
  assert.doesNotMatch(result.stdout + result.stderr, /PROVIDER_SECRET/);
  malformed = true;
  const client = new BotaClient({ apiKey: 'sk_test_fixture', apiUrl: api.url });
  await assert.rejects(client.getIntegration('asr', 'deepgram'), error => { assert.doesNotMatch(JSON.stringify(error) + error.message, /PROVIDER_SECRET/); return true; });
  assert.equal(api.requests.length, 2);
});

test('integration stored-key checks retain safe hosted result parity and fail the CLI exit status', async t => {
  const cases = [
    [{ success: true, message: 'API key is valid' }, { success: true, code: 'credential_valid', message: 'The provider accepted the basic credential check.' }],
    [{ success: false, message: 'Invalid API key' }, { success: false, code: 'credential_rejected', message: 'The provider rejected the stored credential.' }],
    [{ success: false, message: 'No API key configured for this provider' }, { success: false, code: 'credential_missing', message: 'No enabled stored credential is available for this provider.' }],
    [{ success: false, message: 'API error: 429' }, { success: false, code: 'provider_rate_limited', message: 'The provider rate limited the credential check.', provider_status: 429 }],
    [{ success: false, message: `URL?key=${secret}` }, { success: false, code: 'provider_test_failed', message: 'The basic provider credential check failed.' }],
  ];
  for (const [legacy, hosted] of cases) assert.deepEqual(safeIntegrationTest(legacy), safeIntegrationTest(hosted));
  const api = await fixture(t, (req, res) => {
    assert.equal(req.url, '/v1/integrations/asr/deepgram/test'); assert.deepEqual(JSON.parse(req.body), {});
    json(res, cases[1][0]);
  });
  const result = await runCli(t, api.url, ['integrations', 'test', 'asr', 'deepgram', '--json']);
  assert.equal(result.code, 1);
  assert.deepEqual(JSON.parse(result.stdout), cases[1][1]);
  assert.equal(result.stderr, '');
  assert.equal(api.requests.length, 1);
});
