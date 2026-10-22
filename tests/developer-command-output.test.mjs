import assert from 'node:assert/strict';
import test from 'node:test';
import { bufferDeveloperCommandOutput, captureDeveloperOutput } from '../src/developer-command-output.ts';
import { DeveloperProfileError, developerProfileFailure, sanitizeDeveloperProfileError } from '../src/developer-profile-error.ts';
import { printJson, printTable, printDetail, printPagination, errorDetails } from '../src/output.ts';

const defer = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const refused = error => { assert.equal(developerProfileFailure(error)?.code, 'developer_output_failed'); return true; };

test('ordinary CLI helpers buffer until explicit publication after the caller joins cleanup', async () => {
  const published = [];
  const result = await bufferDeveloperCommandOutput(async () => {
    printJson({ data: ['owned'] }); printTable(['Name'], [['device']]); printDetail({ status: 'ready' });
    printPagination({ has_more: true, next_cursor: 'next' }); assert.equal(published.length, 0); return 7;
  }, 1024 * 1024);
  assert.equal(result.value, 7); assert.equal(published.length, 0);
  let joined = false;
  await assert.rejects(result.publish(() => { assert.equal(joined, true); }, async (...entry) => published.push(entry)), refused);
  assert.equal(published.length, 0);
});

test('success publishes channels in order only once after the guard succeeds', async () => {
  const result = await bufferDeveloperCommandOutput(async () => { printJson({ accepted: true }); printPagination({ has_more: true, next_cursor: 'c' }); return 'accepted'; }, 4096);
  const output = []; let guards = 0;
  await result.publish(() => { guards++; }, async (channel, text) => { output.push({ channel, text }); });
  assert.equal(output[0].channel, 'stdout'); assert.equal(output[1].channel, 'stderr');
  assert.match(output[0].text, /accepted/); assert.ok(guards >= 4);
  await assert.rejects(result.publish(() => {}, async () => {}), refused);
});

test('a failed action never returns a publish capability or releases partial output', async () => {
  await assert.rejects(bufferDeveloperCommandOutput(async () => { printJson({ privateBusinessResult: true }); throw new DeveloperProfileError('developer_recovery_required', true); }, 4096),
    error => developerProfileFailure(error)?.recovery_required === true);
  assert.equal(captureDeveloperOutput('stdout', 'ordinary output'), false);
});

test('retired asynchronous descendants cannot fall through to ordinary stdout', async () => {
  const release = defer(); let descendant;
  await bufferDeveloperCommandOutput(async () => { descendant = release.promise.then(() => assert.throws(() => printJson({ late: true }), refused)); }, 4096);
  release.resolve(); await descendant;
});

test('concurrent captures isolate data without process-wide output replacement', async () => {
  const gates = [defer(), defer()];
  const values = await Promise.all(['A', 'B'].map((value, index) => bufferDeveloperCommandOutput(async () => {
    gates[index].resolve(); await gates[1 - index].promise; printJson({ value });
  }, 4096)));
  for (const [index, value] of values.entries()) { const output = [];
    await value.publish(() => {}, async (_channel, text) => output.push(text));
    assert.equal(JSON.parse(output.join('')).value, ['A', 'B'][index]); }
});

test('bounded capture refuses overflow instead of truncating or publishing a partial result', async () => {
  await assert.rejects(bufferDeveloperCommandOutput(async () => { printJson({ value: 'long' }); }, 8), refused);
});

test('a failed publication joins the started writer and projects no private exception', async () => {
  const result = await bufferDeveloperCommandOutput(async () => { printJson({ value: 'safe' }); }, 4096);
  const entered = defer(), release = defer(); let settled = false;
  const writing = result.publish(() => {}, async () => { entered.resolve(); await release.promise; throw Error('PRIVATE_WRITER_CANARY'); }).finally(() => { settled = true; });
  void writing.catch(() => {}); await entered.promise; await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  release.resolve(); await assert.rejects(writing, error => { refused(error); assert.doesNotMatch(error.stack + JSON.stringify(error), /PRIVATE_WRITER_CANARY/); return true; });
});

test('deadline withdrawal between writes prevents later output', async () => {
  const result = await bufferDeveloperCommandOutput(async () => { printJson({ first: true }); printJson({ second: true }); }, 4096);
  let active = true, writes = 0;
  await assert.rejects(result.publish(() => { if (!active) throw Error('PRIVATE_GUARD'); }, async () => { writes++; active = false; }), refused);
  assert.equal(writes, 1);
});

test('renderer uses immutable branded failure facts instead of mutable message/cause', () => {
  const error = new DeveloperProfileError('developer_enrollment_unknown', true, true); error.message = 'PRIVATE_MUTABLE_ERROR'; error.code = 'PRIVATE_CODE'; error.cause = 'PRIVATE_CAUSE';
  const safe = errorDetails(error); assert.equal(safe.code, 'developer_enrollment_unknown'); assert.equal(safe.recovery_required, true);
  assert.doesNotMatch(JSON.stringify(safe), /PRIVATE_/);
  const copy = sanitizeDeveloperProfileError(error); assert.notEqual(copy, error); assert.doesNotMatch(copy.message + JSON.stringify(copy), /PRIVATE_/);
});

test('opaque error proxies and forged records never run private hooks', () => {
  let hooks = 0; const proxy = new Proxy({}, { get() { hooks++; throw Error('PRIVATE_HOOK'); }, getPrototypeOf() { hooks++; throw Error('PRIVATE_HOOK'); } });
  assert.equal(developerProfileFailure(proxy), undefined); assert.equal(developerProfileFailure({ code: 'developer_recovery_required' }), undefined);
  const safe = sanitizeDeveloperProfileError(proxy, true, true); assert.equal(safe.code, 'developer_operation_failed'); assert.equal(hooks, 0);
});
