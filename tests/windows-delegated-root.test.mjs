import assert from 'node:assert/strict';
import test from 'node:test';
import { getWindowsDelegatedRoot } from '../src/windows-delegated-root.ts';

const code = expected => error => { assert.equal(error.code, expected); assert.equal(error.cause, undefined); return true; };
test('delegated root rejects hostile context hooks before OS lookup and never evaluates them', async () => {
  let calls = 0;
  const signal = new AbortController().signal, budget = { assertActive() {} };
  for (const context of [null, new Proxy({}, { get() { calls++; throw Error('private'); } }),
    Object.defineProperty({ budget }, 'signal', { get() { calls++; throw Error('private'); } }),
    { signal, budget: Object.defineProperty({}, 'assertActive', { get() { calls++; throw Error('private'); } }) },
    { signal: new Proxy(signal, {}), budget }, { signal: {}, budget }])
    await assert.rejects(getWindowsDelegatedRoot(context), code('profile_invalid_input'));
  assert.equal(calls, 0);
});
test('delegated root uses native cancellation state despite a shadow aborted getter', async () => {
  const controller = new AbortController(); controller.abort(); let calls = 0;
  Object.defineProperty(controller.signal, 'aborted', { get() { calls++; throw Error('private'); } });
  await assert.rejects(getWindowsDelegatedRoot({ signal: controller.signal, budget: { assertActive() {} } }), code('profile_cancelled'));
  assert.equal(calls, 0);
});
test('delegated root maps private budget exceptions and refuses changed capabilities before lookup', async () => {
  await assert.rejects(getWindowsDelegatedRoot({ signal: new AbortController().signal,
    budget: { assertActive() { throw Error('private'); } } }), code('profile_deadline'));
  const context = { signal: new AbortController().signal, budget: { assertActive() {
    Object.defineProperty(context, 'signal', { get() { throw Error('must not execute'); } });
  } } };
  await assert.rejects(getWindowsDelegatedRoot(context), code('profile_invalid_input'));
});
