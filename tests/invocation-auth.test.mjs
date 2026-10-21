import assert from 'node:assert/strict';
import test from 'node:test';
import { BotaClient, BotaApiError, callMcpTool } from '../src/client.ts';
import { assertInvocationActive, captureInvocationAccess, getApiKey, getApiUrl, getInvocationSignal,
  getProfileContext, isSecureInvocation, withInvocationCredential } from '../src/config.ts';
import { errorDetails } from '../src/output.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const keyA = 'rk_INVOCATION_A_CANARY', keyB = 'rk_INVOCATION_B_CANARY';
const originA = 'https://a.example.invalid', originB = 'https://b.example.invalid';
function credential(key = keyA, apiOrigin = originA) {
  return { apiKey: key, apiOrigin, source: 'store', profile: {}, identity: {
    project_id: key === keyA ? 'project:a' : 'project:b', organization_id: 'organization:synthetic',
    key_id: key === keyA ? 'key:a' : 'key:b', key_type: 'restricted', scope_mode: 'restricted', scopes: [], is_test_mode: false,
  } };
}
function operation() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, context: { signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error(keyA); } } } };
}
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function refused(code, possible) {
  return error => {
    assert.ok(error instanceof NativeProfileTransactionError); assert.equal(error.code, code);
    if (possible !== undefined) assert.equal(error.operation_may_have_executed, possible);
    assert.doesNotMatch(error.stack + JSON.stringify(error), /INVOCATION_[AB]_CANARY|RAW_DETAIL/);
    return true;
  };
}
async function mockedFetch(t, handler) {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async (...args) => { calls++; return handler(...args); };
  t.after(() => { globalThis.fetch = original; });
  return () => calls;
}

test('secure invocation getters stay in the current asynchronous action and do not publish a process-wide selection', async () => {
  const op = operation(); assert.equal(isSecureInvocation(), false);
  await withInvocationCredential(credential(), op.context, async () => {
    assert.equal(isSecureInvocation(), true); assert.equal(getApiKey(), keyA); assert.equal(getApiUrl(originB), originA);
    assert.equal(getInvocationSignal(), op.context.signal);
    assert.equal(Object.keys(getProfileContext()).includes('apiKey'), false);
    await Promise.resolve(); assert.equal(getApiKey(), keyA); assert.equal(getProfileContext().identity.project_id, 'project:a');
  });
  assert.equal(isSecureInvocation(), false); assert.equal(op.context.signal.aborted, false);
});

test('a client from a settled secure invocation cannot send its credential outside that invocation', async t => {
  const calls = await mockedFetch(t, () => new Response('{}')); const op = operation(); let client;
  await withInvocationCredential(credential(), op.context, async () => { client = new BotaClient(); });
  assert.equal(op.context.signal.aborted, false, 'caller-owned signal is deliberately still active');
  await assert.rejects(client.get('/v1/synthetic'), refused('profile_binding_mismatch'));
  assert.equal(calls(), 0);
});

test('a client cannot be borrowed by a different invocation, even when both use the same operation context', async t => {
  const calls = await mockedFetch(t, () => new Response('{}')); const op = operation(); let client;
  await withInvocationCredential(credential(), op.context, async () => { client = new BotaClient(); });
  await withInvocationCredential(credential(keyB, originB), op.context, async () => {
    await assert.rejects(client.get('/v1/synthetic'), refused('profile_binding_mismatch'));
  });
  assert.equal(calls(), 0);
});

test('a compatibility client cannot override an explicitly selected secure invocation', async t => {
  const calls = await mockedFetch(t, () => new Response('{}'));
  // Both explicit synthetic values avoid reading legacy files/environment.
  const client = new BotaClient({ apiKey: keyB, apiUrl: originB });
  await withInvocationCredential(credential(), operation().context, async () => {
    await assert.rejects(client.get('/v1/synthetic'), refused('profile_binding_mismatch'));
  });
  assert.equal(calls(), 0);
});

test('retired asynchronous descendants keep a revoked scope and cannot fall through to compatibility credentials', async t => {
  const calls = await mockedFetch(t, () => new Response('{}')); const gate = deferred(); let descendant;
  await withInvocationCredential(credential(), operation().context, async () => {
    const client = new BotaClient(); const access = captureInvocationAccess();
    descendant = (async () => {
      await gate.promise;
      assert.equal(isSecureInvocation(), true);
      assert.throws(access, refused('profile_operation_failed', true));
      assert.throws(getApiKey, refused('profile_operation_failed', true));
      await assert.rejects(client.get('/v1/synthetic'), refused('profile_operation_failed', true));
    })();
  });
  gate.resolve(); await descendant; assert.equal(calls(), 0);
});

test('concurrent secure actions keep origins, credentials, signals and identities isolated', async t => {
  const observed = [];
  await mockedFetch(t, async (url, init) => {
    observed.push({ url: String(url), bearer: init.headers.Authorization });
    await new Promise(resolve => setImmediate(resolve)); return Response.json({ origin: new URL(String(url)).origin });
  });
  const both = [deferred(), deferred()];
  const action = (index, selected) => withInvocationCredential(selected, operation().context, async () => {
    const client = new BotaClient(); both[index].resolve(); await both[1 - index].promise;
    assert.equal(getApiKey(), selected.apiKey);
    const result = await client.get('/v1/synthetic'); assert.equal(result.origin, selected.apiOrigin);
    assert.equal(getProfileContext().identity.project_id, selected.identity.project_id);
  });
  await Promise.all([action(0, credential()), action(1, credential(keyB, originB))]);
  assert.equal(observed.length, 2);
  for (const item of observed) assert.equal(item.bearer, `Bearer ${item.url.startsWith(originA) ? keyA : keyB}`);
});

test('secure clients and MCP calls reject explicit origin/key mismatches before any transport send', async t => {
  const calls = await mockedFetch(t, () => new Response('{}'));
  await withInvocationCredential(credential(), operation().context, async () => {
    for (const options of [{ apiUrl: originB }, { apiKey: keyB }, { apiUrl: originA, apiKey: keyB }]) {
      assert.throws(() => new BotaClient(options), refused('profile_binding_mismatch'));
    }
    await assert.rejects(callMcpTool(originB, keyA, 'synthetic', {}), refused('profile_binding_mismatch'));
    await assert.rejects(callMcpTool(originA, keyB, 'synthetic', {}), refused('profile_binding_mismatch'));
  });
  assert.equal(calls(), 0);
});

test('parent cancellation is propagated through the HTTP signal and blocks subsequent sends', async t => {
  const entered = deferred(); let fetchSignal;
  const calls = await mockedFetch(t, (_url, init) => {
    fetchSignal = init.signal; entered.resolve();
    return new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error(keyA)), { once: true }));
  });
  const op = operation();
  await withInvocationCredential(credential(), op.context, async () => {
    const client = new BotaClient(); const request = client.get('/v1/synthetic'); await entered.promise;
    op.controller.abort(keyA); assert.equal(fetchSignal.aborted, true); await assert.rejects(request);
    assert.throws(getApiKey, refused('profile_cancelled', true));
    await assert.rejects(client.get('/v1/synthetic'), refused('profile_cancelled', true));
  });
  assert.equal(calls(), 1);
});

test('the same caller budget is checked before each send and preserves fixed deadline uncertainty', async t => {
  const calls = await mockedFetch(t, () => new Response('{}')); const op = operation();
  await withInvocationCredential(credential(), op.context, async () => {
    const client = new BotaClient(); op.expire();
    assert.throws(assertInvocationActive, refused('profile_deadline', true));
    await assert.rejects(client.get('/v1/synthetic'), refused('profile_deadline', true));
  });
  assert.equal(calls(), 0);
});

test('responses completing after scope retirement fail closed for both JSON and no-content operations', async t => {
  let pending;
  await mockedFetch(t, () => pending.promise);
  for (const status of [200, 204]) {
    pending = deferred(); let request;
    await withInvocationCredential(credential(), operation().context, async () => {
      request = new BotaClient().delete('/v1/synthetic');
    });
    pending.resolve(new Response(status === 204 ? null : '{}', { status }));
    await assert.rejects(request, refused('profile_operation_failed', true));
  }
});

test('scope retirement joins cancellation of an unread HTTP body before rejecting', async t => {
  const pending = deferred(), cancelled = deferred(); let request, cancellationStarted = false;
  await mockedFetch(t, () => pending.promise);
  await withInvocationCredential(credential(), operation().context, async () => {
    request = new BotaClient().get('/v1/synthetic');
  });
  let settled = false;
  const refusal = assert.rejects(request, refused('profile_operation_failed', true)).then(() => { settled = true; });
  pending.resolve(new Response(new ReadableStream({ cancel() { cancellationStarted = true; return cancelled.promise; } })));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancellationStarted, true); assert.equal(settled, false);
  cancelled.resolve(); await refusal; assert.equal(settled, true);
});

test('business errors inside secure actions are replaced with fixed diagnostics and outcome uncertainty', async t => {
  await mockedFetch(t, () => Response.json({ error: { message: `${keyA} RAW_DETAIL`, code: keyA,
    param: keyA, request_id: keyA } }, { status: 403, headers: { 'x-request-id': keyA, 'retry-after': keyA } }));
  await withInvocationCredential(credential(), operation().context, async () => {
    try { await new BotaClient().post('/v1/synthetic', {}); assert.fail('expected refusal'); }
    catch (error) {
      assert.ok(error instanceof BotaApiError);
      const safe = errorDetails(error); assert.equal(safe.code, 'profile_operation_failed');
      assert.equal(safe.operation_may_have_executed, true); assert.equal(safe.recovery_required, false);
      assert.doesNotMatch(JSON.stringify(safe), /INVOCATION_A_CANARY|RAW_DETAIL|request_id|retry_after|rate_limit/);
    }
    const safe = errorDetails(new NativeProfileTransactionError('profile_state_unknown', true, true));
    assert.equal(safe.recovery_required, true); assert.equal(safe.operation_may_have_executed, true);
  });
});

test('throwing actions retire scope access while preserving caller-owned context lifetime', async () => {
  const gate = deferred(); let descendant; const op = operation();
  await assert.rejects(withInvocationCredential(credential(), op.context, async () => {
    descendant = (async () => { await gate.promise; assert.throws(getApiKey, refused('profile_operation_failed', true)); })();
    throw new Error('synthetic-action-failure');
  }), /synthetic-action-failure/);
  gate.resolve(); await descendant; assert.equal(op.context.signal.aborted, false);
});
