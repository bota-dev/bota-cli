/** Private shared REST/MCP invocation assembly. No native store, default
 * deployment, profile selector, login command or credential migration. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { DelegatedFamilyEngine, type DelegatedFamilyContext, type DelegatedVerifiedAccess } from './delegated-family-engine.js';
import { delegatedFamilyIdentity, delegatedFamilyKey, familyObject, sameFamilySet, type DelegatedFamilyKey } from './delegated-family-state.js';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';

type Kind = 'rest' | 'mcp';
type Failure = 'invalid_input' | 'binding_mismatch' | 'wrong_resource' | 'unsupported_operation'
  | 'cancelled' | 'deadline' | 'retired' | 'operation_failed';
const genuine = new WeakMap<object, Failure>();
export class DelegatedInvocationError extends Error {
  constructor(readonly code: Failure = 'operation_failed') {
    super('The selected developer session cannot perform this operation.');
    this.name = 'DelegatedInvocationError'; genuine.set(this, code);
  }
}
export function delegatedInvocationFailure(error: unknown): Failure | undefined {
  return error && typeof error === 'object' && !types.isProxy(error) ? genuine.get(error) : undefined;
}
function refuse(code: Failure = 'invalid_input'): never { throw new DelegatedInvocationError(code); }
const nativeFetch = globalThis.fetch.bind(globalThis);
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const statusOf = Object.getOwnPropertyDescriptor(Response.prototype, 'status')!.get!;
const bodyOf = Object.getOwnPropertyDescriptor(Response.prototype, 'body')!.get!;
const headersOf = Object.getOwnPropertyDescriptor(Response.prototype, 'headers')!.get!;
const redirectedOf = Object.getOwnPropertyDescriptor(Response.prototype, 'redirected')!.get!;
const header = Headers.prototype.get;
const getReader = ReadableStream.prototype.getReader;
const read = ReadableStreamDefaultReader.prototype.read;
const cancelReader = ReadableStreamDefaultReader.prototype.cancel;
const release = ReadableStreamDefaultReader.prototype.releaseLock;
const maxBodyBytes = 1024 * 1024;
const maxMilliseconds = 30_000;
interface Scope {
  readonly deployment: DelegatedLoginDeployment; readonly kind: Kind; readonly resource: string;
  readonly accessToken: string; readonly identity: DelegatedVerifiedAccess;
  readonly signal: AbortSignal; readonly transport: typeof fetch;
  check(): void;
  cleanupFailed(): void;
  own<T>(kind: 'rest' | 'transport', work: () => Promise<T>): Promise<T>;
}
const local = new AsyncLocalStorage<Scope>();
export function hasDelegatedInvocation(): boolean { return local.getStore() !== undefined; }
/** Compatibility readers must refuse inside a delegated scope, including its
 * retired asynchronous descendants. No API key/profile fallback is permitted. */
export function refuseDelegatedCompatibility(): void { if (local.getStore()) refuse('wrong_resource'); }
export function captureDelegatedInvocationAccess(): () => void {
  const expected = local.getStore();
  return () => {
    if (local.getStore() !== expected) refuse('binding_mismatch');
    expected?.check();
  };
}
export function assertDelegatedInvocationActive(): void { local.getStore()?.check(); }

export interface DelegatedInvocationBinding {
  readonly stage: 'private-shared-delegated-invocation';
  run<T>(kind: Kind, context: DelegatedFamilyContext, action: () => Promise<T>): Promise<T>;
  requestAuth(kind: Kind): <T>(signal: AbortSignal, action: () => Promise<T>) => Promise<T>;
}
export async function bindDelegatedInvocation(engine: DelegatedFamilyEngine, key: DelegatedFamilyKey,
  deployment: unknown, context: DelegatedFamilyContext): Promise<DelegatedInvocationBinding> {
  return bindDelegatedInvocationForTrustedPorts(engine, key, deployment, context, { fetch: nativeFetch });
}
/** Trusted source/fixture composition only. No input, env or saved metadata can
 * replace transport or select a persistence/locking implementation. */
export async function bindDelegatedInvocationForTrustedPorts(engine: DelegatedFamilyEngine, inputKey: DelegatedFamilyKey,
  inputDeployment: unknown, context: DelegatedFamilyContext, ports: { readonly fetch: typeof fetch }): Promise<DelegatedInvocationBinding> {
  const key = delegatedFamilyKey(inputKey), deployment = parseDelegatedLoginDeployment(inputDeployment);
  const input = familyObject(ports, ['fetch']);
  if (types.isProxy(engine) || !(engine instanceof DelegatedFamilyEngine) || typeof input.fetch !== 'function' || types.isProxy(input.fetch)
    || key.issuer !== deployment.issuer || key.clientId !== deployment.client.clientId) refuse();
  const transport = input.fetch as typeof fetch;
  const snapshot = await engine.inspect(key, context);
  if (!snapshot || snapshot.state !== 'ready' || JSON.stringify(snapshot.deployment) !== JSON.stringify(deployment)) refuse('binding_mismatch');
  const expected = delegatedFamilyIdentity(snapshot.binding, deployment);
  async function run<T>(kind: Kind, parent: DelegatedFamilyContext, action: () => Promise<T>): Promise<T> {
    if (local.getStore() || !['rest', 'mcp'].includes(kind) || !deployment.client.resourceKinds.includes(kind)
      || !expected.grantResourceUris.includes(deployment.resources[kind]) || typeof action !== 'function' || types.isProxy(action)) refuse();
    const fields = familyObject(parent, ['signal', 'budget']);
    if (types.isProxy(fields.signal) || !fields.budget || typeof fields.budget !== 'object' || types.isProxy(fields.budget)) refuse();
    const assertion = Object.getOwnPropertyDescriptor(fields.budget, 'assertActive');
    if (!assertion || !Object.hasOwn(assertion, 'value') || typeof assertion.value !== 'function' || types.isProxy(assertion.value)) refuse();
    const signal = fields.signal as AbortSignal, budget = fields.budget as DelegatedFamilyContext['budget'];
    try { aborted.call(signal); } catch { return refuse(); }
    const controller = new AbortController(), until = performance.now() + maxMilliseconds;
    let live = true, expired = false;
    const stop = () => controller.abort();
    const timer = setTimeout(() => { expired = true; stop(); }, maxMilliseconds);
    EventTarget.prototype.addEventListener.call(signal, 'abort', stop, { once: true });
    const check = () => {
      if (!live) refuse('retired');
      if (expired || performance.now() >= until) refuse('deadline');
      if (aborted.call(signal) || aborted.call(controller.signal)) refuse('cancelled');
      const current = familyObject(parent, ['signal', 'budget']);
      const currentAssertion = Object.getOwnPropertyDescriptor(budget, 'assertActive');
      if (current.signal !== signal || current.budget !== budget || !currentAssertion || !Object.hasOwn(currentAssertion, 'value')
        || currentAssertion.value !== assertion.value) refuse('binding_mismatch');
      try { assertion.value.call(budget); } catch { return refuse('deadline'); }
      const after = familyObject(parent, ['signal', 'budget']), afterAssertion = Object.getOwnPropertyDescriptor(budget, 'assertActive');
      if (after.signal !== signal || after.budget !== budget || !afterAssertion || !Object.hasOwn(afterAssertion, 'value')
        || afterAssertion.value !== assertion.value) refuse('binding_mismatch');
      if (aborted.call(signal) || aborted.call(controller.signal)) refuse('cancelled');
      if (expired || performance.now() >= until) refuse('deadline');
    };
    const owned = Object.freeze({ signal: controller.signal, budget: Object.freeze({ assertActive: check }) });
    let admittedExpiry: number | undefined;
    try {
      check();
      const result = await engine.withAccess(key, deployment.resources[kind], owned, async access => {
        check();
        admittedExpiry = access.identity.expiresAtSeconds;
        const identityFields = ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId', 'grantResourceUris', 'grantScopes'] as const;
        const actual = delegatedFamilyIdentity(Object.fromEntries(identityFields.map(name => [name, access.identity[name]])), deployment);
        if (['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId'].some(name =>
          actual[name as keyof typeof actual] !== expected[name as keyof typeof expected])
          || !sameFamilySet(actual.grantResourceUris, expected.grantResourceUris) || !sameFamilySet(actual.grantScopes, expected.grantScopes)
          || access.resource !== deployment.resources[kind] || access.identity.resource !== access.resource) refuse('binding_mismatch');
        let active = true, transportFailed = false;
        const network = new AbortController(), pending = new Map<Promise<unknown>, 'rest' | 'transport'>();
        const stopNetwork = () => network.abort();
        EventTarget.prototype.addEventListener.call(controller.signal, 'abort', stopNetwork, { once: true });
        if (aborted.call(controller.signal)) stopNetwork();
        const scope: Scope = Object.freeze({ deployment, kind, resource: access.resource, accessToken: access.accessToken,
          identity: access.identity, signal: network.signal, transport,
          check() { check(); if (!active) refuse('retired');
            if (aborted.call(network.signal)) refuse('cancelled');
            if (Math.floor(Date.now() / 1000) >= access.identity.expiresAtSeconds) refuse('deadline'); },
          cleanupFailed() { transportFailed = true; },
          own<T>(kind: 'rest' | 'transport', work: () => Promise<T>): Promise<T> {
            scope.check();
            const operation = Promise.resolve().then(() => { scope.check(); return work(); });
            pending.set(operation, kind);
            // Optional MCP GET cancellation is expected when its owner closes.
            // A rejection while the scope is live, or uncertain native cleanup
            // reported below, must still prevent publishing action success.
            void operation.catch(() => { if (kind === 'transport' && active && !aborted.call(network.signal)) transportFailed = true; });
            void operation.finally(() => pending.delete(operation)).catch(() => undefined);
            return operation;
          } });
        let result: T | undefined, failed = false;
        try { result = await local.run(scope, action); scope.check(); }
        catch { failed = true; }
        finally {
          // Returning from an action cannot abandon a started REST operation.
          // MCP's SDK may still own its optional GET's cancellation; join that
          // transport work too, before leaving the actual family lease.
          if ([...pending.values()].includes('rest')) failed = true;
          active = false; network.abort();
          while (pending.size) await Promise.allSettled([...pending.keys()]);
          EventTarget.prototype.removeEventListener.call(controller.signal, 'abort', stopNetwork);
        }
        check();
        if (Math.floor(Date.now() / 1000) >= access.identity.expiresAtSeconds) refuse('deadline');
        if (failed || transportFailed) refuse('operation_failed');
        return result as T;
      });
      // The lease implementation may itself await durable release after the
      // access callback. Admission must still be current when that join ends.
      check();
      if (admittedExpiry === undefined || Math.floor(Date.now() / 1000) >= admittedExpiry) refuse('deadline');
      return result;
    } finally {
      live = false; controller.abort(); clearTimeout(timer);
      EventTarget.prototype.removeEventListener.call(signal, 'abort', stop);
    }
  }
  return Object.freeze({ stage: 'private-shared-delegated-invocation' as const, run,
    requestAuth: (kind: Kind) => <T>(signal: AbortSignal, action: () => Promise<T>) =>
      run(kind, Object.freeze({ signal, budget: Object.freeze({ assertActive() {} }) }), action) });
}

export interface DelegatedRestInvocation {
  request(method: string, path: string, body?: unknown, params?: Record<string, string | number | undefined>): Promise<Response>;
}
const restScopes: Readonly<Record<string, string>> = Object.freeze({ 'end-users': 'end_users:read', devices: 'devices:read',
  recordings: 'recordings:read', transcriptions: 'transcriptions:read', summaries: 'summaries:read' });
export function captureDelegatedRestInvocation(options: { apiKey?: string; apiUrl?: string }): DelegatedRestInvocation | undefined {
  const scope = local.getStore(); if (!scope) return undefined;
  scope.check(); if (scope.kind !== 'rest') refuse('wrong_resource');
  if (options.apiKey !== undefined || options.apiUrl !== undefined) refuse('binding_mismatch');
  const assertCurrent = captureDelegatedInvocationAccess();
  return Object.freeze({ request(method: string, path: string, body?: unknown, params?: Record<string, string | number | undefined>) {
    return scope.own('rest', async () => {
    assertCurrent();
    const match = typeof path === 'string' ? /^\/v1\/(end-users|devices|recordings|transcriptions|summaries)(?:\/([A-Za-z0-9_-]{1,256}))?$/.exec(path) : null;
    const identity = path === '/v1/auth/delegated-identity';
    if (method !== 'GET' || body !== undefined || !match && !identity || match?.[1] === 'devices' && match[2] === 'stats') refuse('unsupported_operation');
    if (match && !scope.identity.accessScopes.includes(restScopes[match[1]!]!)) refuse('unsupported_operation');
    const url = new URL(scope.resource + path.slice('/v1'.length));
    if (params !== undefined) {
      if (!params || typeof params !== 'object' || types.isProxy(params) || ![Object.prototype, null].includes(Object.getPrototypeOf(params))) refuse();
      const keys = Object.keys(params), value = familyObject(params, keys);
      if (Reflect.ownKeys(params).length > 16) refuse();
      for (const [key, item] of Object.entries(value)) {
        if (!['limit', 'cursor', 'external_id', 'end_user_id', 'device_id', 'status', 'start_date', 'end_date', 'recording_id', 'transcription_id'].includes(key)
          || item !== undefined && (typeof item !== 'string' && typeof item !== 'number' || typeof item === 'number' && !Number.isFinite(item))) refuse();
        if (item !== undefined) { const text = String(item); if (text.length > 2048 || /[\x00-\x1f\x7f]/.test(text)) refuse(); url.searchParams.set(key, text); }
      }
    }
    if (identity && url.search || url.href.length > 16384) refuse();
    return joinedResponse(scope, url, { method: 'GET', headers: { Authorization: `Bearer ${scope.accessToken}`, Accept: 'application/json' },
      redirect: 'error', credentials: 'omit', signal: scope.signal }, true);
    });
  } });
}

/** Buffer only the selected JSON-response cohort and join native reader/body
 * cleanup before giving a copied response to a client or SDK. */
async function joinedResponse(scope: Scope, url: Parameters<typeof fetch>[0], init: RequestInit, rest: boolean): Promise<Response> {
    const assertCurrent = captureDelegatedInvocationAccess();
    let response: Response | undefined, stream: ReadableStream<Uint8Array> | null = null;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined, output: Response | undefined;
    const chunks: Uint8Array[] = []; let failed = false;
    try {
      assertCurrent(); response = await scope.transport(url, { ...init, redirect: 'error', credentials: 'omit',
        signal: init.signal ? AbortSignal.any([scope.signal, init.signal]) : scope.signal });
      assertCurrent(); stream = bodyOf.call(response);
      const headers = headersOf.call(response), length = header.call(headers, 'content-length'), status = statusOf.call(response);
      const empty = !rest && (init.method === 'GET' && status === 405 || init.method === 'POST' && status === 202);
      if (status !== 200 && !empty || redirectedOf.call(response) || !stream && !empty
        || !rest && init.method === 'GET' && status !== 405
        || !empty && !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(header.call(headers, 'content-type') ?? '')
        || header.call(headers, 'content-encoding') !== null
        || !rest && header.call(headers, 'mcp-session-id') !== null
        || length !== null && (!/^\d{1,7}$/.test(length) || Number(length) > maxBodyBytes)) refuse('operation_failed');
      let size = 0;
      if (stream) { reader = getReader.call(stream) as ReadableStreamDefaultReader<Uint8Array>;
      for (;;) {
        assertCurrent(); const item = await read.call(reader); assertCurrent(); if (item.done) break;
        if (types.isProxy(item.value) || !types.isUint8Array(item.value)) refuse('operation_failed');
        size += item.value.byteLength; if (size > maxBodyBytes) refuse('operation_failed'); chunks.push(Uint8Array.from(item.value));
      } }
      if (length !== null && Number(length) !== size || empty && size !== 0) refuse('operation_failed');
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (!empty) JSON.parse(text);
        output = new Response(empty ? null : text, { status, headers: empty ? {} : { 'Content-Type': 'application/json' } }); }
      finally { bytes.fill(0); }
    } catch { failed = true; }
    finally {
      try { if (reader) await cancelReader.call(reader); else if (stream) await stream.cancel(); else if (response) await bodyOf.call(response)?.cancel(); }
      catch { failed = true; scope.cleanupFailed(); }
      try { if (reader) release.call(reader); } catch { failed = true; scope.cleanupFailed(); }
      chunks.forEach(chunk => chunk.fill(0));
      try { assertCurrent(); } catch { failed = true; }
    }
    if (failed || !output) refuse('operation_failed'); return output;
}
export function captureDelegatedMcpInvocation(): Readonly<{ url: string; accessToken: string; signal: AbortSignal; assertActive(): void;
  authorizeTool(name: string): void; fetch: typeof fetch }> | undefined {
  const scope = local.getStore(); if (!scope) return undefined;
  scope.check(); if (scope.kind !== 'mcp') refuse('wrong_resource');
  const assertActive = captureDelegatedInvocationAccess();
  return Object.freeze({ url: scope.resource, accessToken: scope.accessToken, signal: scope.signal, assertActive,
    authorizeTool(name: string) {
      assertActive();
      const required: Readonly<Record<string, readonly string[]>> = {
        get_delegated_identity: [], list_end_users: ['end_users:read'], get_end_user: ['end_users:read'],
        list_devices: ['devices:read'], get_device: ['devices:read'], list_recordings: ['recordings:read'],
        get_recording: ['recordings:read', 'transcriptions:read', 'summaries:read'],
      };
      if (typeof name !== 'string' || !Object.hasOwn(required, name) || !required[name]!.every(value => scope.identity.accessScopes.includes(value))) refuse('unsupported_operation');
    },
    fetch: async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      assertActive(); const url = input instanceof URL ? input.href : typeof input === 'string' ? input : undefined;
      if (url !== scope.resource) refuse('binding_mismatch');
      const headers = new Headers(init?.headers);
      if (!init || !['GET', 'POST'].includes(init.method ?? '') || headers.get('authorization') !== `Bearer ${scope.accessToken}`
        || headers.has('cookie') || headers.has('mcp-session-id')) refuse('binding_mismatch');
      return scope.own('transport', () => joinedResponse(scope, input, init, false));
    } });
}
