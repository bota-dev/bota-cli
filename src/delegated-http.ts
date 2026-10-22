/** Inactive HTTP component. No command, browser, native store or identity route
 * is wired. Production and trusted fixture assembly are separate factories. */
import { types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { parseDelegatedLoginDeployment, readDelegatedLoginExchangeBinding,
  type DelegatedLoginAttempt, type DelegatedLoginDeployment } from './delegated-login.js';
import { delegatedFamilyIdentity, delegatedScopes, familyObject, familySeconds, familyServerUuid, familyStrings,
  sameFamilySet } from './delegated-family-state.js';
import type { DelegatedFamilyContext, DelegatedRevocationBinding, DelegatedTokenPair, DelegatedVerifiedAccess } from './delegated-family-engine.js';

export const DELEGATED_HTTP_LIMITS = Object.freeze({ timeoutMs: 30_000, maxBodyBytes: 16 * 1024, maxIssuedAccess: 128 });
const nativeFetch = globalThis.fetch.bind(globalThis);
const monotonic = performance.now.bind(performance);
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const listen = EventTarget.prototype.addEventListener, unlisten = EventTarget.prototype.removeEventListener;
const abort = AbortController.prototype.abort;
const statusOf = Object.getOwnPropertyDescriptor(Response.prototype, 'status')!.get!;
const bodyOf = Object.getOwnPropertyDescriptor(Response.prototype, 'body')!.get!;
const headersOf = Object.getOwnPropertyDescriptor(Response.prototype, 'headers')!.get!;
const redirectedOf = Object.getOwnPropertyDescriptor(Response.prototype, 'redirected')!.get!;
const getHeader = Headers.prototype.get;
const consumedAttempts = new WeakSet<DelegatedLoginAttempt>();
type Failure = 'http_configuration_invalid' | 'http_input_invalid' | 'http_cancelled' | 'http_deadline' | 'http_identity_failed' | 'http_unknown';
const failureCodes: readonly Failure[] = ['http_configuration_invalid', 'http_input_invalid', 'http_cancelled', 'http_deadline', 'http_identity_failed', 'http_unknown'];
const failures = new WeakMap<object, Readonly<{ code: Failure; mutationSubmitted: boolean }>>();
export class DelegatedHttpError extends Error {
  constructor(readonly code: Failure, readonly mutationSubmitted = false) {
    super('Developer authorization HTTP operation is invalid, unavailable or uncertain.'); this.name = 'DelegatedHttpError';
    this.code = failureCodes.includes(code) ? code : 'http_unknown'; this.mutationSubmitted = mutationSubmitted === true;
    failures.set(this, Object.freeze({ code: this.code, mutationSubmitted: this.mutationSubmitted }));
  }
}
function fail(code: Failure, submitted = false): never { throw new DelegatedHttpError(code, submitted); }
export type DelegatedIdentityVerifier = (deployment: DelegatedLoginDeployment, accessToken: string,
  resource: string, context: DelegatedFamilyContext) => Promise<unknown>;
export interface DelegatedHttpAdapter {
  readonly stage: 'inactive-one-attempt-http';
  exchangeCode(attempt: DelegatedLoginAttempt, context: DelegatedFamilyContext): Promise<DelegatedTokenPair>;
  exchange(deployment: DelegatedLoginDeployment, refresh: string, resource: string, context: DelegatedFamilyContext): Promise<DelegatedTokenPair>;
  verifyAccess(deployment: DelegatedLoginDeployment, access: string, resource: string, context: DelegatedFamilyContext): Promise<DelegatedVerifiedAccess>;
  revoke(deployment: DelegatedLoginDeployment, refresh: string, expected: DelegatedRevocationBinding,
    context: DelegatedFamilyContext): Promise<DelegatedRevocationBinding | 'unknown' | 'not_submitted'>;
}
export interface DelegatedHttpTrustedPorts {
  readonly fetch: typeof fetch;
  /** Mandatory read-only authority seam, with no store/SQL mutation capability.
   * Cancellation withdraws its authority and observes/discards late completion;
   * an uncooperative verifier can outlive public settlement. A future actual
   * HTTP verifier must additionally join its native response/body cleanup.
   * No identity URL, schema or route is inferred here. */
  readonly verifyAccess: DelegatedIdentityVerifier;
  readonly nowSeconds?: () => number;
  readonly timeoutMs?: number;
}
function secret(kind: 'access' | 'refresh' | 'code', value: unknown): value is string {
  const prefix = kind === 'access' ? 'bota_da1_' : kind === 'refresh' ? 'bota_dr1_' : 'bota_dc1_';
  return typeof value === 'string' && value.length === 52 && value.startsWith(prefix)
    && /^[A-Za-z0-9_-]{43}$/.test(value.slice(9)) && Buffer.from(value.slice(9), 'base64url').toString('base64url') === value.slice(9);
}
const identityFields = ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId', 'grantResourceUris', 'grantScopes'];
interface Scope { readonly context: DelegatedFamilyContext; check(): void; submitted(): void }
interface Access { readonly resource: string; readonly identity: DelegatedVerifiedAccess }

/** Production uses captured native fetch/TLS and a mandatory explicit authority
 * verifier. There is no discovery, environment fallback or test HTTP option. */
export function createDelegatedHttpAdapter(deployment: unknown, verifier: DelegatedIdentityVerifier): DelegatedHttpAdapter {
  return createDelegatedHttpAdapterForTrustedPorts(deployment, { fetch: nativeFetch, verifyAccess: verifier });
}
/** Trusted internal fixture/adapter assembly only. A transport replacement is
 * not evidence of production TLS, identity admission or native qualification. */
export function createDelegatedHttpAdapterForTrustedPorts(input: unknown, inputPorts: DelegatedHttpTrustedPorts): DelegatedHttpAdapter {
  let deployment: DelegatedLoginDeployment, transport: typeof fetch, verifier: DelegatedIdentityVerifier,
    clock: () => number, timeoutMs: number;
  try {
    deployment = parseDelegatedLoginDeployment(input);
    const ports = familyObject(inputPorts, ['fetch', 'verifyAccess'], ['nowSeconds', 'timeoutMs']);
    if (typeof ports.fetch !== 'function' || types.isProxy(ports.fetch) || typeof ports.verifyAccess !== 'function' || types.isProxy(ports.verifyAccess)
      || ports.nowSeconds !== undefined && (typeof ports.nowSeconds !== 'function' || types.isProxy(ports.nowSeconds))) fail('http_configuration_invalid');
    transport = ports.fetch as typeof fetch; verifier = ports.verifyAccess as DelegatedIdentityVerifier;
    clock = ports.nowSeconds as (() => number) | undefined ?? (() => Math.floor(Date.now() / 1000));
    timeoutMs = ports.timeoutMs as number | undefined ?? DELEGATED_HTTP_LIMITS.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DELEGATED_HTTP_LIMITS.timeoutMs) fail('http_configuration_invalid');
  } catch { return fail('http_configuration_invalid'); }
  const issued = new Map<string, Access>();
  function now(): number { const value = clock(); if (!familySeconds(value)) fail('http_input_invalid'); return value; }
  function selected(value: unknown): void {
    try { if (JSON.stringify(parseDelegatedLoginDeployment(value)) !== JSON.stringify(deployment)) fail('http_input_invalid'); }
    catch { fail('http_input_invalid'); }
  }
  function resource(value: unknown): asserts value is string {
    if (typeof value !== 'string' || !deployment.client.resourceKinds.some(kind => deployment.resources[kind] === value)) fail('http_input_invalid');
  }
  async function operation<T>(inputContext: DelegatedFamilyContext, work: (scope: Scope) => Promise<T>, publish?: (result: T) => void): Promise<T> {
    let parent: AbortSignal, budget: DelegatedFamilyContext['budget'], assertion: () => void;
    try {
      const fields = familyObject(inputContext, ['signal', 'budget']);
      if (types.isProxy(fields.signal) || !fields.budget || typeof fields.budget !== 'object' || types.isProxy(fields.budget)) fail('http_input_invalid');
      const own = Object.getOwnPropertyDescriptor(fields.budget, 'assertActive');
      if (!own || !Object.hasOwn(own, 'value') || typeof own.value !== 'function' || types.isProxy(own.value)) fail('http_input_invalid');
      aborted.call(fields.signal); parent = fields.signal as AbortSignal; budget = fields.budget as DelegatedFamilyContext['budget']; assertion = own.value;
    } catch { return fail('http_input_invalid'); }
    const child = new AbortController(), until = monotonic() + timeoutMs;
    let cancelled = false, deadline = false, retired = false, submitted = false;
    const stop = () => abort.call(child);
    const onAbort = () => { cancelled = true; stop(); };
    const sameAuthority = () => {
      const signalField = Object.getOwnPropertyDescriptor(inputContext, 'signal'), budgetField = Object.getOwnPropertyDescriptor(inputContext, 'budget');
      const assertionField = Object.getOwnPropertyDescriptor(budget, 'assertActive');
      return signalField && budgetField && assertionField && Object.hasOwn(signalField, 'value') && signalField.value === parent
        && Object.hasOwn(budgetField, 'value') && budgetField.value === budget && Object.hasOwn(assertionField, 'value') && assertionField.value === assertion;
    };
    const check = () => {
      if (retired) fail('http_unknown', submitted);
      if (cancelled || aborted.call(parent)) fail('http_cancelled', submitted);
      if (deadline || monotonic() >= until) { deadline = true; stop(); fail('http_deadline', submitted); }
      if (!sameAuthority()) fail('http_input_invalid', submitted);
      try { assertion.call(budget); } catch { fail('http_deadline', submitted); }
      if (cancelled || aborted.call(parent)) fail('http_cancelled', submitted);
      if (deadline || monotonic() >= until) { deadline = true; stop(); fail('http_deadline', submitted); }
      if (!sameAuthority()) fail('http_input_invalid', submitted);
    };
    const context = Object.freeze({ signal: child.signal, budget: Object.freeze({ assertActive: check }) });
    const scope = Object.freeze({ context, check, submitted: () => { check(); submitted = true; } });
    let timer: ReturnType<typeof setTimeout> | undefined, result: T | undefined, failure: Readonly<{ code: Failure; mutationSubmitted: boolean }> | undefined;
    listen.call(parent, 'abort', onAbort, { once: true }); if (aborted.call(parent)) onAbort();
    try {
      check(); timer = setTimeout(() => { deadline = true; stop(); }, timeoutMs);
      result = await work(scope); check();
    } catch (error) {
      const known = error && typeof error === 'object' ? failures.get(error) : undefined;
      failure = { code: known?.code ?? 'http_unknown', mutationSubmitted: submitted || Boolean(known?.mutationSubmitted) };
    }
    try {
      // Owned native responses/bodies are joined. A mandatory read-only verifier
      // may instead be retired with an observed, discarded late completion.
      // Recheck before exposing tokens or populating the transient ledger.
      check(); if (!failure) publish?.(result as T);
    } catch (error) {
      const known = error && typeof error === 'object' ? failures.get(error) : undefined;
      failure = { code: known?.code ?? 'http_unknown', mutationSubmitted: submitted || Boolean(known?.mutationSubmitted) };
    } finally {
      retired = true; stop(); if (timer !== undefined) clearTimeout(timer); unlisten.call(parent, 'abort', onAbort);
    }
    if (failure) fail(failure.code, failure.mutationSubmitted); return result as T;
  }
  async function post(path: string, fields: URLSearchParams, scope: Scope, emptyAllowed = false): Promise<unknown> {
    let response: Response | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined, body: ReadableStream<Uint8Array> | null | undefined;
    let value: unknown, failed = false;
    try {
      scope.check(); scope.submitted();
      response = await transport(path, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fields.toString(), redirect: 'error', credentials: 'omit', cache: 'no-store', signal: scope.context.signal });
      scope.check(); body = bodyOf.call(response);
      if (statusOf.call(response) !== 200 || redirectedOf.call(response)) fail('http_unknown', true);
      const headers = headersOf.call(response), length = getHeader.call(headers, 'content-length');
      if (length !== null && (!/^\d+$/.test(length) || BigInt(length) > BigInt(DELEGATED_HTTP_LIMITS.maxBodyBytes))) fail('http_unknown', true);
      if (!body) { if (!emptyAllowed) fail('http_unknown', true); return undefined; }
      reader = body.getReader(); let size = 0; const chunks: Uint8Array[] = [];
      for (;;) {
        scope.check(); const part = await reader.read(); scope.check(); if (part.done) break;
        size += part.value.byteLength; if (size > DELEGATED_HTTP_LIMITS.maxBodyBytes) fail('http_unknown', true); chunks.push(part.value);
      }
      if (!size && emptyAllowed) value = undefined;
      else {
        const contentType = getHeader.call(headers, 'content-type');
        if (!contentType || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)) fail('http_unknown', true);
        const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        // The frozen wire responses are flat scalar objects. Reject duplicates,
        // nested extension values and BOM without inventing a general JSON codec.
        value = JSON.parse(text);
        if (!value || typeof value !== 'object' || Array.isArray(value)) fail('http_unknown', true);
        const keys = [...text.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)].map(match => JSON.parse('"' + match[1] + '"'));
        if (new Set(keys).size !== keys.length || Object.values(value).some(item => item !== null && typeof item === 'object')) fail('http_unknown', true);
      }
    } catch { failed = true; }
    finally {
      try { if (reader) await reader.cancel(); else if (body) await body.cancel(); else if (response) await bodyOf.call(response)?.cancel(); }
      catch { failed = true; }
      try { reader?.releaseLock(); } catch { failed = true; }
    }
    scope.check(); if (failed) fail('http_unknown', true); return value;
  }
  async function verify(access: string, selectedResource: string, scope: Scope): Promise<DelegatedVerifiedAccess> {
    scope.check(); let rejectAbort!: (reason: unknown) => void;
    const cancellation = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
    const onAbort = () => { try { scope.check(); fail('http_unknown'); } catch (error) { rejectAbort(error); } };
    listen.call(scope.context.signal, 'abort', onAbort, { once: true });
    const work = Promise.resolve().then(() => { scope.check(); return verifier(deployment, access, selectedResource, scope.context); });
    void work.catch(() => undefined);
    if (aborted.call(scope.context.signal)) onAbort();
    let raw: unknown;
    try { raw = await Promise.race([work, cancellation]); }
    finally { unlisten.call(scope.context.signal, 'abort', onAbort); }
    scope.check();
    try {
      const value = familyObject(raw, [...identityFields, 'resource', 'accessScopes', 'expiresAtSeconds']);
      const identity = delegatedFamilyIdentity(Object.fromEntries(identityFields.map(key => [key, value[key]])), deployment);
      const accessScopes = familyStrings(value.accessScopes, identity.grantScopes);
      if (value.resource !== selectedResource || !identity.grantResourceUris.includes(selectedResource) || !familySeconds(value.expiresAtSeconds)
        || value.expiresAtSeconds <= now() || value.expiresAtSeconds > now() + 300 || JSON.stringify(identity).includes(access)) fail('http_identity_failed');
      return Object.freeze({ ...identity, resource: selectedResource, accessScopes, expiresAtSeconds: value.expiresAtSeconds });
    } catch { return fail('http_identity_failed'); }
  }
  function remember(pair: DelegatedTokenPair, identity: DelegatedVerifiedAccess): void {
    if (issued.size >= DELEGATED_HTTP_LIMITS.maxIssuedAccess) issued.delete(issued.keys().next().value!);
    issued.set(pair.accessToken, Object.freeze({ resource: pair.resource, identity }));
  }
  async function token(fields: URLSearchParams, selectedResource: string, scope: Scope): Promise<{ pair: DelegatedTokenPair; identity: DelegatedVerifiedAccess }> {
    const raw = await post(deployment.endpoints.token, fields, scope);
    const item = familyObject(raw, ['access_token', 'refresh_token', 'token_type', 'expires_in', 'resource', 'bota_grant_id', 'bota_family_id'], ['scope']);
    if (!secret('access', item.access_token) || !secret('refresh', item.refresh_token) || item.token_type !== 'Bearer'
      || item.resource !== selectedResource || !familyServerUuid(item.bota_grant_id) || !familyServerUuid(item.bota_family_id)
      || !Number.isSafeInteger(item.expires_in) || (item.expires_in as number) < 1 || (item.expires_in as number) > 300) fail('http_unknown', true);
    let scopes: readonly string[] = [];
    if (Object.hasOwn(item, 'scope')) {
      if (typeof item.scope !== 'string' || !item.scope || item.scope.split(' ').some(value => !value)) fail('http_unknown', true);
      scopes = familyStrings(item.scope.split(' '), delegatedScopes);
    }
    const identity = await verify(item.access_token, selectedResource, scope);
    if (identity.grantId !== item.bota_grant_id || identity.familyId !== item.bota_family_id || !sameFamilySet(identity.accessScopes, scopes)) fail('http_identity_failed', true);
    // expires_in is a bounded relative hint only. Without a server response
    // timestamp/client clock-skew policy it cannot prove exact absolute expiry.
    // Never manufacture now()+hint or extend the authoritative identity expiry.
    return { pair: Object.freeze({ accessToken: item.access_token, refreshToken: item.refresh_token, resource: selectedResource,
      expiresAtSeconds: identity.expiresAtSeconds, grantId: identity.grantId, familyId: identity.familyId, scopes: Object.freeze([...scopes]) }), identity };
  }
  return Object.freeze({ stage: 'inactive-one-attempt-http' as const,
    async exchangeCode(attempt: DelegatedLoginAttempt, context: DelegatedFamilyContext) {
      return operation(context, async scope => {
        const binding = readDelegatedLoginExchangeBinding(attempt);
        if (binding.issuer !== deployment.issuer || binding.tokenEndpoint !== deployment.endpoints.token || binding.clientId !== deployment.client.clientId
          || consumedAttempts.has(attempt)) fail('http_input_invalid');
        resource(binding.resource); consumedAttempts.add(attempt);
        const result = familyObject(await attempt.result, ['code']); scope.check(); readDelegatedLoginExchangeBinding(attempt);
        if (!secret('code', result.code)) fail('http_input_invalid');
        const obtained = await token(new URLSearchParams({ grant_type: 'authorization_code', client_id: deployment.client.clientId,
          code: result.code, redirect_uri: binding.redirectUri, code_verifier: binding.verifier, resource: binding.resource }), binding.resource, scope);
        if (obtained.identity.grantResourceUris.some(value => !binding.grantResources.includes(value))
          || obtained.identity.grantScopes.some(value => !(binding.scopes as readonly string[]).includes(value))) fail('http_identity_failed', true);
        readDelegatedLoginExchangeBinding(attempt); return obtained;
      }, obtained => { readDelegatedLoginExchangeBinding(attempt); remember(obtained.pair, obtained.identity); }).then(obtained => obtained.pair);
    },
    async exchange(selectedDeployment: DelegatedLoginDeployment, refresh: string, selectedResource: string, context: DelegatedFamilyContext) {
      return operation(context, async scope => {
        selected(selectedDeployment); resource(selectedResource); if (!secret('refresh', refresh)) fail('http_input_invalid');
        const obtained = await token(new URLSearchParams({ grant_type: 'refresh_token', client_id: deployment.client.clientId, refresh_token: refresh, resource: selectedResource }), selectedResource, scope);
        if (obtained.pair.refreshToken === refresh) fail('http_unknown', true); return obtained;
      }, obtained => remember(obtained.pair, obtained.identity)).then(obtained => obtained.pair);
    },
    async verifyAccess(selectedDeployment: DelegatedLoginDeployment, access: string, selectedResource: string, context: DelegatedFamilyContext) {
      return operation(context, async scope => {
        selected(selectedDeployment); resource(selectedResource); const known = issued.get(access);
        if (!secret('access', access) || !known || known.resource !== selectedResource || known.identity.expiresAtSeconds <= now()) fail('http_input_invalid');
        const current = await verify(access, selectedResource, scope);
        if (JSON.stringify(current) !== JSON.stringify(known.identity)) fail('http_identity_failed'); return current;
      });
    },
    async revoke(selectedDeployment: DelegatedLoginDeployment, refresh: string, inputExpected: DelegatedRevocationBinding, context: DelegatedFamilyContext) {
      try {
        return await operation(context, async scope => {
          selected(selectedDeployment); if (!secret('refresh', refresh)) fail('http_input_invalid');
          const expected = familyObject(inputExpected, ['grantId', 'familyId']);
          if (!familyServerUuid(expected.grantId) || !familyServerUuid(expected.familyId)) fail('http_input_invalid');
          const raw = await post(deployment.endpoints.revocation, new URLSearchParams({ client_id: deployment.client.clientId,
            token: refresh, token_type_hint: 'refresh_token', bota_grant_id: expected.grantId, bota_family_id: expected.familyId }), scope, true);
          const receipt = familyObject(raw, ['bota_revoked', 'bota_grant_id', 'bota_family_id']);
          if (receipt.bota_revoked !== true || receipt.bota_grant_id !== expected.grantId || receipt.bota_family_id !== expected.familyId) fail('http_unknown', true);
          return Object.freeze({ grantId: expected.grantId, familyId: expected.familyId });
        });
      } catch (error) { const known = error && typeof error === 'object' ? failures.get(error) : undefined; return known?.mutationSubmitted ? 'unknown' : 'not_submitted'; }
    },
  });
}
