import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';

/** Explicit callback contract. This module performs no discovery, browser
 * launch, token exchange or profile/store write; its trusted caller owns them.
 * Receiving a code does not establish a human identity or complete login. */
export const DELEGATED_LOGIN_STAGE = 'inactive-client-contract' as const;
export const DELEGATED_LOGIN_LIMITS = Object.freeze({
  defaultTimeoutMs: 120_000, maxTimeoutMs: 300_000, maxRequestBytes: 2048,
  maxHeaderBytes: 8192, maxRequests: 32, maxConnections: 8, maxTotalConnections: 64,
});
const scopeNames = ['end_users:read', 'devices:read', 'recordings:read', 'transcriptions:read', 'summaries:read'] as const;
type Scope = typeof scopeNames[number];
type ResourceKind = 'rest' | 'mcp';
type LoopbackHost = '127.0.0.1' | '::1';
const redirectBases = ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'];
type Failure = 'login_configuration_invalid' | 'login_callback_invalid' | 'login_unavailable'
  | 'login_cancelled' | 'login_deadline' | 'login_denied' | 'login_not_complete';
export class DelegatedLoginError extends Error {
  constructor(readonly code: Failure) {
    super('Developer authorization attempt is invalid, unavailable or incomplete.');
    this.name = 'DelegatedLoginError';
  }
}
function fail(code: Failure = 'login_configuration_invalid'): never { throw new DelegatedLoginError(code); }

export interface DelegatedLoginDeployment {
  readonly version: 1;
  readonly issuer: string;
  /** Trusted source opt-in only; absent means the legacy recovery namespace. */
  readonly recoveryProtocol?: 'negative-fence-v1';
  readonly endpoints: Readonly<{ authorization: string; token: string; revocation: string }>;
  readonly resources: Readonly<{ rest: string; mcp: string }>;
  readonly client: Readonly<{ clientId: string; kind: 'native'; redirectUris: readonly string[];
    resourceKinds: readonly ResourceKind[]; pkceMethod: 'S256' }>;
}
export interface DelegatedLoginSelection {
  readonly resourceKind: ResourceKind;
  readonly grantResourceKinds: readonly ResourceKind[];
  readonly scopes: readonly Scope[];
  readonly loopbackHost: LoopbackHost;
}
export interface DelegatedLoginAttempt {
  readonly stage: typeof DELEGATED_LOGIN_STAGE;
  readonly authorizationUrl: string;
  readonly redirectUri: string;
  readonly result: Promise<Readonly<{ code: string }>>;
  cancel(): Promise<void>;
}
export interface DelegatedLoginExchangeBinding {
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly resource: string;
  readonly grantResources: readonly string[];
  readonly scopes: readonly Scope[];
  readonly redirectUri: string;
  readonly verifier: string;
}
/** Secret recovery input for trusted retention/explicit protective cleanup only.
 * It is never status, callback output, ordinary metadata or exchange authority. */
export interface DelegatedLoginRecoveryBinding {
  readonly attemptId: string;
  readonly recoveryVerifier: string;
  readonly pkceVerifier: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly grantResources: readonly string[];
  readonly scopes: readonly Scope[];
  readonly recoveryProtocol?: 'negative-fence-v1';
}
export interface DelegatedLoginRetentionContext {
  readonly signal: AbortSignal;
  readonly budget: { assertActive(): void };
}
export interface DelegatedLoginRetentionPort {
  /** A positive matching receipt promises the exact whole input is protected
   * and retained. This trusted seam does not itself qualify native persistence. */
  retain(binding: DelegatedLoginRecoveryBinding, context: DelegatedLoginRetentionContext): Promise<
    Readonly<{ status: 'retained'; attemptId: string }> | 'not_retained' | 'unknown'>;
}

// Snapshot own data only, before traversing input. No getters, proxies, coercion
// or toJSON hooks can redirect a deployment or leak input through diagnostics.
function record(input: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!input || typeof input !== 'object' || types.isProxy(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const names = Reflect.ownKeys(input);
  if (names.length > keys.length + optional.length || keys.some(key => !Object.hasOwn(descriptors, key))
    || names.some(key => typeof key !== 'string' || ![...keys, ...optional].includes(key)
      || !descriptors[key]?.enumerable || !Object.hasOwn(descriptors[key]!, 'value'))) fail();
  return Object.fromEntries((names as string[]).map(key => [key, descriptors[key]!.value]));
}
function strings(input: unknown, allowed: readonly string[], minimum = 1): readonly string[] {
  if (types.isProxy(input) || !Array.isArray(input) || input.length < minimum || input.length > allowed.length
    || Reflect.ownKeys(input).length !== input.length + 1) fail();
  const result: string[] = [];
  for (let index = 0; index < input.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'string' || !allowed.includes(descriptor.value) || result.includes(descriptor.value)) fail();
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}
function httpsUri(input: unknown, originOnly = false): input is string {
  if (typeof input !== 'string' || input.length > 2048 || !/^[\x21-\x7e]+$/.test(input)
    || !input.startsWith('https://') || /[\\%?#@]/.test(input)) return false;
  try {
    const url = new URL(input);
    if (url.username || url.password || url.search || url.hash || url.port === '0' || !url.hostname || url.pathname.includes('//')) return false;
    return originOnly ? input === url.origin : input === url.origin || input === url.href && !url.pathname.endsWith('/');
  } catch { return false; }
}

/** Explicit frozen policy-v1 manifest; no inferred production issuer or client.
 * Exact endpoint paths match the backend's inactive developer-auth manifest. */
export function parseDelegatedLoginDeployment(input: unknown): DelegatedLoginDeployment {
  try {
    const value = record(input, ['version', 'issuer', 'endpoints', 'resources', 'client'], ['recoveryProtocol']);
    const endpoints = record(value.endpoints, ['authorization', 'token', 'revocation']);
    const resources = record(value.resources, ['rest', 'mcp']);
    const client = record(value.client, ['clientId', 'kind', 'redirectUris', 'resourceKinds', 'pkceMethod']);
    if (value.version !== 1 || Object.hasOwn(value, 'recoveryProtocol') && value.recoveryProtocol !== 'negative-fence-v1' || !httpsUri(value.issuer, true)
      || endpoints.authorization !== `${value.issuer}/oauth/authorize` || endpoints.token !== `${value.issuer}/oauth/token`
      || endpoints.revocation !== `${value.issuer}/oauth/revoke` || !httpsUri(resources.rest) || !httpsUri(resources.mcp)
      || typeof client.clientId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(client.clientId)
      || client.kind !== 'native' || client.pkceMethod !== 'S256') fail();
    const resourceMetadata = [resources.rest, resources.mcp].map(value => {
      const url = new URL(value as string);
      return `${url.origin}/.well-known/oauth-protected-resource${url.pathname === '/' ? '' : url.pathname}`;
    });
    const uris = [value.issuer, ...Object.values(endpoints), ...Object.values(resources),
      `${value.issuer}/.well-known/oauth-authorization-server`, ...resourceMetadata];
    if (new Set(uris).size !== uris.length) fail();
    return Object.freeze({ version: 1, issuer: value.issuer,
      ...value.recoveryProtocol === 'negative-fence-v1' ? { recoveryProtocol: 'negative-fence-v1' as const } : {},
      endpoints: Object.freeze({ authorization: endpoints.authorization, token: endpoints.token, revocation: endpoints.revocation }) as DelegatedLoginDeployment['endpoints'],
      resources: Object.freeze({ rest: resources.rest, mcp: resources.mcp }),
      client: Object.freeze({ clientId: client.clientId, kind: 'native', pkceMethod: 'S256',
        redirectUris: strings(client.redirectUris, redirectBases), resourceKinds: strings(client.resourceKinds, ['rest', 'mcp']) as readonly ResourceKind[] }) });
  } catch { return fail(); }
}
function selection(input: unknown, deployment: DelegatedLoginDeployment): DelegatedLoginSelection {
  const value = record(input, ['resourceKind', 'grantResourceKinds', 'scopes', 'loopbackHost']);
  if (!['rest', 'mcp'].includes(value.resourceKind as string) || !['127.0.0.1', '::1'].includes(value.loopbackHost as string)) fail();
  const grantResourceKinds = strings(value.grantResourceKinds, deployment.client.resourceKinds) as readonly ResourceKind[];
  if (!grantResourceKinds.includes(value.resourceKind as ResourceKind)
    || !deployment.client.redirectUris.includes(`http://${value.loopbackHost === '::1' ? '[::1]' : value.loopbackHost}/oauth/callback`)) fail();
  return Object.freeze({ resourceKind: value.resourceKind as ResourceKind, grantResourceKinds,
    scopes: strings(value.scopes, scopeNames, 0) as readonly Scope[], loopbackHost: value.loopbackHost as LoopbackHost });
}
function canonical32(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}
function entropy(): string {
  let bytes: Buffer | undefined;
  try { bytes = randomBytes(32); return bytes.toString('base64url'); }
  finally { bytes?.fill(0); }
}
function attemptOptions(input: unknown): { signal?: AbortSignal; timeoutMs: number } {
  if (!input || typeof input !== 'object' || types.isProxy(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(input).some(key => typeof key !== 'string' || !['signal', 'timeoutMs'].includes(key)
    || !descriptors[key]?.enumerable || !Object.hasOwn(descriptors[key]!, 'value'))) fail();
  const rawTimeout = descriptors.timeoutMs?.value;
  const timeoutMs = rawTimeout === undefined ? DELEGATED_LOGIN_LIMITS.defaultTimeoutMs : rawTimeout;
  const signal = descriptors.signal?.value;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DELEGATED_LOGIN_LIMITS.maxTimeoutMs
    || signal !== undefined && types.isProxy(signal)) fail();
  if (signal) { try { signalAborted.call(signal); } catch { return fail(); } }
  return { timeoutMs, signal };
}
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const abortChild = AbortController.prototype.abort;
const invoke = Reflect.apply;

const bindings = new WeakMap<DelegatedLoginAttempt, () => DelegatedLoginExchangeBinding>();
const recoveryBindings = new WeakMap<DelegatedLoginAttempt, DelegatedLoginRecoveryBinding>();
/** Genuine handle classification only; do not infer recovery from URL fields. */
export function isRecoverableDelegatedLoginAttempt(attempt: unknown): boolean {
  return recoveryBindings.has(attempt as DelegatedLoginAttempt);
}
/** A trusted owned handle, after successful joined callback capture only. This
 * snapshot is exchange input, not identity or grant authority. Never log it. */
export function readDelegatedLoginExchangeBinding(attempt: DelegatedLoginAttempt): DelegatedLoginExchangeBinding {
  const read = bindings.get(attempt);
  if (!read) fail('login_not_complete');
  return read();
}
/** Intentionally survives cancellation/expiry: explicit cleanup must remain
 * possible after callback loss. It does not permit exchange or reactivate login. */
export function readDelegatedLoginRecoveryBinding(attempt: DelegatedLoginAttempt): DelegatedLoginRecoveryBinding {
  const binding = recoveryBindings.get(attempt); if (!binding) fail('login_not_complete'); return binding;
}

type Callback = { kind: 'invalid' } | { kind: 'code'; code: string } | { kind: 'denied' };
function callback(request: IncomingMessage, authority: string, state: string): Callback {
  try {
    const target = request.url;
    if (request.method !== 'GET' || !target || target.length > DELEGATED_LOGIN_LIMITS.maxRequestBytes
      || !/^[\x21-\x7e]+$/.test(target) || target.includes('#') || target.slice(0, target.indexOf('?')) !== '/oauth/callback') return { kind: 'invalid' };
    let hosts = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      const name = request.rawHeaders[index]!.toLowerCase(), value = request.rawHeaders[index + 1]!;
      if (name === 'host' && (++hosts !== 1 || value !== authority)
        || ['authorization', 'proxy-authorization', 'transfer-encoding', 'expect'].includes(name)
        || name === 'content-length' && value !== '0') return { kind: 'invalid' };
    }
    if (hosts !== 1) return { kind: 'invalid' };
    const fields = target.slice(target.indexOf('?') + 1).split('&');
    if (fields.length < 2 || fields.length > 4) return { kind: 'invalid' };
    const values = new Map<string, string>();
    for (const field of fields) {
      const split = field.indexOf('='), name = field.slice(0, split), raw = field.slice(split + 1);
      if (split < 1 || !['state', 'code', 'error', 'error_description', 'error_uri'].includes(name) || values.has(name)) return { kind: 'invalid' };
      const value = decodeURIComponent(raw.replaceAll('+', ' '));
      if ((name === 'state' || name === 'code') && raw !== value) return { kind: 'invalid' };
      values.set(name, value);
    }
    const returnedState = values.get('state');
    if (!returnedState || !canonical32(returnedState)
      || !timingSafeEqual(Buffer.from(returnedState, 'ascii'), Buffer.from(state, 'ascii'))) return { kind: 'invalid' };
    const code = values.get('code');
    if (code && values.size === 2 && code.startsWith('bota_dc1_') && code.length === 52 && canonical32(code.slice(9))) return { kind: 'code', code };
    const error = values.get('error');
    if (!values.has('code') && error && ['invalid_request', 'unauthorized_client', 'access_denied', 'unsupported_response_type',
      'invalid_scope', 'server_error', 'temporarily_unavailable'].includes(error)) return { kind: 'denied' };
    return { kind: 'invalid' };
  } catch { return { kind: 'invalid' }; }
}
function respond(response: ServerResponse, status: number, accepted = false, done?: () => void): void {
  response.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", Connection: 'close' });
  response.end(accepted ? 'Authorization response received. You can close this tab.\n' : 'Authorization response rejected.\n', done);
}

/** Owns one literal-IP ephemeral listener. Engineering cohort: 120s default,
 * 300s maximum total budget, bounded headers/targets/requests/connections. All
 * success/failure settlement follows joined server and owned socket closure. */
export async function startDelegatedLoginAttempt(deploymentInput: unknown, selectionInput: unknown,
  options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<DelegatedLoginAttempt> {
  return startAttempt(deploymentInput, selectionInput, options);
}
/** Explicit retained-attempt producer. No authorization URL or handle is
 * published before a definitive matching trusted retention acknowledgement. */
export async function startRecoverableDelegatedLoginAttempt(deploymentInput: unknown, selectionInput: unknown,
  retentionPort: DelegatedLoginRetentionPort, options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<DelegatedLoginAttempt> {
  let retain: DelegatedLoginRetentionPort['retain'];
  try { const fields = record(retentionPort, ['retain']);
    if (typeof fields.retain !== 'function' || types.isProxy(fields.retain)) fail(); retain = fields.retain as DelegatedLoginRetentionPort['retain']; }
  catch { return fail(); }
  return startAttempt(deploymentInput, selectionInput, options, (binding, context) => invoke(retain, retentionPort, [binding, context]));
}
async function startAttempt(deploymentInput: unknown, selectionInput: unknown,
  options: { signal?: AbortSignal; timeoutMs?: number }, retain?: DelegatedLoginRetentionPort['retain']): Promise<DelegatedLoginAttempt> {
  const deployment = parseDelegatedLoginDeployment(deploymentInput), chosen = selection(selectionInput, deployment);
  const { signal, timeoutMs } = attemptOptions(options), deadline = performance.now() + timeoutMs;
  if (signal && signalAborted.call(signal)) fail('login_cancelled');
  let state: string, verifier: string, challenge: string, recoveryVerifier: string | undefined, attemptId: string | undefined;
  try { state = entropy(); verifier = entropy(); challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    if (retain) { attemptId = randomUUID(); recoveryVerifier = entropy(); if (recoveryVerifier === verifier || recoveryVerifier === state) fail('login_unavailable'); } }
  catch { return fail('login_unavailable'); }
  const sockets = new Map<Socket, Promise<void>>();
  let totalConnections = 0, requests = 0, claimed = false, outcome: { code: string } | DelegatedLoginError | undefined;
  let resolveResult!: (result: Readonly<{ code: string }>) => void, rejectResult!: (error: DelegatedLoginError) => void;
  const result = new Promise<Readonly<{ code: string }>>((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  void result.catch(() => undefined); // The caller receives the original promise after bind.
  let ready!: () => void;
  const listenSettled = new Promise<void>(resolve => { ready = resolve; });
  let closing: Promise<void> | undefined, completed = false, cancelled = false, authority = '', redirectUri = '', retained = !retain;
  const retentionController = retain ? new AbortController() : undefined;
  const currentFailure = (): DelegatedLoginError | undefined => cancelled || signal && signalAborted.call(signal) ? new DelegatedLoginError('login_cancelled')
    : performance.now() >= deadline ? new DelegatedLoginError('login_deadline') : undefined;
  const server = createServer({ maxHeaderSize: DELEGATED_LOGIN_LIMITS.maxHeaderBytes }, (request, response) => {
    response.on('error', () => undefined);
    requests++;
    const parsed = callback(request, authority, state);
    if (!retained || outcome || claimed || currentFailure() || requests > DELEGATED_LOGIN_LIMITS.maxRequests) {
      respond(response, 400, false, () => { if (requests > DELEGATED_LOGIN_LIMITS.maxRequests) finish(new DelegatedLoginError('login_callback_invalid')); });
      return;
    }
    if (parsed.kind === 'invalid') { respond(response, 400); return; }
    claimed = true; // Claim synchronously; a competing callback can never replace it.
    respond(response, parsed.kind === 'code' ? 200 : 400, parsed.kind === 'code', () => {
      finish(parsed.kind === 'code' ? { code: parsed.code } : new DelegatedLoginError('login_denied'));
    });
  });
  server.headersTimeout = Math.min(5000, timeoutMs);
  server.requestTimeout = Math.min(5000, timeoutMs);
  server.keepAliveTimeout = 1;
  server.maxRequestsPerSocket = 1;
  server.on('connection', socket => {
    const closed = new Promise<void>(resolve => socket.once('close', () => { sockets.delete(socket); resolve(); }));
    sockets.set(socket, closed);
    socket.on('error', () => undefined);
    socket.setTimeout(Math.min(5000, Math.max(1, deadline - performance.now())), () => socket.destroy());
    if (outcome || ++totalConnections > DELEGATED_LOGIN_LIMITS.maxTotalConnections
      || sockets.size > DELEGATED_LOGIN_LIMITS.maxConnections) socket.destroy();
    if (totalConnections > DELEGATED_LOGIN_LIMITS.maxTotalConnections) finish(new DelegatedLoginError('login_callback_invalid'));
  });
  server.on('clientError', (_error, socket) => {
    // The HTTP parser's opaque error never becomes a diagnostic or response.
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n');
    if (++requests > DELEGATED_LOGIN_LIMITS.maxRequests) finish(new DelegatedLoginError('login_callback_invalid'));
  });
  server.on('error', () => { ready(); finish(new DelegatedLoginError('login_unavailable')); });
  server.on('listening', ready);
  const abort = () => finish(new DelegatedLoginError('login_cancelled'));
  let timer = setTimeout(onDeadline, Math.max(1, Math.ceil(deadline - performance.now())));
  function onDeadline(): void {
    if (outcome) return;
    // Native timers may fire before the fractional monotonic deadline. Retain
    // the original deadline instead of retiring authority on that early tick.
    const remaining = deadline - performance.now();
    if (remaining > 0) { timer = setTimeout(onDeadline, Math.ceil(remaining)); return; }
    finish(new DelegatedLoginError('login_deadline'));
  }
  if (signal) EventTarget.prototype.addEventListener.call(signal, 'abort', abort, { once: true });
  function finish(selected: { code: string } | DelegatedLoginError): void {
    if (outcome) return;
    outcome = currentFailure() ?? selected;
    if (retentionController) abortChild.call(retentionController);
    closing = (async () => {
      await listenSettled;
      const closed = new Promise<void>(resolve => {
        if (server.listening) server.close(() => resolve()); else resolve();
      });
      server.closeAllConnections();
      for (const socket of sockets.keys()) socket.destroy();
      await Promise.all([...sockets.values()]);
      await closed;
      clearTimeout(timer); if (signal) EventTarget.prototype.removeEventListener.call(signal, 'abort', abort);
      outcome = currentFailure() ?? outcome;
      completed = true;
      if (outcome instanceof DelegatedLoginError) rejectResult(outcome);
      else resolveResult(Object.freeze({ code: outcome!.code }));
    })().catch(() => { clearTimeout(timer); if (signal) EventTarget.prototype.removeEventListener.call(signal, 'abort', abort);
      const failure = new DelegatedLoginError('login_unavailable'); outcome = failure; completed = true; rejectResult(failure); });
  }
  try {
    server.listen({ host: chosen.loopbackHost, port: 0, exclusive: true, ipv6Only: chosen.loopbackHost === '::1' });
  } catch { ready(); finish(new DelegatedLoginError('login_unavailable')); }
  await listenSettled;
  if (outcome) { await closing; return fail((outcome as DelegatedLoginError).code as Failure); }
  const expired = currentFailure();
  if (expired) { finish(expired); await closing; return fail(expired.code); }
  const address = server.address();
  if (!address || typeof address === 'string' || address.address !== chosen.loopbackHost || address.port < 1) {
    finish(new DelegatedLoginError('login_unavailable')); await closing; return fail('login_unavailable');
  }
  authority = `${chosen.loopbackHost === '::1' ? '[::1]' : chosen.loopbackHost}:${address.port}`;
  redirectUri = `http://${authority}/oauth/callback`;
  const authorizationUrl = new URL(deployment.endpoints.authorization);
  authorizationUrl.searchParams.set('response_type', 'code'); authorizationUrl.searchParams.set('client_id', deployment.client.clientId);
  authorizationUrl.searchParams.set('redirect_uri', redirectUri); authorizationUrl.searchParams.set('state', state);
  authorizationUrl.searchParams.set('code_challenge', challenge);
  authorizationUrl.searchParams.set('code_challenge_method', 'S256');
  if (attemptId && recoveryVerifier) {
    authorizationUrl.searchParams.set('enrollment_attempt', attemptId);
    authorizationUrl.searchParams.set('recovery_challenge', createHash('sha256').update(recoveryVerifier, 'ascii').digest('base64url'));
    authorizationUrl.searchParams.set('recovery_challenge_method', 'S256');
    if (deployment.recoveryProtocol) authorizationUrl.searchParams.set('recovery_protocol', deployment.recoveryProtocol);
  }
  for (const kind of chosen.grantResourceKinds) authorizationUrl.searchParams.append('resource', deployment.resources[kind]);
  if (chosen.scopes.length) authorizationUrl.searchParams.set('scope', chosen.scopes.join(' '));
  const binding = Object.freeze({ issuer: deployment.issuer, tokenEndpoint: deployment.endpoints.token, clientId: deployment.client.clientId,
    resource: deployment.resources[chosen.resourceKind], grantResources: Object.freeze(chosen.grantResourceKinds.map(kind => deployment.resources[kind])),
    scopes: chosen.scopes, redirectUri, verifier });
  let recoveryBinding: DelegatedLoginRecoveryBinding | undefined;
  if (retain && retentionController && attemptId && recoveryVerifier) {
    recoveryBinding = Object.freeze({ attemptId, recoveryVerifier, pkceVerifier: verifier, issuer: deployment.issuer, clientId: deployment.client.clientId,
      redirectUri, resource: binding.resource, grantResources: binding.grantResources, scopes: binding.scopes,
      ...deployment.recoveryProtocol ? { recoveryProtocol: deployment.recoveryProtocol } : {} });
    let active = true, failed = false, acknowledgement: Readonly<{ status: 'retained'; attemptId: string }> | undefined;
    const assertActive = () => {
      const failure = currentFailure();
      if (failure) throw failure;
      if (!active || outcome || signalAborted.call(retentionController.signal)) fail('login_unavailable');
    };
    const context: DelegatedLoginRetentionContext = Object.freeze({ signal: retentionController.signal, budget: Object.freeze({ assertActive }) });
    try {
      assertActive();
      // Join the supported retention producer directly. Cancellation closes the
      // listener and withdraws child authority, but never detaches its work.
      const receipt = await retain(recoveryBinding, context); assertActive();
      const acknowledged = record(receipt, ['status', 'attemptId']);
      if (acknowledged.status !== 'retained' || acknowledged.attemptId !== attemptId) fail('login_unavailable');
      acknowledgement = Object.freeze({ status: 'retained' as const, attemptId: acknowledged.attemptId as string });
    } catch { failed = true; }
    finally { active = false; abortChild.call(retentionController); }
    const failure = currentFailure();
    if (failed || !acknowledgement || failure || outcome) {
      const selected = failure ?? new DelegatedLoginError('login_unavailable'); finish(selected); await closing; return fail(selected.code);
    }
    retained = true;
  }
  const attempt: DelegatedLoginAttempt = Object.freeze({ stage: DELEGATED_LOGIN_STAGE, authorizationUrl: authorizationUrl.href, redirectUri, result,
    cancel: async () => { cancelled = true; finish(new DelegatedLoginError('login_cancelled')); await closing; } });
  bindings.set(attempt, () => {
    if (!completed || !outcome || outcome instanceof DelegatedLoginError || currentFailure()) fail('login_not_complete');
    return binding;
  });
  if (recoveryBinding) recoveryBindings.set(attempt, recoveryBinding);
  return attempt;
}
