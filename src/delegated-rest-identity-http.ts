/** Inactive REST identity verifier. No command/profile/native enrollment wiring.
 * MCP credentials require their own resource transport and never fall back here. */
import { types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';
import { familyObject, familySeconds } from './delegated-family-state.js';
import { normalizeDelegatedIdentity } from './delegated-identity.js';
import type { DelegatedIdentityVerifier } from './delegated-http.js';
import type { DelegatedFamilyContext } from './delegated-family-engine.js';

const nativeFetch = globalThis.fetch.bind(globalThis);
const monotonic = performance.now.bind(performance);
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const listen = EventTarget.prototype.addEventListener, unlisten = EventTarget.prototype.removeEventListener;
const abort = AbortController.prototype.abort;
const statusOf = Object.getOwnPropertyDescriptor(Response.prototype, 'status')!.get!;
const bodyOf = Object.getOwnPropertyDescriptor(Response.prototype, 'body')!.get!;
const headersOf = Object.getOwnPropertyDescriptor(Response.prototype, 'headers')!.get!;
const redirectedOf = Object.getOwnPropertyDescriptor(Response.prototype, 'redirected')!.get!;
const header = Headers.prototype.get;
const getReader = ReadableStream.prototype.getReader;
const cancelBody = ReadableStream.prototype.cancel;
const read = ReadableStreamDefaultReader.prototype.read;
const cancelReader = ReadableStreamDefaultReader.prototype.cancel;
const release = ReadableStreamDefaultReader.prototype.releaseLock;
export const DELEGATED_REST_IDENTITY_HTTP_LIMITS = Object.freeze({ maxBodyBytes: 16 * 1024, timeoutMs: 30_000 });

type Failure = 'identity_http_configuration_invalid' | 'identity_http_input_invalid' | 'identity_http_unavailable';
export class DelegatedRestIdentityHttpError extends Error {
  constructor(readonly code: Failure = 'identity_http_unavailable') {
    super('Developer REST identity is invalid or unavailable.'); this.name = 'DelegatedRestIdentityHttpError';
  }
}
function fail(code: Failure = 'identity_http_unavailable'): never { throw new DelegatedRestIdentityHttpError(code); }
export interface DelegatedRestIdentityHttpOptions { readonly identityUrl: string }
export interface DelegatedRestIdentityHttpTrustedPorts {
  readonly fetch: typeof fetch;
  readonly nowSeconds?: () => number;
  readonly timeoutMs?: number;
}
function access(value: unknown): value is string {
  return typeof value === 'string' && value.length === 52 && value.startsWith('bota_da1_')
    && /^[A-Za-z0-9_-]{43}$/.test(value.slice(9))
    && Buffer.from(value.slice(9), 'base64url').toString('base64url') === value.slice(9);
}

/** Frozen identity wire shape is a flat object of scalars and string arrays.
 * Native parsing validates syntax first; this bounded shape walk rejects raw
 * duplicate (including escaped) member names before the parsed-value codec.
 * It does not introduce a general JSON parser or accept nested extensions. */
function identityJson(text: string): unknown {
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  let index = 0;
  const whitespace = () => { while (index < text.length && /[\t\r\n ]/.test(text[index]!)) index++; };
  const expect = (character: string) => { whitespace(); if (text[index++] !== character) fail(); };
  const string = (): string => {
    whitespace(); const start = index; if (text[index++] !== '"') fail();
    while (index < text.length) {
      const character = text[index++];
      if (character === '\\') index++;
      else if (character === '"') return JSON.parse(text.slice(start, index)) as string;
    }
    return fail();
  };
  const scalar = () => {
    whitespace();
    if (text[index] === '"') { string(); return; }
    if (text[index] === '[') {
      index++; whitespace(); if (text[index] === ']') { index++; return; }
      for (;;) { string(); whitespace(); if (text[index] === ']') { index++; return; } expect(','); }
    }
    const start = index;
    while (index < text.length && !/[\t\r\n ,}\]]/.test(text[index]!)) index++;
    const token = text.slice(start, index);
    if (!/^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$/.test(token)) fail();
  };
  const keys = new Set<string>(); expect('{'); whitespace();
  if (text[index] !== '}') for (;;) {
    const key = string(); if (keys.has(key)) fail(); keys.add(key); expect(':'); scalar(); whitespace();
    if (text[index] === '}') break; expect(',');
  }
  expect('}'); whitespace(); if (index !== text.length || keys.size !== Object.keys(value).length) fail();
  return value;
}

export function createDelegatedRestIdentityVerifier(deployment: unknown, options: DelegatedRestIdentityHttpOptions): DelegatedIdentityVerifier {
  return createDelegatedRestIdentityVerifierForTrustedPorts(deployment, options, { fetch: nativeFetch });
}
/** Explicit trusted fixture port. Replacement transport is not production TLS
 * qualification. It must honor the child signal and join its own native I/O;
 * arbitrary uncooperative transport promises have no universal bounded join. */
export function createDelegatedRestIdentityVerifierForTrustedPorts(input: unknown,
  inputOptions: DelegatedRestIdentityHttpOptions, inputPorts: DelegatedRestIdentityHttpTrustedPorts): DelegatedIdentityVerifier {
  let deployment: DelegatedLoginDeployment, identityUrl: string, transport: typeof fetch, clock: () => number, timeoutMs: number;
  try {
    deployment = parseDelegatedLoginDeployment(input);
    const options = familyObject(inputOptions, ['identityUrl']);
    const ports = familyObject(inputPorts, ['fetch'], ['nowSeconds', 'timeoutMs']);
    const resource = new URL(deployment.resources.rest);
    const expected = resource.origin + (resource.pathname === '/' ? '' : resource.pathname) + '/auth/delegated-identity';
    if (!deployment.client.resourceKinds.includes('rest') || options.identityUrl !== expected
      || typeof ports.fetch !== 'function' || types.isProxy(ports.fetch)
      || ports.nowSeconds !== undefined && (typeof ports.nowSeconds !== 'function' || types.isProxy(ports.nowSeconds))) fail();
    identityUrl = expected; transport = ports.fetch as typeof fetch;
    clock = ports.nowSeconds as (() => number) | undefined ?? (() => Math.floor(Date.now() / 1000));
    timeoutMs = ports.timeoutMs as number | undefined ?? DELEGATED_REST_IDENTITY_HTTP_LIMITS.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DELEGATED_REST_IDENTITY_HTTP_LIMITS.timeoutMs) fail();
  } catch { return fail('identity_http_configuration_invalid'); }
  const selected = JSON.stringify(deployment);
  return async (selectedDeployment, accessToken, resource, inputContext) => {
    let parent: AbortSignal, budget: DelegatedFamilyContext['budget'], assertion: () => void;
    try {
      if (JSON.stringify(parseDelegatedLoginDeployment(selectedDeployment)) !== selected
        || resource !== deployment.resources.rest || !access(accessToken)) fail();
      const context = familyObject(inputContext, ['signal', 'budget']);
      const fields = familyObject(context.budget, ['assertActive']);
      if (types.isProxy(context.signal) || typeof fields.assertActive !== 'function' || types.isProxy(fields.assertActive)) fail();
      aborted.call(context.signal); parent = context.signal as AbortSignal;
      budget = context.budget as DelegatedFamilyContext['budget']; assertion = fields.assertActive as () => void;
    } catch { return fail('identity_http_input_invalid'); }
    const controller = new AbortController(), deadline = monotonic() + timeoutMs;
    let live = true, interrupted = false;
    const stop = () => { interrupted = true; abort.call(controller); };
    const check = () => {
      try {
        if (!live || interrupted || aborted.call(parent) || monotonic() >= deadline) fail();
        const context = familyObject(inputContext, ['signal', 'budget']), fields = familyObject(budget, ['assertActive']);
        if (context.signal !== parent || context.budget !== budget || fields.assertActive !== assertion) fail();
        assertion.call(budget);
        const after = familyObject(inputContext, ['signal', 'budget']), afterBudget = familyObject(budget, ['assertActive']);
        if (!live || interrupted || aborted.call(parent) || monotonic() >= deadline
          || after.signal !== parent || after.budget !== budget || afterBudget.assertActive !== assertion) fail();
      } catch { stop(); return fail(); }
    };
    let response: Response | undefined, stream: ReadableStream<Uint8Array> | null | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined, result: unknown, failed = false;
    const chunks: Uint8Array[] = [];
    const timer = setTimeout(stop, timeoutMs);
    listen.call(parent, 'abort', stop, { once: true }); if (aborted.call(parent)) stop();
    try {
      check();
      response = await transport(identityUrl, { method: 'GET', headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}` },
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal });
      check(); stream = bodyOf.call(response);
      if (statusOf.call(response) !== 200 || redirectedOf.call(response) || !stream) fail();
      const headers = headersOf.call(response), length = header.call(headers, 'content-length'), contentType = header.call(headers, 'content-type');
      if (!contentType || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)
        || header.call(headers, 'content-encoding') !== null
        || length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > DELEGATED_REST_IDENTITY_HTTP_LIMITS.maxBodyBytes)) fail();
      reader = getReader.call(stream) as ReadableStreamDefaultReader<Uint8Array>; let size = 0;
      for (;;) {
        check(); const part = await read.call(reader); check(); if (part.done) break;
        if (!types.isUint8Array(part.value) || types.isProxy(part.value)) fail();
        size += part.value.byteLength; if (size > DELEGATED_REST_IDENTITY_HTTP_LIMITS.maxBodyBytes) fail();
        chunks.push(Uint8Array.from(part.value));
      }
      if (length !== null && Number(length) !== size) fail();
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { result = identityJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
      finally { bytes.fill(0); }
      check(); const seconds = clock(); if (!familySeconds(seconds)) fail();
      result = normalizeDelegatedIdentity(result, { deployment, resource, nowSeconds: seconds }); check();
    } catch { failed = true; }
    finally {
      // Cancellation withdraws authority before cleanup; no result is published
      // until the owned response/body cancellation and reader release settle.
      abort.call(controller);
      try { if (reader) await cancelReader.call(reader); else if (stream) await cancelBody.call(stream); else if (response) await bodyOf.call(response)?.cancel(); }
      catch { failed = true; }
      try { if (reader) release.call(reader); } catch { failed = true; }
      chunks.forEach(chunk => chunk.fill(0));
      try { check(); } catch { failed = true; }
      live = false; clearTimeout(timer); unlisten.call(parent, 'abort', stop);
    }
    if (failed) fail(); return result;
  };
}
