/** Private, inactive MCP-resource identity read. No login/profile/store wiring. */
import { types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';
import { familyObject, familySeconds } from './delegated-family-state.js';
import { normalizeDelegatedIdentity } from './delegated-identity.js';
import type { DelegatedIdentityVerifier } from './delegated-http.js';
import type { DelegatedFamilyContext, DelegatedVerifiedAccess } from './delegated-family-engine.js';

const nativeFetch = globalThis.fetch.bind(globalThis), monotonic = performance.now.bind(performance);
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const listen = EventTarget.prototype.addEventListener, unlisten = EventTarget.prototype.removeEventListener;
const abort = AbortController.prototype.abort, header = Headers.prototype.get;
const statusOf = Object.getOwnPropertyDescriptor(Response.prototype, 'status')!.get!;
const bodyOf = Object.getOwnPropertyDescriptor(Response.prototype, 'body')!.get!;
const headersOf = Object.getOwnPropertyDescriptor(Response.prototype, 'headers')!.get!;
const redirectedOf = Object.getOwnPropertyDescriptor(Response.prototype, 'redirected')!.get!;
const getReader = ReadableStream.prototype.getReader, cancelBody = ReadableStream.prototype.cancel;
const read = ReadableStreamDefaultReader.prototype.read, cancelReader = ReadableStreamDefaultReader.prototype.cancel;
const release = ReadableStreamDefaultReader.prototype.releaseLock;
export const DELEGATED_MCP_IDENTITY_HTTP_LIMITS = Object.freeze({ maxBodyBytes: 16 * 1024, timeoutMs: 30_000 });
type Failure = 'mcp_identity_configuration_invalid' | 'mcp_identity_input_invalid' | 'mcp_identity_unavailable';
export class DelegatedMcpIdentityHttpError extends Error {
  constructor(readonly code: Failure = 'mcp_identity_unavailable') {
    super('Developer MCP identity is invalid or unavailable.'); this.name = 'DelegatedMcpIdentityHttpError';
  }
}
function fail(code: Failure = 'mcp_identity_unavailable'): never { throw new DelegatedMcpIdentityHttpError(code); }
export interface DelegatedMcpIdentityHttpTrustedPorts {
  readonly fetch: typeof fetch;
  readonly nowSeconds?: () => number;
  readonly timeoutMs?: number;
}
function access(value: unknown): value is string {
  return typeof value === 'string' && value.length === 52 && value.startsWith('bota_da1_')
    && /^[A-Za-z0-9_-]{43}$/.test(value.slice(9)) && Buffer.from(value.slice(9), 'base64url').toString('base64url') === value.slice(9);
}
/** Native JSON validates syntax; a bounded structural walk additionally refuses
 * duplicate decoded names at every depth, before the SDK loses that evidence. */
function strictJson(text: string): unknown {
  const parsed: unknown = JSON.parse(text); let index = 0;
  const white = () => { while (/[\t\r\n ]/.test(text[index] ?? '') && index < text.length) index++; };
  const expect = (value: string) => { white(); if (text[index++] !== value) fail(); };
  const string = (): string => {
    white(); const start = index; if (text[index++] !== '"') fail();
    while (index < text.length) { const value = text[index++]; if (value === '\\') index++; else if (value === '"') return JSON.parse(text.slice(start, index)) as string; }
    return fail();
  };
  const value = (depth: number): void => {
    if (depth > 16) fail(); white();
    if (text[index] === '"') { string(); return; }
    if (text[index] === '{') {
      index++; white(); if (text[index] === '}') { index++; return; }
      const keys = new Set<string>();
      for (;;) { const key = string(); if (keys.has(key) || keys.size >= 128) fail(); keys.add(key); expect(':'); value(depth + 1); white();
        if (text[index] === '}') { index++; return; } expect(','); }
    }
    if (text[index] === '[') {
      index++; white(); if (text[index] === ']') { index++; return; } let size = 0;
      for (;;) { if (++size > 128) fail(); value(depth + 1); white(); if (text[index] === ']') { index++; return; } expect(','); }
    }
    const start = index; while (index < text.length && !/[\t\r\n ,}\]]/.test(text[index]!)) index++;
    if (!/^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$/.test(text.slice(start, index))) fail();
  };
  value(0); white(); if (index !== text.length) fail(); return parsed;
}
function identityResult(value: unknown): unknown {
  const result = familyObject(value, ['content'], ['isError']);
  if (Object.hasOwn(result, 'isError') && result.isError !== false || !Array.isArray(result.content) || result.content.length !== 1) fail();
  const content = familyObject(result.content[0], ['type', 'text']);
  if (content.type !== 'text' || typeof content.text !== 'string' || Buffer.byteLength(content.text) > DELEGATED_MCP_IDENTITY_HTTP_LIMITS.maxBodyBytes) fail();
  return strictJson(content.text);
}
export function createDelegatedMcpIdentityVerifier(deployment: unknown): DelegatedIdentityVerifier {
  return createDelegatedMcpIdentityVerifierForTrustedPorts(deployment, { fetch: nativeFetch });
}
/** Trusted test transport may map the exact logical HTTPS URL to owned loopback.
 * It must honor the child signal and join native I/O; arbitrary uncooperative
 * producer promises cannot supply universal bounded cleanup guarantees. */
export function createDelegatedMcpIdentityVerifierForTrustedPorts(input: unknown,
  inputPorts: DelegatedMcpIdentityHttpTrustedPorts): DelegatedIdentityVerifier {
  let deployment: DelegatedLoginDeployment, transport: typeof fetch, clock: () => number, timeoutMs: number;
  try {
    deployment = parseDelegatedLoginDeployment(input);
    const ports = familyObject(inputPorts, ['fetch'], ['nowSeconds', 'timeoutMs']);
    if (!deployment.client.resourceKinds.includes('mcp') || typeof ports.fetch !== 'function' || types.isProxy(ports.fetch)
      || ports.nowSeconds !== undefined && (typeof ports.nowSeconds !== 'function' || types.isProxy(ports.nowSeconds))) fail();
    transport = ports.fetch as typeof fetch; clock = ports.nowSeconds as (() => number) | undefined ?? (() => Math.floor(Date.now() / 1000));
    timeoutMs = ports.timeoutMs as number | undefined ?? DELEGATED_MCP_IDENTITY_HTTP_LIMITS.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DELEGATED_MCP_IDENTITY_HTTP_LIMITS.timeoutMs) fail();
  } catch { return fail('mcp_identity_configuration_invalid'); }
  const selected = JSON.stringify(deployment);
  return async (selectedDeployment, accessToken, resource, inputContext) => {
    let parent: AbortSignal, budget: DelegatedFamilyContext['budget'], assertion: () => void;
    try {
      if (JSON.stringify(parseDelegatedLoginDeployment(selectedDeployment)) !== selected || resource !== deployment.resources.mcp || !access(accessToken)) fail();
      const context = familyObject(inputContext, ['signal', 'budget']), fields = familyObject(context.budget, ['assertActive']);
      if (types.isProxy(context.signal) || typeof fields.assertActive !== 'function' || types.isProxy(fields.assertActive)) fail();
      aborted.call(context.signal); parent = context.signal as AbortSignal; budget = context.budget as DelegatedFamilyContext['budget']; assertion = fields.assertActive as () => void;
    } catch { return fail('mcp_identity_input_invalid'); }
    const controller = new AbortController(), deadline = monotonic() + timeoutMs, url = new URL(deployment.resources.mcp);
    let live = true, interrupted = false, failed = false, result: DelegatedVerifiedAccess | undefined;
    const stop = () => { interrupted = true; abort.call(controller); };
    const check = () => {
      try {
        if (!live || interrupted || aborted.call(parent) || monotonic() >= deadline) fail();
        const context = familyObject(inputContext, ['signal', 'budget']), fields = familyObject(budget, ['assertActive']);
        if (context.signal !== parent || context.budget !== budget || fields.assertActive !== assertion) fail(); assertion.call(budget);
        const after = familyObject(inputContext, ['signal', 'budget']), fieldsAfter = familyObject(budget, ['assertActive']);
        if (!live || interrupted || aborted.call(parent) || monotonic() >= deadline || after.signal !== parent || after.budget !== budget || fieldsAfter.assertActive !== assertion) fail();
      } catch { stop(); return fail(); }
    };
    const client = new Client({ name: 'bota-delegated-identity', version: '1' }, { capabilities: {} });
    client.onerror = () => { failed = true; stop(); };
    const pending = new Set<Promise<Response>>(), methods = new Set<string>();
    const fetchOne = async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
      let response: Response | undefined, stream: ReadableStream<Uint8Array> | null | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      const chunks: Uint8Array[] = [];
      try {
        check(); if (input !== url || !init || !['POST', 'GET'].includes(init.method ?? '')) fail();
        const headers = new Headers(init.headers);
        if (header.call(headers, 'authorization') !== `Bearer ${accessToken}` || header.call(headers, 'cookie') !== null || header.call(headers, 'mcp-session-id') !== null) fail();
        let message: Record<string, unknown> | undefined, method = 'GET';
        if (init.method === 'POST') {
          if (typeof init.body !== 'string') fail(); message = familyObject(strictJson(init.body), ['jsonrpc', 'method'], ['id', 'params']);
          if (message.jsonrpc !== '2.0' || typeof message.method !== 'string') fail(); method = message.method;
          if (!['initialize', 'notifications/initialized', 'tools/call'].includes(method)) fail();
          if (method !== 'notifications/initialized' && (!Number.isSafeInteger(message.id) || (message.id as number) < 0)) fail();
          if (method === 'tools/call') { const params = familyObject(message.params, ['name', 'arguments']);
            if (params.name !== 'get_delegated_identity') fail(); familyObject(params.arguments, []); }
        } else if (init.body !== undefined) fail();
        if (methods.has(method)) fail(); methods.add(method);
        response = await transport(url, { ...init, credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal });
        check(); stream = bodyOf.call(response); const status = statusOf.call(response), responseHeaders = headersOf.call(response);
        if (redirectedOf.call(response) || header.call(responseHeaders, 'mcp-session-id') !== null || header.call(responseHeaders, 'content-encoding') !== null
          || status !== (method === 'GET' ? 405 : method === 'notifications/initialized' ? 202 : 200)) fail();
        const length = header.call(responseHeaders, 'content-length'), contentType = header.call(responseHeaders, 'content-type');
        if (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > DELEGATED_MCP_IDENTITY_HTTP_LIMITS.maxBodyBytes)
          || status === 200 && (!contentType || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType))) fail();
        let size = 0;
        if (stream) {
          reader = getReader.call(stream) as ReadableStreamDefaultReader<Uint8Array>;
          for (;;) { check(); const part = await read.call(reader); check(); if (part.done) break;
            if (types.isProxy(part.value) || !types.isUint8Array(part.value)) fail(); size += part.value.byteLength;
            if (size > DELEGATED_MCP_IDENTITY_HTTP_LIMITS.maxBodyBytes) fail(); chunks.push(Uint8Array.from(part.value)); }
        }
        if (length !== null && Number(length) !== size || status !== 200 && size !== 0) fail();
        if (status !== 200) return new Response(null, { status });
        const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let text: string; try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } finally { bytes.fill(0); }
        const envelope = familyObject(strictJson(text), ['jsonrpc', 'id', 'result']);
        if (envelope.jsonrpc !== '2.0' || envelope.id !== message?.id) fail();
        if (method === 'tools/call') { const now = clock(); if (!familySeconds(now)) fail(); normalizeDelegatedIdentity(identityResult(envelope.result), { deployment, resource, nowSeconds: now }); }
        check(); return new Response(text, { status: 200, headers: { 'Content-Type': 'application/json' } });
      } finally {
        try { if (reader) await cancelReader.call(reader); else if (stream) await cancelBody.call(stream); else if (response) await bodyOf.call(response)?.cancel(); }
        finally { try { if (reader) release.call(reader); } finally { chunks.forEach(chunk => chunk.fill(0)); } }
      }
    };
    const fetchOwned: typeof fetch = (input, init) => {
      const work = Promise.resolve().then(() => fetchOne(input, init)).catch(() => { failed = true; stop(); return fail(); });
      pending.add(work); void work.finally(() => pending.delete(work)).catch(() => undefined); return work;
    };
    const join = async () => { while (pending.size) await Promise.allSettled([...pending]); };
    const timer = setTimeout(stop, timeoutMs); listen.call(parent, 'abort', stop, { once: true }); if (aborted.call(parent)) stop();
    try {
      check(); const transport = new StreamableHTTPClientTransport(url, { fetch: fetchOwned,
        requestInit: { headers: { Authorization: `Bearer ${accessToken}` }, redirect: 'error', credentials: 'omit' },
        reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1000, maxReconnectionDelay: 1000, reconnectionDelayGrowFactor: 1 } });
      const options = { signal: controller.signal, timeout: timeoutMs, maxTotalTimeout: timeoutMs };
      await client.connect(transport, options); check();
      const returned = await client.callTool({ name: 'get_delegated_identity', arguments: {} }, undefined, options); await join(); check();
      const now = clock(); if (!familySeconds(now)) fail(); result = normalizeDelegatedIdentity(identityResult(returned), { deployment, resource, nowSeconds: now });
    } catch { failed = true; }
    finally {
      // SDK1.29 retains cancellation callbacks after a successful response.
      // Disconnect before aborting the completed request signal, otherwise it
      // can try additional notifications/cancelled after the identity read.
      try { await client.close(); } catch { failed = true; }
      abort.call(controller);
      await join(); try { check(); } catch { failed = true; }
      live = false; clearTimeout(timer); unlisten.call(parent, 'abort', stop);
    }
    if (failed || !result) fail();
    try { const now = clock(); if (!familySeconds(now) || result.expiresAtSeconds <= now || result.expiresAtSeconds - now > 300) fail(); }
    catch { return fail(); }
    return result;
  };
}
