import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema, CallToolResultSchema, CancelledNotificationSchema, ErrorCode,
  ListToolsRequestSchema, ListToolsResultSchema, McpError,
  type CallToolRequest, type ListToolsRequest, type RequestId,
} from '@modelcontextprotocol/sdk/types.js';
import { getApiKey, getApiUrl, captureInvocationAccess } from '../config.js';
import type { RequestAuth } from '../invocation-auth.js';
import { NativeProfileTransactionError } from '../native-profile-transaction.js';
import { captureDelegatedMcpInvocation } from '../delegated-invocation.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

const REQUEST_BUDGET_MS = 30_000;
const UNKNOWN_OUTCOME = 'The outcome of a submitted operation may be unknown. Inspect its owning resource before retrying.';

export async function closeHostedTransport(close: () => Promise<void>, cleanup: () => void | Promise<void>): Promise<void> {
  let failed = false;
  try { await close(); } catch { failed = true; }
  finally { try { await cleanup(); } catch { failed = true; } }
  if (failed) throw new McpError(ErrorCode.InternalError, `Hosted MCP cleanup failed. ${UNKNOWN_OUTCOME}`);
}

function hostedUrl(apiUrl: string): URL {
  try {
    const url = new URL(apiUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error();
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/mcp`;
    return url;
  } catch { throw new Error('Use an HTTP(S) API base URL without embedded credentials, query, or fragment.'); }
}

export async function startHostedMcp(apiUrl?: string, apiKey?: string, authenticate?: RequestAuth): Promise<void> {
  return serveHostedMcp(new StdioServerTransport(), apiUrl, apiKey, authenticate, true);
}

/** Trusted composition for an explicitly supplied local transport. This runs
 * the same forward handlers and joined shutdown, without process/stdin owners. */
export async function startHostedMcpWithTransport(transport: Transport, authenticate: RequestAuth): Promise<void> {
  return serveHostedMcp(transport, undefined, undefined, authenticate, false);
}

async function serveHostedMcp(downstream: Transport, apiUrl: string | undefined, apiKey: string | undefined,
  authenticate: RequestAuth | undefined, processOwned: boolean): Promise<void> {
  const startupUrl = authenticate ? undefined : hostedUrl(apiUrl!);
  const server = new Server({ name: 'bota-hosted-bridge', version: '0.1.0' }, { capabilities: { tools: {} } });
  const active = new Map<RequestId, AbortController>();
  const pending = new Set<Promise<unknown>>();
  let stopping = false;
  let stop!: () => void;
  const stopped = new Promise<void>(resolve => { stop = resolve; });
  server.onclose = stop;
  server.onerror = () => undefined;

  const forward = (request: CallToolRequest | ListToolsRequest, downstreamSignal: AbortSignal, id: RequestId) => {
    if (stopping) throw new McpError(ErrorCode.InternalError, 'The hosted MCP bridge is stopping.');
    if (active.has(id)) throw new McpError(ErrorCode.InvalidRequest, 'A request with this ID is already active.');
    if (request.method === 'tools/call' && request.params.task) throw new McpError(ErrorCode.InvalidParams, 'Task-augmented requests are not supported by this hosted bridge.');
    const controller = new AbortController();
    active.set(id, controller);
    const abort = () => controller.abort();
    if (downstreamSignal.aborted) abort(); else downstreamSignal.addEventListener('abort', abort, { once: true });
    let expired = false;
    const timer = setTimeout(() => { expired = true; abort(); }, REQUEST_BUDGET_MS);
    const fetchCleanup: Array<() => void> = [];
    const scoped = async () => {
      const assertAccess = captureInvocationAccess();
      const delegated = captureDelegatedMcpInvocation();
      if (delegated && request.method === 'tools/call') delegated.authorizeTool(request.params.name);
      const upstream = new Client({ name: 'bota-hosted-bridge', version: '0.1.0' }, { capabilities: {} });
      upstream.onerror = () => undefined;
      try {
        const transport = new StreamableHTTPClientTransport(delegated ? new URL(delegated.url) : startupUrl ?? hostedUrl(getApiUrl()), {
          requestInit: { headers: { Authorization: `Bearer ${delegated?.accessToken ?? apiKey ?? getApiKey()}` }, redirect: 'error' },
          reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1000, maxReconnectionDelay: 1000, reconnectionDelayGrowFactor: 1 },
          fetch: (input, init) => {
            assertAccess();
            const fetchController = new AbortController();
            const cancelFetch = () => fetchController.abort();
            for (const signal of [controller.signal, init?.signal]) {
              if (!signal) continue;
              if (signal.aborted) cancelFetch(); else {
                signal.addEventListener('abort', cancelFetch, { once: true });
                fetchCleanup.push(() => signal.removeEventListener('abort', cancelFetch));
              }
            }
            // SDK GET requests have a separate init; retain cancellation through
            // response-body consumption, not just response headers.
            return (delegated?.fetch ?? fetch)(input, { ...init, redirect: 'error', credentials: 'omit', signal: fetchController.signal });
          },
        });
        const options = { signal: controller.signal, timeout: REQUEST_BUDGET_MS, maxTotalTimeout: REQUEST_BUDGET_MS };
        await upstream.connect(transport, options);
        if (request.method === 'tools/list') return await upstream.request({ method: request.method, params: request.params }, ListToolsResultSchema, options);
        return await upstream.request({ method: request.method, params: request.params }, CallToolResultSchema, options);
      } catch (error) {
        const status = error instanceof StreamableHTTPError && typeof error.code === 'number' && error.code >= 100 && error.code <= 599 ? error.code : undefined;
        throw new McpError(expired ? ErrorCode.RequestTimeout : ErrorCode.InternalError,
          `${expired ? 'Hosted MCP request exceeded its 30-second total deadline.' : controller.signal.aborted ? 'Hosted MCP request was cancelled.' : 'Hosted MCP request failed.'} ${UNKNOWN_OUTCOME}`,
          status === undefined ? undefined : { http_status: status });
      } finally {
        // Close first: aborting completed SDK requests can attempt cancellation
        // notifications, which must never create traffic after cleanup.
        await closeHostedTransport(() => upstream.close(), () => { for (const cleanup of fetchCleanup) cleanup(); });
      }
    };
    const operation = (async () => {
      try { return await (authenticate ? authenticate(controller.signal, scoped) : scoped()); }
      catch (error) {
        if (error instanceof NativeProfileTransactionError) throw new McpError(ErrorCode.InternalError, error.message,
          { code: error.code, recovery_required: error.recovery_required, operation_may_have_executed: error.operation_may_have_executed });
        throw error;
      }
      finally {
        controller.abort(); clearTimeout(timer);
        downstreamSignal.removeEventListener('abort', abort);
        for (const cleanup of fetchCleanup) cleanup();
        if (active.get(id) === controller) active.delete(id);
      }
    })();
    pending.add(operation);
    void operation.finally(() => pending.delete(operation)).catch(() => undefined);
    return operation;
  };

  server.setRequestHandler(ListToolsRequestSchema, (request, extra) => forward(request, extra.signal, extra.requestId));
  server.setRequestHandler(CallToolRequestSchema, (request, extra) => forward(request, extra.signal, extra.requestId));
  // SDK 1.29 ignores numeric request ID 0 in its default cancellation handler.
  server.setNotificationHandler(CancelledNotificationSchema, notification => {
    if (notification.params.requestId !== undefined) active.get(notification.params.requestId)?.abort();
  });

  if (processOwned) {
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    process.stdin.once('end', stop);
    process.stdin.once('close', stop);
  }
  try {
    await server.connect(downstream);
    await stopped;
  } finally {
    stopping = true;
    for (const controller of active.values()) controller.abort();
    await closeHostedTransport(() => server.close(), async () => {
      try { await Promise.allSettled([...pending]); }
      finally {
        if (processOwned) {
          process.removeListener('SIGINT', stop);
          process.removeListener('SIGTERM', stop);
          process.stdin.removeListener('end', stop);
          process.stdin.removeListener('close', stop);
        }
      }
    });
  }
}
