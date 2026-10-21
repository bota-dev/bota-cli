import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema, CancelledNotificationSchema, McpError, ErrorCode,
  type RequestId } from '@modelcontextprotocol/sdk/types.js';
import type { RequestAuth } from './invocation-auth.js';
import { NativeProfileTransactionError } from './native-profile-transaction.js';
import { errorDetails } from './output.js';

/** Decorate public SDK request-handler registration before registerTool installs
 * discovery/call handlers. No private registry/handler inspection is used.
 * The decorator is removed after registration; installed handlers keep the gate. */
export function installMcpRequestAuth(server: Server, authenticate: RequestAuth) {
  const original = server.setRequestHandler;
  const seen = new Set<unknown>(), active = new Map<RequestId, AbortController>(), pending = new Set<Promise<unknown>>();
  let stopping = false;
  type PublicExtra = { requestId: RequestId; signal: AbortSignal; [key: string]: unknown };
  type PublicHandler = (request: unknown, extra: PublicExtra) => unknown | Promise<unknown>;
  // The SDK's generic schema/handler association is preserved unchanged. This
  // local erasure only allows decorating the two exact pinned schema objects.
  const register = original.bind(server) as unknown as (schema: unknown, handler: PublicHandler) => void;
  const decorated = ((schema: unknown, handler: PublicHandler) => {
    if (schema !== CallToolRequestSchema && schema !== ListToolsRequestSchema) return register(schema, handler);
    seen.add(schema);
    return register(schema, async (request, extra) => {
      if (stopping || active.has(extra.requestId)) throw new McpError(ErrorCode.InternalError, 'The MCP request cannot be admitted.');
      const controller = new AbortController(); active.set(extra.requestId, controller);
      const abort = () => controller.abort();
      if (extra.signal.aborted) abort(); else extra.signal.addEventListener('abort', abort, { once: true });
      const operation = Promise.resolve().then(() => authenticate(controller.signal, async () => {
        const result = await handler(request, { ...extra, signal: controller.signal });
        // McpServer catches callback/argument failures and returns tool errors
        // rather than throwing. Their text may contain supplied values. The
        // secure legacy cohort deliberately replaces every such result and
        // conservatively marks even validation failures as an unknown outcome.
        if (result && typeof result === 'object' && 'isError' in result && result.isError === true) {
          const detail = errorDetails(new NativeProfileTransactionError('profile_operation_failed', false, true));
          return { content: [{ type: 'text', text: detail.message },
            { type: 'text', text: JSON.stringify({ error: detail }) }], isError: true };
        }
        return result;
      }))
        .catch(error => {
          const safe = error instanceof NativeProfileTransactionError ? error : new NativeProfileTransactionError('profile_operation_failed', false, true);
          throw new McpError(ErrorCode.InternalError, safe.message, { code: safe.code,
            recovery_required: safe.recovery_required, operation_may_have_executed: safe.operation_may_have_executed });
        }).finally(() => {
          controller.abort(); extra.signal.removeEventListener('abort', abort);
          if (active.get(extra.requestId) === controller) active.delete(extra.requestId);
        });
      pending.add(operation);
      try { return await operation; } finally { pending.delete(operation); }
    });
  }) as Server['setRequestHandler'];
  server.setRequestHandler = decorated;
  // SDK1.29's default handler ignores numeric request id0. Both discovery and
  // calls use this explicit controller, with no credential lookup on cancel.
  server.setNotificationHandler(CancelledNotificationSchema, message => {
    if (message.params.requestId !== undefined) active.get(message.params.requestId)?.abort();
  });
  return {
    registered(): void {
      if (server.setRequestHandler === decorated) server.setRequestHandler = original;
      if (seen.size !== 2) throw new McpError(ErrorCode.InternalError, 'MCP authentication registration is incomplete.');
    },
    stop(): void { stopping = true; for (const controller of active.values()) controller.abort(); },
    async join(): Promise<void> { await Promise.allSettled([...pending]); },
  };
}
