import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod/v3';
import { callMcpTool, IntegrationError, safeIntegration, safeIntegrationError, safeIntegrationList, safeIntegrationTest } from '../client.js';

// The SDK calls this public Zod v3 method when validating an object. Keep the
// real object schema for tools/list, but prevent raw issues (including unknown
// property names and supplied values) from becoming tool error text.
function privateInput<T extends z.AnyZodObject>(schema: T) {
  const parse = schema.safeParseAsync.bind(schema);
  schema.safeParseAsync = async (...args) => {
    const result = await parse(...args);
    if (!result.success) throw new Error('Invalid integration tool arguments.');
    return result;
  };
  return schema;
}

export function registerIntegrationMcpTools(server: McpServer, apiUrl: string, apiKey: string): void {
  const provider = z.object({ provider_type: z.enum(['asr', 'llm']), provider_name: z.enum(['whisper', 'deepgram', 'assemblyai', 'elevenlabs', 'gemini', 'openai', 'claude']) }).strict();
  const forward = async (name: string, args: Record<string, unknown>, decode: (value: unknown) => unknown) => {
    try {
      const text = await callMcpTool(apiUrl, apiKey, name, args);
      return { content: [{ type: 'text' as const, text: JSON.stringify(decode(JSON.parse(text)), null, 2) }] };
    } catch (error) {
      const safe = safeIntegrationError(error);
      return { content: [{ type: 'text' as const, text: JSON.stringify({ error: { code: safe.code, message: safe.message, ...(safe.status !== undefined && { status: safe.status }) } }) }], isError: true };
    }
  };
  server.registerTool('list_integrations', {
    description: 'List project integration metadata without credentials or raw provider errors.',
    inputSchema: privateInput(z.object({}).strict()), annotations: { readOnlyHint: true },
  }, () => forward('list_integrations', {}, safeIntegrationList));
  server.registerTool('get_integration', {
    description: 'Read project integration metadata without credentials or raw provider errors.',
    inputSchema: privateInput(provider), annotations: { readOnlyHint: true },
  }, args => forward('get_integration', args, safeIntegration));
  server.registerTool('test_integration', {
    description: 'Explicitly check the stored credential with the provider. May consume provider capacity; does not qualify processing or approve a regulated route.',
    inputSchema: privateInput(provider), annotations: { readOnlyHint: false, openWorldHint: true },
  }, args => forward('test_integration', args, safeIntegrationTest));
  server.registerTool('update_integration', {
    description: 'Enable or disable a project integration. Keys must be entered through Platform or secure CLI stdin.',
    inputSchema: privateInput(z.object({ id: z.string().min(1), is_enabled: z.boolean() }).strict()),
    annotations: { readOnlyHint: false, destructiveHint: true },
  }, args => forward('update_integration', args, safeIntegration));
  server.registerTool('delete_integration', {
    description: 'Delete a project integration. Existing processing pinned to it may fail after deletion.',
    inputSchema: privateInput(z.object({ id: z.string().min(1) }).strict()),
    annotations: { readOnlyHint: false, destructiveHint: true },
  }, args => forward('delete_integration', args, value => {
    if (!value || typeof value !== 'object' || !('deleted' in value) || value.deleted !== true) throw new IntegrationError('invalid_integration_response');
    return { deleted: true };
  }));
}
