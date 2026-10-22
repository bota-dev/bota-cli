import { Command } from 'commander';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { BotaClient, callMcpTool } from '../client.js';
import { getApiKey, getApiUrl } from '../config.js';
import { WEBHOOK_MANAGEMENT_UNAVAILABLE } from './webhooks.js';
import { errorDetails } from '../output.js';
import { registerIntegrationMcpTools } from './integration-mcp.js';
import { startHostedMcp } from './hosted-mcp.js';
import { createMcpRequestAuth, type RequestAuth } from '../invocation-auth.js';
import { installMcpRequestAuth } from '../mcp-request-auth.js';
import { refuseDelegatedCompatibility } from '../delegated-invocation.js';

function ok(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(e: unknown) {
  const detail = errorDetails(e);
  const content = [{ type: 'text' as const, text: detail.message }];
  if (Object.keys(detail).length > 1) content.push({ type: 'text', text: JSON.stringify({ error: detail }) });
  return { content, isError: true };
}

export interface McpCommandPorts {
  /** Trusted code/test composition only; never selected by command input. */
  readonly createRequestAuth: (name: string, apiUrlOverride?: string) => Promise<RequestAuth>;
}

export function registerMcp(program: Command, ports: McpCommandPorts = { createRequestAuth: createMcpRequestAuth }): void {
  program
    .command('mcp')
    .description('Start a local MCP server for IDE integration')
    .option('--mode <mode>', 'legacy local tools or explicit hosted canonical tools', 'legacy')
    .action(async (opts: { mode: string }) => {
      if (opts.mode !== 'legacy' && opts.mode !== 'hosted') throw new Error('--mode must be legacy or hosted.');
      const globalOpts = program.opts();
      const secure = globalOpts['secureProfile'] !== undefined;
      const authenticate = secure ? await ports.createRequestAuth(globalOpts['secureProfile'] as string, globalOpts['apiUrl'] as string | undefined) : undefined;
      const apiKey = secure ? undefined : getApiKey();
      const apiUrl = secure ? undefined : getApiUrl(globalOpts['apiUrl'] as string | undefined);
      if (opts.mode === 'hosted') { await startHostedMcp(apiUrl, apiKey, authenticate); return; }
      // Secure clients are constructed inside each authenticated callback. The
      // compatibility cohort retains its existing once-resolved startup client.
      const startup = secure ? undefined : new BotaClient({ apiKey, apiUrl });
      const client = {
        get: <T>(path: string, params?: Record<string, string | number | undefined>) => (startup ?? new BotaClient()).get<T>(path, params),
        post: <T>(path: string, body?: unknown) => (startup ?? new BotaClient()).post<T>(path, body),
      };

      const server = new McpServer({ name: 'bota', version: '0.1.0' });
      const requestAuth = authenticate ? installMcpRequestAuth(server.server,
        (signal, action) => authenticate(signal, async () => { refuseDelegatedCompatibility(); return action(); })) : undefined;
      registerIntegrationMcpTools(server, apiUrl, apiKey);

      server.registerTool(
        'list_end_users',
        {
          description: 'List end users',
          inputSchema: {
            limit: z.number().optional(),
            cursor: z.string().optional(),
            external_id: z.string().optional(),
          },
        },
        async ({ limit, cursor, external_id }) => {
          try {
            return ok(await client.get('/v1/end-users', { limit, cursor, external_id }));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'get_end_user',
        {
          description: 'Get end user by ID (eu_...) or external ID',
          inputSchema: { id: z.string() },
        },
        async ({ id }) => {
          try {
            if (id.startsWith('eu_')) {
              return ok(await client.get(`/v1/end-users/${id}`));
            } else {
              return ok(await client.get('/v1/end-users', { external_id: id }));
            }
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'list_devices',
        {
          description: 'List devices',
          inputSchema: {
            limit: z.number().optional(),
            cursor: z.string().optional(),
            end_user_id: z.string().optional(),
          },
        },
        async ({ limit, cursor, end_user_id }) => {
          try {
            return ok(await client.get('/v1/devices', { limit, cursor, end_user_id }));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'get_device',
        {
          description: 'Get device by ID',
          inputSchema: { id: z.string() },
        },
        async ({ id }) => {
          try {
            return ok(await client.get(`/v1/devices/${id}`));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'get_fleet_stats',
        {
          description: 'Get fleet statistics',
          inputSchema: {},
        },
        async () => {
          try {
            return ok(await client.get('/v1/devices/stats'));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'list_recordings',
        {
          description: 'List recordings',
          inputSchema: {
            limit: z.number().optional(),
            cursor: z.string().optional(),
            end_user_id: z.string().optional(),
            device_id: z.string().optional(),
            status: z.string().optional(),
            start_date: z.string().optional().describe('Include recordings created at or after this ISO timestamp'),
            end_date: z.string().optional().describe('Include recordings created before this ISO timestamp'),
          },
        },
        async ({ limit, cursor, end_user_id, device_id, status, start_date, end_date }) => {
          try {
            return ok(await client.get('/v1/recordings', { limit, cursor, end_user_id, device_id, status, start_date, end_date }));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'get_recording',
        {
          description: 'Get recording by ID including transcription and summary status',
          inputSchema: { id: z.string() },
        },
        async ({ id }) => {
          try {
            const recording = await client.get<Record<string, unknown>>(`/v1/recordings/${id}`);
            const transcriptionRes = await client.get<{ data: Array<Record<string, unknown>> }>('/v1/transcriptions', { recording_id: id });
            const transcription = transcriptionRes.data[0];
            if (transcription) {
              recording['transcription'] = transcription;
              const summaryRes = await client.get<{ data: Array<Record<string, unknown>> }>('/v1/summaries', { transcription_id: transcription['id'] as string });
              const summary = summaryRes.data[0];
              if (summary) recording['summary'] = summary;
            }
            return ok(recording);
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'create_transcription',
        {
          description: 'Create a transcription for a recording',
          inputSchema: {
            recording_id: z.string(),
            language: z.string().optional(),
          },
        },
        async ({ recording_id, language }) => {
          try {
            return ok(await client.post('/v1/transcriptions', { recording_id, language }));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'create_summary',
        {
          description: 'Create a summary from a transcription',
          inputSchema: {
            transcription_id: z.string(),
            template_id: z.string().optional(),
            prompt: z.string().optional(),
          },
        },
        async ({ transcription_id, template_id, prompt }) => {
          try {
            return ok(await client.post('/v1/summaries', { transcription_id, template_id, prompt }));
          } catch (e) { return fail(e); }
        },
      );

      server.registerTool(
        'list_webhooks',
        {
          description: 'List webhooks',
          inputSchema: { limit: z.number().optional() },
        },
        async () => fail(new Error(WEBHOOK_MANAGEMENT_UNAVAILABLE)),
      );

      server.registerTool(
        'trigger_webhook_event',
        {
          description: 'Trigger a webhook event for testing',
          inputSchema: {
            webhook_id: z.string(),
            event_type: z.string(),
          },
        },
        async ({ webhook_id, event_type }) => {
          try {
            const result = await callMcpTool(apiUrl ?? getApiUrl(), apiKey ?? getApiKey(), 'trigger_webhook_event', { webhook_id, event_type });
            return ok(result);
          } catch (e) { return fail(e); }
        },
      );

      const transport = new StdioServerTransport();
      requestAuth?.registered();
      let stop!: () => void;
      const stopped = new Promise<void>(resolve => { stop = resolve; });
      server.server.onclose = stop;
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
      process.stdin.once('end', stop); process.stdin.once('close', stop);
      try { await server.connect(transport); await stopped; }
      finally {
        requestAuth?.stop();
        try { await server.close(); }
        finally {
          await requestAuth?.join();
          process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
          process.stdin.removeListener('end', stop); process.stdin.removeListener('close', stop);
        }
      }
    });
}
