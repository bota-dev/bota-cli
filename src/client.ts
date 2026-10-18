import { getApiKey, getApiUrl } from './config.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

interface ClientOptions {
  apiKey?: string;
  apiUrl?: string;
}

export class BotaApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly param?: string;
  readonly requestId?: string;

  constructor(status: number, error?: { message?: string; code?: string; param?: string; request_id?: string }) {
    super(error?.message ?? `HTTP ${status}`);
    this.name = 'BotaApiError';
    this.status = status;
    this.code = error?.code;
    this.param = error?.param;
    this.requestId = error?.request_id;
  }
}

export class BotaClient {
  private apiKey: string;
  private apiUrl: string;

  constructor(opts: ClientOptions = {}) {
    this.apiKey = opts.apiKey ?? getApiKey();
    this.apiUrl = opts.apiUrl ?? getApiUrl();
  }

  private async request<T>(method: string, path: string, body?: unknown, params?: Record<string, string | number | undefined>): Promise<T> {
    let url = `${this.apiUrl}${path}`;

    if (params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined) qs.set(k, String(v));
      }
      const str = qs.toString();
      if (str) url += `?${str}`;
    }

    const res = await fetch(url, {
      method,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });

    if (res.status === 204) return undefined as T;

    const data = await res.json().catch(() => undefined) as Record<string, unknown> | undefined;

    if (!res.ok) {
      throw new BotaApiError(res.status, data?.['error'] as ConstructorParameters<typeof BotaApiError>[1]);
    }

    if (data === undefined) throw new Error(`HTTP ${res.status}: expected a JSON response`);

    return data as T;
  }

  get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
    return this.request<T>('GET', path, undefined, params);
  }

  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PATCH', path, body);
  }

  delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }
}

export async function callMcpTool(apiUrl: string, apiKey: string, toolName: string, args: Record<string, unknown>): Promise<string> {
  const client = new Client({ name: 'bota-cli', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`${apiUrl.replace(/\/+$/, '')}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${apiKey}` }, redirect: 'error' },
  });
  try {
    await client.connect(transport);
    const result = CallToolResultSchema.parse(await client.callTool({ name: toolName, arguments: args }, undefined, { timeout: 30_000 }));
    const content = result.content.find(item => item.type === 'text');
    const text = content?.type === 'text' ? content.text : JSON.stringify(result);
    if (result.isError) throw new Error(text);
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      // Successful text-only tool results retain the existing string return shape.
    }
    if (value && typeof value === 'object' && 'success' in value && value.success === false) {
      const failed = value as { error?: string; status_code?: number };
      throw new Error(failed.error ?? `Webhook delivery failed${failed.status_code ? ` (HTTP ${failed.status_code})` : ''}`);
    }
    return text;
  } finally {
    await client.close();
  }
}
