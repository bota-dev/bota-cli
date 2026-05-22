import { getApiKey, getApiUrl } from './config.js';

interface ClientOptions {
  apiKey?: string;
  apiUrl?: string;
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
    });

    if (res.status === 204) return undefined as T;

    const data = await res.json() as Record<string, unknown>;

    if (!res.ok) {
      const err = data['error'] as { message?: string } | undefined;
      throw new Error(err?.message ?? `HTTP ${res.status}`);
    }

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
  const res = await fetch(`${apiUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: toolName, arguments: args },
    }),
  });

  const text = await res.text();

  let jsonStr = text;
  for (const line of text.split('\n')) {
    if (line.startsWith('data:')) {
      jsonStr = line.slice(5).trim();
      break;
    }
  }

  const parsed = JSON.parse(jsonStr) as { result?: { content?: Array<{ text?: string }> } };
  const content = parsed.result?.content;
  if (Array.isArray(content) && content[0]?.text) {
    return content[0].text;
  }
  return jsonStr;
}
