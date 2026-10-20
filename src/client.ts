import { getApiKey, getApiUrl } from './config.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

interface ClientOptions {
  apiKey?: string;
  apiUrl?: string;
}

// Private CLI identity model. This does not establish delegated login or profiles.
export interface ProjectIdentity {
  project_id: string;
  organization_id: string;
  key_id: string;
  key_type: 'secret' | 'restricted';
  is_test_mode: boolean;
  scope_mode: 'project_secret' | 'restricted';
  scopes: string[] | null;
}

// Decode only the existing seven-field project-key contract. Callers own
// transport bounds and any origin/project binding; this grants no authority.
export function parseProjectIdentity(value: unknown): ProjectIdentity {
  const data = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
  if (typeof data.project_id !== 'string' || typeof data.organization_id !== 'string' || typeof data.key_id !== 'string'
    || typeof data.is_test_mode !== 'boolean'
    || !(data.key_type === 'secret' && data.scope_mode === 'project_secret' && data.scopes === null
      || data.key_type === 'restricted' && data.scope_mode === 'restricted' && Array.isArray(data.scopes)
        && data.scopes.every(scope => typeof scope === 'string'))) {
    throw new BotaResponseError(undefined, 'unexpected identity response');
  }
  return {
    project_id: data.project_id, organization_id: data.organization_id, key_id: data.key_id,
    key_type: data.key_type as ProjectIdentity['key_type'], is_test_mode: data.is_test_mode,
    scope_mode: data.scope_mode as ProjectIdentity['scope_mode'], scopes: data.scopes === null ? null : [...data.scopes as string[]],
  };
}

export class BotaResponseError extends Error {
  constructor(readonly status?: number, detail = 'expected a JSON response') {
    super(status === undefined ? detail : `HTTP ${status}: ${detail}`);
    this.name = 'BotaResponseError';
  }
}

export const INTEGRATION_PROVIDERS = {
  asr: ['whisper', 'deepgram', 'assemblyai', 'elevenlabs'],
  llm: ['gemini', 'openai', 'claude'],
} as const;
export type IntegrationProviderType = keyof typeof INTEGRATION_PROVIDERS;

// These are private CLI models, not a released Bota API SDK.
export interface Integration {
  id: string;
  project_id: string;
  provider_type: IntegrationProviderType;
  provider_name: string;
  is_enabled: boolean;
  has_error: boolean;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

const integrationMessages = {
  invalid_request: 'Check the integration identifiers and required fields.',
  validation_error: 'Check the integration identifiers and required fields.',
  invalid_api_key: 'Authenticate with a project developer credential.',
  expired_api_key: 'The project developer credential has expired.',
  insufficient_permissions: 'This credential does not grant the required integration scope.',
  resource_not_found: 'Integration not found in this project.',
  rate_limit_exceeded: 'The integration operation is rate limited. Retry after the limit resets.',
  provider_route_not_approved: 'Credential testing is not approved for this project.',
  provider_credential_unavailable: 'The stored provider credential is unavailable.',
  idempotency_conflict: 'Reconcile the previous integration operation before attempting another write.',
  invalid_integration_input: 'Use a valid integration UUID and an ASR or LLM provider supported by this CLI.',
  invalid_integration_response: 'The integration response did not match the expected safe contract.',
  integration_key_input_required: 'Pipe one provider API key into stdin with --key-stdin; interactive key entry is unavailable.',
  integration_key_input_invalid: 'Stdin must contain one nonempty UTF-8 key line without whitespace or control characters.',
  integration_key_input_too_large: 'Provider key input exceeds the 16 KiB limit.',
  integration_key_input_timeout: 'Provider key input timed out before EOF.',
  integration_operation_failed: 'Integration operation failed. Check project access and Platform diagnostics.',
} as const;

export class IntegrationError extends Error {
  constructor(readonly code: keyof typeof integrationMessages, readonly status?: number) {
    super(integrationMessages[code]);
    this.name = 'IntegrationError';
  }
}

export function safeIntegrationError(error: unknown): IntegrationError {
  if (error instanceof IntegrationError) return error;
  if (error instanceof Error && !(error instanceof BotaApiError)) {
    try {
      const detail = JSON.parse(error.message)?.error as { code?: unknown; status?: unknown } | undefined;
      if (typeof detail?.code === 'string'
        && ['invalid_request', 'invalid_api_key', 'insufficient_permissions', 'resource_not_found', 'rate_limit_exceeded', 'provider_route_not_approved', 'provider_credential_unavailable'].includes(detail.code)
        && typeof detail.status === 'number' && Number.isInteger(detail.status) && detail.status >= 400 && detail.status <= 599) {
        return new IntegrationError(detail.code as keyof typeof integrationMessages, detail.status);
      }
    } catch { /* Arbitrary hosted text is never included in diagnostics. */ }
  }
  const code = error instanceof BotaApiError && Object.hasOwn(integrationMessages, error.code ?? '')
    ? error.code as keyof typeof integrationMessages : 'integration_operation_failed';
  return new IntegrationError(code, error instanceof BotaApiError ? error.status : undefined);
}

export function integrationProvider(type: string, name: string): IntegrationProviderType {
  if ((type !== 'asr' && type !== 'llm') || !(INTEGRATION_PROVIDERS[type] as readonly string[]).includes(name)) {
    throw new IntegrationError('invalid_integration_input');
  }
  return type;
}

export function integrationId(value: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new IntegrationError('invalid_integration_input');
  return value;
}

function integrationObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new IntegrationError('invalid_integration_response');
  return value as Record<string, unknown>;
}

export function safeIntegration(value: unknown): Integration {
  const data = integrationObject(value);
  const timestamp = (value: unknown): value is string => typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
  if (typeof data.id !== 'string' || typeof data.project_id !== 'string' || typeof data.provider_type !== 'string'
    || typeof data.provider_name !== 'string' || typeof data.is_enabled !== 'boolean'
    || !(data.last_used_at === null || timestamp(data.last_used_at)) || !timestamp(data.created_at) || !timestamp(data.updated_at)) {
    throw new IntegrationError('invalid_integration_response');
  }
  return {
    id: integrationId(data.id), project_id: integrationId(data.project_id),
    provider_type: integrationProvider(data.provider_type, data.provider_name), provider_name: data.provider_name,
    is_enabled: data.is_enabled, has_error: typeof data.has_error === 'boolean' ? data.has_error : Boolean(data.last_error),
    last_used_at: data.last_used_at, created_at: data.created_at, updated_at: data.updated_at,
  };
}

export function safeIntegrationList(value: unknown): { data: Integration[] } {
  const page = integrationObject(value);
  if (!Array.isArray(page.data)) throw new IntegrationError('invalid_integration_response');
  return { data: page.data.map(safeIntegration) };
}

const integrationTestMessages = {
  credential_valid: 'The provider accepted the basic credential check.',
  credential_missing: 'No enabled stored credential is available for this provider.',
  credential_rejected: 'The provider rejected the stored credential.',
  provider_rate_limited: 'The provider rate limited the credential check.',
  provider_test_failed: 'The basic provider credential check failed.',
} as const;
export interface IntegrationTestResult {
  success: boolean;
  code: keyof typeof integrationTestMessages;
  message: string;
  provider_status?: number;
}

export function safeIntegrationTest(value: unknown): IntegrationTestResult {
  const data = integrationObject(value);
  if (typeof data.success !== 'boolean') throw new IntegrationError('invalid_integration_response');
  const legacyStatus = typeof data.message === 'string' ? /^API error: ([1-5][0-9]{2})$/.exec(data.message)?.[1] : undefined;
  const code = typeof data.code === 'string' && Object.hasOwn(integrationTestMessages, data.code)
    ? data.code as keyof typeof integrationTestMessages : data.success ? 'credential_valid'
      : data.message === 'No API key configured for this provider' ? 'credential_missing'
        : data.message === 'Invalid API key' ? 'credential_rejected' : legacyStatus === '429' ? 'provider_rate_limited' : 'provider_test_failed';
  if (data.success !== (code === 'credential_valid')) throw new IntegrationError('invalid_integration_response');
  const providerStatus = legacyStatus ? Number(legacyStatus) : data.provider_status;
  return { success: data.success, code, message: integrationTestMessages[code],
    ...(!data.success && Number.isInteger(providerStatus) && Number(providerStatus) >= 100 && Number(providerStatus) <= 599
      ? { provider_status: Number(providerStatus) } : {}) };
}

export class BotaApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly param?: string;
  readonly requestId?: string;
  readonly retryAfter?: string;
  readonly rateLimit?: Record<string, string>;

  constructor(status: number, error?: { message?: string; code?: string; param?: string; request_id?: string }, headers?: Headers) {
    super(typeof error?.message === 'string' ? error.message : `HTTP ${status}`);
    this.name = 'BotaApiError';
    this.status = status;
    this.code = typeof error?.code === 'string' ? error.code : undefined;
    this.param = typeof error?.param === 'string' ? error.param : undefined;
    this.requestId = typeof error?.request_id === 'string' ? error.request_id : headers?.get('x-request-id') ?? undefined;
    this.retryAfter = headers?.get('retry-after') ?? undefined;
    const rateLimit: Record<string, string> = {};
    for (const name of ['ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset', 'ratelimit-policy', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-tier']) {
      const value = headers?.get(name);
      if (value !== undefined && value !== null) rateLimit[name] = value;
    }
    if (Object.keys(rateLimit).length) this.rateLimit = rateLimit;
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
      throw new BotaApiError(res.status, data?.['error'] as ConstructorParameters<typeof BotaApiError>[1], res.headers);
    }

    if (data === undefined) throw new BotaResponseError(res.status);

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

  async getProjectIdentity(): Promise<ProjectIdentity> {
    return parseProjectIdentity(await this.get<unknown>('/v1/auth/identity'));
  }

  private async integrationRequest<T>(method: string, path: string, body: unknown, decode: (value: unknown) => T): Promise<T> {
    try { return decode(await this.request<unknown>(method, path, body)); }
    catch (error) { throw safeIntegrationError(error); }
  }

  listIntegrations(): Promise<{ data: Integration[] }> {
    return this.integrationRequest('GET', '/v1/integrations', undefined, safeIntegrationList);
  }

  getIntegration(type: IntegrationProviderType, provider: string): Promise<Integration> {
    integrationProvider(type, provider);
    return this.integrationRequest('GET', `/v1/integrations/${type}/${encodeURIComponent(provider)}`, undefined, safeIntegration);
  }

  setIntegration(type: IntegrationProviderType, provider: string, apiKey: string): Promise<Integration> {
    integrationProvider(type, provider);
    return this.integrationRequest('POST', '/v1/integrations', { provider_type: type, provider_name: provider, api_key: apiKey }, safeIntegration);
  }

  rotateIntegration(id: string, apiKey: string): Promise<Integration> {
    return this.integrationRequest('PATCH', `/v1/integrations/${integrationId(id)}`, { api_key: apiKey }, safeIntegration);
  }

  setIntegrationEnabled(id: string, enabled: boolean): Promise<Integration> {
    return this.integrationRequest('PATCH', `/v1/integrations/${integrationId(id)}`, { is_enabled: enabled }, safeIntegration);
  }

  deleteIntegration(id: string): Promise<void> {
    return this.integrationRequest('DELETE', `/v1/integrations/${integrationId(id)}`, undefined, () => undefined);
  }

  deleteIntegrationByProvider(type: IntegrationProviderType, provider: string): Promise<void> {
    integrationProvider(type, provider);
    return this.integrationRequest('DELETE', `/v1/integrations/${type}/${encodeURIComponent(provider)}`, undefined, () => undefined);
  }

  testIntegration(type: IntegrationProviderType, provider: string): Promise<IntegrationTestResult> {
    integrationProvider(type, provider);
    return this.integrationRequest('POST', `/v1/integrations/${type}/${encodeURIComponent(provider)}/test`, {}, safeIntegrationTest);
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
    if (toolName === 'trigger_webhook_event' && value && typeof value === 'object' && 'success' in value && value.success === false) {
      const failed = value as { error?: string; status_code?: number };
      throw new Error(failed.error ?? `Webhook delivery failed${failed.status_code ? ` (HTTP ${failed.status_code})` : ''}`);
    }
    return text;
  } finally {
    await client.close();
  }
}
