import { BotaApiError, BotaClient, BotaResponseError } from '../client.js';
import { printError } from '../output.js';

const messages = {
  not_authenticated: 'No credential is selected. Run: bota auth login, or supply BOTA_API_KEY.',
  invalid_credential: 'The API rejected this credential. It may be invalid, expired, or revoked.',
  permission_denied: 'This credential cannot read project developer identity. Use a project secret or restricted API key.',
  organization_access_quarantined: 'Organization access is quarantined. Check Bota Platform before continuing.',
  rate_limit_exceeded: 'The identity check is rate limited. Try again after the limit resets.',
  identity_service_unavailable: 'The identity service is unavailable. Try again later; credential validity is not established.',
  identity_http_error: 'The API could not complete the identity check. Check backend support and project access.',
  invalid_identity_response: 'The API returned an unexpected identity response. Check backend support before continuing.',
  identity_request_failed: 'The identity check could not reach the API. Check connectivity and the configured API endpoint.',
} as const;

class AuthStatusError extends Error {
  constructor(readonly code: keyof typeof messages, readonly status?: number) { super(messages[code]); }
}

function statusError(error: unknown): AuthStatusError {
  if (error instanceof BotaResponseError) return new AuthStatusError('invalid_identity_response', error.status);
  if (!(error instanceof BotaApiError)) return new AuthStatusError('identity_request_failed');
  const code = error.status === 401 ? 'invalid_credential' : error.status === 403 ? 'permission_denied'
    : error.status === 423 ? 'organization_access_quarantined' : error.status === 429 ? 'rate_limit_exceeded'
      : error.status >= 500 ? 'identity_service_unavailable' : 'identity_http_error';
  return new AuthStatusError(code, error.status);
}

function safeStatusJson(value: unknown, pretty = false): string {
  return JSON.stringify(value, null, pretty ? 2 : undefined)
    .replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/g,
      character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

export async function showAuthStatus(options: { apiKey?: string; apiUrl: string; json: boolean }): Promise<void> {
  try {
    if (!options.apiKey) throw new AuthStatusError('not_authenticated');
    const identity = await new BotaClient({ apiKey: options.apiKey, apiUrl: options.apiUrl }).getProjectIdentity();
    if (options.json) { console.log(safeStatusJson(identity, true)); return; }
    console.log('Authenticated project developer credential.');
    // The identifiers are opaque and stored scopes may contain arbitrary strings.
    // Escape C0/DEL/C1 and direction/line controls without filtering the values.
    console.log(`Project: ${safeStatusJson(identity.project_id)}`);
    console.log(`Organization: ${safeStatusJson(identity.organization_id)}`);
    console.log(`Credential ID: ${safeStatusJson(identity.key_id)}`);
    console.log(`Credential type: ${identity.key_type}`);
    console.log(`Key test flag: ${identity.is_test_mode}`);
    console.log(`Scope mode: ${identity.scope_mode}`);
    console.log(`Scopes: ${safeStatusJson(identity.scopes)}`);
  } catch (error) {
    printError(error instanceof AuthStatusError ? error : statusError(error), options.json);
    process.exitCode = 1;
  }
}
