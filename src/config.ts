import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ProjectIdentity } from './client.js';
import { NativeProfileTransactionError, type NativeOperationContext, type NativeResolvedCredential } from './native-profile-transaction.js';
import { hasDelegatedInvocation, refuseDelegatedCompatibility, assertDelegatedInvocationActive, captureDelegatedInvocationAccess } from './delegated-invocation.js';

const CONFIG_DIR = join(homedir(), '.bota');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const DEFAULT_API_URL = 'https://api.bota.dev';

interface ProfileContext {
  apiKey: string;
  apiUrl: string;
  identity: ProjectIdentity;
}

// A selected profile is resolved once before its command. It never reads or
// updates the legacy credential file, and it is not a saved default selection.
let profileContext: Readonly<ProfileContext> | undefined;
interface InvocationScope { readonly profile: Readonly<ProfileContext>; readonly context: NativeOperationContext; active: boolean }
const invocation = new AsyncLocalStorage<InvocationScope>();

/** A secure action never changes the process-wide compatibility selection.
 * Descendants retain their scope, but cannot use it once the action settles. */
export async function withInvocationCredential<T>(credential: NativeResolvedCredential, context: NativeOperationContext,
  action: () => Promise<T>): Promise<T> {
  const profile = { apiUrl: credential.apiOrigin, identity: { ...credential.identity,
    scopes: credential.identity.scopes === null ? null : [...credential.identity.scopes] } } as ProfileContext;
  Object.defineProperty(profile, 'apiKey', { value: credential.apiKey });
  const scope: InvocationScope = { profile: Object.freeze(profile), context, active: true };
  try { return await invocation.run(scope, action); }
  finally { scope.active = false; }
}

export function isSecureInvocation(): boolean { return invocation.getStore() !== undefined || hasDelegatedInvocation(); }
export function assertInvocationActive(): void {
  assertDelegatedInvocationActive();
  const scope = invocation.getStore();
  if (!scope) return;
  if (!scope.active) throw new NativeProfileTransactionError('profile_operation_failed', false, true);
  if (scope.context.signal.aborted) throw new NativeProfileTransactionError('profile_cancelled', false, true);
  try { scope.context.budget.assertActive(); }
  catch { throw new NativeProfileTransactionError('profile_deadline', false, true); }
}
export function getInvocationSignal(): AbortSignal | undefined { assertInvocationActive(); return invocation.getStore()?.context.signal; }
/** A client cannot carry a credential into another action or outlive its own
 * callback, including caller-owned contexts whose signal remains un-aborted. */
export function captureInvocationAccess(): () => void {
  const expected = invocation.getStore();
  const delegated = captureDelegatedInvocationAccess();
  return () => {
    delegated();
    if (invocation.getStore() !== expected) throw new NativeProfileTransactionError('profile_binding_mismatch');
    assertInvocationActive();
  };
}
export function assertInvocationCredential(apiUrl?: string, apiKey?: string): void {
  assertInvocationActive();
  const scope = invocation.getStore();
  if (scope && (apiUrl !== undefined && apiUrl !== scope.profile.apiUrl
    || apiKey !== undefined && apiKey !== scope.profile.apiKey)) throw new NativeProfileTransactionError('profile_binding_mismatch');
}

export function setProfileContext(context: ProfileContext): void {
  profileContext = Object.freeze({ ...context });
}

export function getProfileContext(): Readonly<ProfileContext> | undefined {
  refuseDelegatedCompatibility();
  assertInvocationActive();
  if (invocation.getStore()) return invocation.getStore()!.profile;
  return profileContext;
}

interface Config {
  apiKey?: string;
  apiUrl?: string;
}

export function readConfig(): Config {
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function writeConfig(config: Config): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

export function getApiKey(): string {
  const selected = getProfileContext();
  if (selected) return selected.apiKey;
  const config = readConfig();
  const key = config.apiKey ?? process.env['BOTA_API_KEY'];
  if (!key) {
    console.error('Not authenticated. Run: bota auth login <key>');
    process.exit(1);
  }
  return key;
}

export function getApiUrl(override?: string): string {
  const selected = getProfileContext();
  if (selected) return selected.apiUrl;
  if (override) return override;
  if (process.env['BOTA_API_URL']) return process.env['BOTA_API_URL'];
  const config = readConfig();
  return config.apiUrl ?? DEFAULT_API_URL;
}

export function getDashboardUrl(apiUrl: string): string {
  // api.bota.dev → platform.bota.dev, api.dev.bota.dev → platform.dev.bota.dev
  try {
    const u = new URL(apiUrl);
    u.hostname = u.hostname.replace(/^api\./, 'platform.');
    return u.origin;
  } catch {
    return 'https://platform.bota.dev';
  }
}
