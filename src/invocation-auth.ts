import type { Command } from 'commander';
import { withInvocationCredential } from './config.js';
import { runWithSecureProfile, inspectSecureProfile } from './secure-profiles.js';
import { NativeProfileTransactionError, type NativeProfileBinding, type NativeProfileSnapshot,
  type NativeResolvedCredential, type NativeOperationContext } from './native-profile-transaction.js';
import type { SecureProfileOptions } from './secure-profiles.js';

/** Explicit native selection wraps the complete action, including its cleanup.
 * There is no preAction/postAction lock handoff or saved default selection. */
export function withCommandAuth<Args extends unknown[], Result>(program: Command,
  action: (...args: Args) => Result | Promise<Result>): (...args: Args) => Promise<Result> {
  return async (...args) => {
    const options = program.opts();
    if (options['secureProfile'] === undefined) return action(...args);
    const controller = new AbortController();
    let interrupt: number | undefined;
    const sigint = () => { interrupt = 130; controller.abort(); };
    const sigterm = () => { interrupt = 143; controller.abort(); };
    process.once('SIGINT', sigint); process.once('SIGTERM', sigterm);
    try {
      return await runWithSecureProfile(options['secureProfile'] as string,
        { ...(options['apiUrl'] === undefined ? {} : { apiUrlOverride: options['apiUrl'] as string }), signal: controller.signal, timeoutMs: 120_000 },
        (credential, context) => withInvocationCredential(credential, context, async () => action(...args)));
    } finally {
      process.removeListener('SIGINT', sigint); process.removeListener('SIGTERM', sigterm);
      if (interrupt !== undefined) process.exitCode = interrupt;
    }
  };
}

export type RequestAuth = <T>(signal: AbortSignal, action: () => Promise<T>) => Promise<T>;

export interface McpProfileAuthService {
  inspect(name: string): Promise<NativeProfileSnapshot | null>;
  run<T>(name: string, options: SecureProfileOptions,
    action: (credential: NativeResolvedCredential, context: NativeOperationContext) => Promise<T>): Promise<T>;
}

/** MCP pins metadata at startup, then loads/verifies a credential for every
 * discovery/invocation. No bearer is kept in a server/client startup closure. */
export function bindMcpRequestAuth(service: McpProfileAuthService): (name: string, apiUrlOverride?: string) => Promise<RequestAuth> {
  return async (name, apiUrlOverride) => {
    const snapshot = await service.inspect(name);
    if (!snapshot) throw new NativeProfileTransactionError('profile_not_found');
    if (snapshot.journal) throw new NativeProfileTransactionError('profile_pending_recovery', true);
    const record = snapshot.record;
    if (!record || record.state !== 'ready') throw new NativeProfileTransactionError('profile_disabled');
    const expectedBinding: NativeProfileBinding = Object.freeze({ profile_id: record.profile_id,
      api_origin: record.api_origin, project_id: record.project_id, organization_id: record.organization_id });
    return (signal, action) => service.run(name, { ...(apiUrlOverride === undefined ? {} : { apiUrlOverride }), expectedBinding, signal, timeoutMs: 30_000 },
      (credential, context) => withInvocationCredential(credential, context, action));
  };
}

/** Production binds only the fixed native service. The factory above is an
 * explicit trusted test port; no CLI option, environment or metadata selects it. */
export const createMcpRequestAuth = bindMcpRequestAuth({ inspect: inspectSecureProfile, run: runWithSecureProfile });
