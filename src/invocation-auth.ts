import type { Command } from 'commander';
import { withInvocationCredential } from './config.js';
import { runWithSecureProfile, inspectSecureProfile } from './secure-profiles.js';
import { NativeProfileTransactionError, type NativeProfileBinding, type NativeProfileSnapshot,
  type NativeResolvedCredential, type NativeOperationContext } from './native-profile-transaction.js';
import type { SecureProfileOptions } from './secure-profiles.js';
import { hasDelegatedInvocation, refuseDelegatedCompatibility } from './delegated-invocation.js';
import { developerProfileService } from './developer-profile-production.js';
import type { DeveloperProfileService } from './developer-profile-service.js';
import { DeveloperProfileError } from './developer-profile-error.js';
import { captureDeveloperDeploymentSelection } from './developer-deployment-selection.js';

/** Explicit native selection wraps the complete action, including its cleanup.
 * There is no preAction/postAction lock handoff or saved default selection. */
export function withCommandAuth<Args extends unknown[], Result>(program: Command,
  action: (...args: Args) => Result | Promise<Result>, developer: DeveloperProfileService = developerProfileService): (...args: Args) => Promise<Result> {
  return async (...args) => {
    const options = program.opts();
    if (options['developerProfile'] !== undefined) {
      if (hasDelegatedInvocation() || ['profile', 'secureProfile', 'apiUrl', 'dashboardUrl'].some(name => options[name] !== undefined)) throw new DeveloperProfileError('developer_profile_invalid');
      const controller = new AbortController(); let interrupt: number | undefined;
      const sigint = () => { interrupt = 130; controller.abort(); }, sigterm = () => { interrupt = 143; controller.abort(); };
      process.once('SIGINT', sigint); process.once('SIGTERM', sigterm);
      try { return await developer.run(options['developerProfile'] as string, 'rest', async () => action(...args), { signal: controller.signal }); }
      finally { process.removeListener('SIGINT', sigint); process.removeListener('SIGTERM', sigterm); if (interrupt !== undefined) process.exitCode = interrupt; }
    }
    if (hasDelegatedInvocation() && options['secureProfile'] !== undefined) refuseDelegatedCompatibility();
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

/** Pin only nonsecret native metadata at startup. Every tools/list or tools/call
 * opens its own protected runtime and exact-resource current admission. */
export function bindDeveloperMcpRequestAuth(service: Pick<DeveloperProfileService, 'pin' | 'run'>) {
  return async (name: string, signal?: AbortSignal): Promise<RequestAuth> => {
    const inSelection = captureDeveloperDeploymentSelection();
    const expected = await service.pin(name, { signal, timeoutMs: 30_000 });
    return (signal, action) => inSelection(() => service.run(name, 'mcp', action, { signal, timeoutMs: 30_000 }, expected));
  };
}
export const createDeveloperMcpRequestAuth = bindDeveloperMcpRequestAuth(developerProfileService);
