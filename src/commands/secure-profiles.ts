import { Command } from 'commander';
import { types } from 'node:util';
import { NativeProfileTransactionError, type NativeProfileErrorCode, type NativeOperationContext, type NativeProfileRecord,
  type NativeProfileSnapshot } from '../native-profile-transaction.js';
import { WindowsNativeError, type WindowsNativeErrorCode } from '../windows-native-api.js';
import { printError } from '../output.js';
import { readSecureKey, SecureKeyInputError, type SecureKeyInputOptions } from '../secure-key-input.js';

const messages = {
  invalid_secure_profile_command: 'Invalid secure profile command. Run bota auth secure-profiles --help; API keys are accepted only through explicit secure input.',
  secure_profile_api_url_required: 'Secure profile enrollment requires an explicit --api-url for the trusted API origin.',
  secure_profile_input_required: 'Select exactly one of --key-stdin, --key-prompt or --from-env.',
  secure_profile_failed: 'The secure profile operation failed. Inspect its state before attempting recovery.',
} as const;
export class SecureProfileCommandError extends Error {
  declare readonly code: keyof typeof messages;
  constructor(code: keyof typeof messages) {
    const safeCode = Object.hasOwn(messages, code) ? code : 'secure_profile_failed';
    super(messages[safeCode]); this.name = 'SecureProfileCommandError';
    Object.defineProperty(this, 'code', { value: safeCode, enumerable: true });
  }
}

export interface SecureProfileCommandService {
  enrollSecureProfile(input: { name: string; apiOrigin: string; allowHttpLoopback?: boolean;
    readKey: (context: NativeOperationContext) => Promise<string> }, options?: { signal: AbortSignal }): Promise<NativeProfileRecord>;
  inspectSecureProfile(name: string, options?: { signal: AbortSignal }): Promise<NativeProfileSnapshot | null>;
  removeSecureProfile(name: string, options?: { signal: AbortSignal }): Promise<NativeProfileRecord>;
  recoverSecureProfile(name: string, options?: { signal: AbortSignal }): Promise<NativeProfileRecord>;
}

const nativeCodes: readonly WindowsNativeErrorCode[] = ['windows_native_unsupported', 'windows_native_environment',
  'windows_native_untrusted', 'windows_native_unavailable', 'windows_native_busy', 'windows_native_close_unknown', 'windows_native_poisoned'];

/** Never surface arbitrary provider/host errors, causes, paths, or input values. */
export function sanitizeSecureProfileCommandError(error: unknown): Error {
  if (error && typeof error === 'object' && !types.isProxy(error)) {
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    if (typeof code !== 'string') return new SecureProfileCommandError('secure_profile_failed');
    if (error instanceof SecureProfileCommandError && Object.hasOwn(messages, code)) return new SecureProfileCommandError(code as keyof typeof messages);
    if (error instanceof SecureKeyInputError) return new SecureKeyInputError(code as SecureKeyInputError['code']);
    if (error instanceof NativeProfileTransactionError) {
      return new NativeProfileTransactionError(code as NativeProfileErrorCode, Object.getOwnPropertyDescriptor(error, 'recovery_required')?.value === true,
        Object.getOwnPropertyDescriptor(error, 'operation_may_have_executed')?.value === true);
    }
    if (error instanceof WindowsNativeError && nativeCodes.includes(code as WindowsNativeErrorCode)) return new WindowsNativeError(code as WindowsNativeErrorCode);
  }
  return new SecureProfileCommandError('secure_profile_failed');
}

function show(value: unknown): void {
  console.log(JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`));
}

function projection(record: NativeProfileRecord): Record<string, unknown> {
  return { name: record.name, format_version: record.format_version, api_origin: record.api_origin,
    project_id: record.project_id, organization_id: record.organization_id, key_id: record.key_id,
    credential_source: record.store_id, allow_http_loopback: record.allow_http_loopback, state: record.state };
}

async function boundary(work: (signal: AbortSignal) => Promise<void>): Promise<void> {
  const controller = new AbortController(); let interrupt: number | undefined;
  const sigint = () => { interrupt = 130; controller.abort(); };
  const sigterm = () => { interrupt = 143; controller.abort(); };
  process.once('SIGINT', sigint); process.once('SIGTERM', sigterm);
  try { await work(controller.signal); } catch (error) {
    const safe = sanitizeSecureProfileCommandError(error);
    if (interrupt === undefined && safe instanceof NativeProfileTransactionError && safe.code === 'profile_cancelled') interrupt = 130;
    throw safe;
  }
  finally {
    process.removeListener('SIGINT', sigint); process.removeListener('SIGTERM', sigterm);
    if (interrupt !== undefined) process.exitCode = interrupt;
  }
}

export function registerSecureProfiles(auth: Command, program: Command, service: SecureProfileCommandService,
  input: Omit<SecureKeyInputOptions, 'mode' | 'signal'> = {}): void {
  const profiles = new Command('secure-profiles').description('Manage explicitly enrolled API keys in the supported OS credential store')
    .allowExcessArguments(false).configureOutput({ outputError: () => {
      printError(new SecureProfileCommandError('invalid_secure_profile_command'), Boolean(program.opts()['json']));
    } });
  auth.addCommand(profiles);
  profiles.command('add <name>').allowExcessArguments(false)
    .description('Verify and securely enroll a key; never accepts key arguments or silently imports legacy credentials')
    .option('--key-stdin', 'Read one API key from piped standard input')
    .option('--key-prompt', 'Read one API key from an interactive terminal without echo')
    .option('--from-env', 'Explicitly enroll BOTA_API_KEY from the current environment')
    .option('--allow-http-loopback', 'Explicitly permit a literal loopback HTTP API origin')
    .action(async (name: string, options: { keyStdin?: boolean; keyPrompt?: boolean; fromEnv?: boolean; allowHttpLoopback?: boolean }) => boundary(async signal => {
      const apiOrigin = program.opts()['apiUrl'] as string | undefined;
      if (apiOrigin === undefined) throw new SecureProfileCommandError('secure_profile_api_url_required');
      if ([options.keyStdin, options.keyPrompt, options.fromEnv].filter(Boolean).length !== 1) {
        throw new SecureProfileCommandError('secure_profile_input_required');
      }
      const mode = options.keyStdin ? 'stdin' : options.keyPrompt ? 'prompt' : 'environment';
      const record = await service.enrollSecureProfile({ name, apiOrigin, allowHttpLoopback: options.allowHttpLoopback,
        readKey: async context => {
          context.budget.assertActive();
          let key: string;
          try { key = await readSecureKey({ ...input, mode, signal: context.signal }); }
          catch (error) {
            if (error instanceof SecureKeyInputError && error.code === 'secure_key_cancelled') throw new NativeProfileTransactionError('profile_cancelled');
            throw error;
          }
          context.budget.assertActive();
          return key;
        } }, { signal });
      show(projection(record));
    }));
  profiles.command('show <name>').allowExcessArguments(false)
    .description('Inspect non-secret metadata and whether explicit recovery is required')
    .action(async (name: string) => boundary(async signal => {
      const snapshot = await service.inspectSecureProfile(name, { signal });
      if (snapshot === null) { show({ name, state: 'absent' }); return; }
      const record = snapshot.record ?? snapshot.journal!.desired;
      show({ ...projection(record), recovery_required: snapshot.journal !== null,
        ...(snapshot.journal && { pending_operation: snapshot.journal.operation }) });
    }));
  profiles.command('remove <name>').allowExcessArguments(false)
    .description('Disable selection and remove the exact local credential; does not revoke the project API key')
    .action(async (name: string) => boundary(async signal => {
      const record = await service.removeSecureProfile(name, { signal });
      show({ name: record.name, state: record.state, removed: record.state === 'removed' });
    }));
  profiles.command('recover <name>').allowExcessArguments(false)
    .description('Recover the exact retained enrollment or removal transaction without importing another credential')
    .action(async (name: string) => boundary(async signal => { show(projection(await service.recoverSecureProfile(name, { signal }))); }));
}
