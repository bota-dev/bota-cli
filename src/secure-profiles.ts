/** Opt-in API-key profiles shared by CLI actions and individual MCP calls. */
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { normalizeProfileOrigin } from './profiles.js';
import {
  NativeProfileTransactionError,
  type NativeOperationContext,
  type NativeProfileBinding,
  type NativeProfileRecord,
  type NativeProfileSnapshot,
  type NativeProfileTransactions,
  type NativeResolvedCredential,
  type NativeSelectionOptions,
} from './native-profile-transaction.js';

export interface SecureProfileOptions {
  readonly context?: NativeOperationContext;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly env?: Record<string, unknown>;
  readonly apiUrlOverride?: string;
  readonly expectedBinding?: NativeProfileBinding;
}
export type SecureProfileEnrollment = {
  readonly name: string;
  readonly apiOrigin: string;
  readonly allowHttpLoopback?: boolean;
} & ({ readonly key: string; readonly readKey?: never }
  | { readonly key?: never; readonly readKey: (context: NativeOperationContext) => Promise<string> });

export interface SecureProfileRuntime {
  readonly engine: Pick<NativeProfileTransactions, 'withCredential' | 'enroll' | 'inspect' | 'remove' | 'recover'>;
  close(): void | Promise<void>;
}
export interface SecureProfileServiceDependencies {
  /** Trusted implementation/test port. Production never accepts a root option. */
  createRuntime(context: NativeOperationContext): Promise<SecureProfileRuntime>;
}

function failure(code: 'profile_invalid_input' | 'profile_key_required'): never {
  throw new NativeProfileTransactionError(code);
}
function nameChecked(name: unknown): asserts name is string {
  if (typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(name)) failure('profile_invalid_input');
}
function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) failure('profile_invalid_input');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== Object.keys(descriptors).length) failure('profile_invalid_input');
  const result: Record<string, unknown> = Object.create(null);
  for (const [name, descriptor] of Object.entries(descriptors)) {
    if (!allowed.includes(name) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) failure('profile_invalid_input');
    result[name] = descriptor.value;
  }
  return result;
}
function optionsChecked(options: SecureProfileOptions): SecureProfileOptions {
  const value = fields(options, ['context', 'signal', 'timeoutMs', 'env', 'apiUrlOverride', 'expectedBinding']);
  if (value.context !== undefined && (value.signal !== undefined || value.timeoutMs !== undefined)) failure('profile_invalid_input');
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) failure('profile_invalid_input');
  if (value.timeoutMs !== undefined && (!Number.isSafeInteger(value.timeoutMs)
    || (value.timeoutMs as number) < 1 || (value.timeoutMs as number) > 300_000)) failure('profile_invalid_input');
  if (Object.hasOwn(value, 'apiUrlOverride') && typeof value.apiUrlOverride !== 'string') failure('profile_invalid_input');
  return value as SecureProfileOptions;
}
function assertContext(context: NativeOperationContext): void {
  try {
    if (!context || types.isProxy(context) || !(context.signal instanceof AbortSignal) || !context.budget
      || typeof context.budget.assertActive !== 'function') failure('profile_invalid_input');
    if (context.signal.aborted) throw new NativeProfileTransactionError('profile_cancelled');
    try { context.budget.assertActive(); }
    catch { throw new NativeProfileTransactionError('profile_deadline'); }
  } catch (error) {
    if (error instanceof NativeProfileTransactionError) throw error;
    failure('profile_invalid_input');
  }
}
function lifecycle(options: SecureProfileOptions, defaultTimeout: number): {
  context: NativeOperationContext; close(): void;
} {
  if (options.context !== undefined) {
    assertContext(options.context);
    return { context: options.context, close() {} };
  }
  const controller = new AbortController();
  const deadline = performance.now() + (options.timeoutMs ?? defaultTimeout);
  let expired = false;
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) abort();
  const timer = setTimeout(() => { expired = true; abort(); }, options.timeoutMs ?? defaultTimeout);
  timer.unref();
  const context: NativeOperationContext = Object.freeze({ signal: controller.signal,
    budget: Object.freeze({ assertActive() {
      if (expired || performance.now() >= deadline) throw new NativeProfileTransactionError('profile_deadline');
    } }) });
  return { context, close() { clearTimeout(timer); options.signal?.removeEventListener('abort', abort); controller.abort(); } };
}
function safeFailure(error: unknown, context: NativeOperationContext): NativeProfileTransactionError {
  const known = error instanceof NativeProfileTransactionError ? error : undefined;
  let code = known?.code ?? 'profile_store_unavailable';
  // Context failures are interpreted without serializing abort reasons or
  // opaque budget exceptions. Keep mutation/action uncertainty intact.
  try { context.budget.assertActive(); }
  catch { code = 'profile_deadline'; }
  try { if (context.signal.aborted && code !== 'profile_deadline') code = 'profile_cancelled'; }
  catch { code = 'profile_invalid_input'; }
  return new NativeProfileTransactionError(code, known?.recovery_required, known?.operation_may_have_executed);
}
function environmentSelection(env: Record<string, unknown>): Pick<NativeSelectionOptions, 'environmentKey'> {
  if (!env || typeof env !== 'object' || types.isProxy(env)) failure('profile_invalid_input');
  const selected = Object.getOwnPropertyDescriptor(env, 'BOTA_API_KEY');
  if (!selected) return {};
  if (!Object.hasOwn(selected, 'value')) failure('profile_key_required');
  // Own presence is selection, including an empty/undefined/invalid value.
  // The engine validates it after origin/state checks and never falls back.
  return { environmentKey: selected.value };
}
function originSelection(options: SecureProfileOptions, env: Record<string, unknown>): Pick<NativeSelectionOptions, 'apiOriginOverride'> {
  if (!env || typeof env !== 'object' || types.isProxy(env)) failure('profile_invalid_input');
  const selected = Object.getOwnPropertyDescriptor(env, 'BOTA_API_URL');
  const explicit = Object.hasOwn(options, 'apiUrlOverride');
  if (!selected && !explicit) return {};
  const normalized = (value: unknown): string => {
    try {
      if (typeof value !== 'string') throw new Error();
      return normalizeProfileOrigin(value, true);
    } catch { throw new NativeProfileTransactionError('profile_origin_mismatch'); }
  };
  if (selected && !Object.hasOwn(selected, 'value')) throw new NativeProfileTransactionError('profile_origin_mismatch');
  const environment = selected ? normalized(selected.value) : undefined;
  const override = explicit ? normalized(options.apiUrlOverride) : undefined;
  if (environment !== undefined && override !== undefined && environment !== override) {
    throw new NativeProfileTransactionError('profile_origin_mismatch');
  }
  return { apiOriginOverride: override ?? environment };
}

export function createSecureProfileService(dependencies: SecureProfileServiceDependencies) {
  async function execute<T>(name: string, options: SecureProfileOptions, defaultTimeout: number,
    work: (runtime: SecureProfileRuntime, context: NativeOperationContext, markMutation: () => void,
      markAction: () => void) => Promise<T>): Promise<T> {
    nameChecked(name);
    const checked = optionsChecked(options);
    const scope = lifecycle(checked, defaultTimeout);
    let runtime: SecureProfileRuntime | undefined, result: T | undefined;
    let failed: NativeProfileTransactionError | undefined;
    let mutationEntered = false, actionEntered = false;
    try {
      assertContext(scope.context);
      runtime = await dependencies.createRuntime(scope.context);
      assertContext(scope.context);
      result = await work(runtime, scope.context, () => { mutationEntered = true; }, () => { actionEntered = true; });
      assertContext(scope.context);
    } catch (error) { failed = safeFailure(error, scope.context); }
    finally {
      try { await runtime?.close(); }
      catch {
        failed = new NativeProfileTransactionError('profile_lease_failed',
          failed?.recovery_required || mutationEntered, failed?.operation_may_have_executed || actionEntered);
      }
      // Cleanup is joined even after cancellation, and may itself outlast the
      // caller's lifetime. A late abort/deadline cannot publish success. Keep
      // an earlier failure or uncertain close authoritative rather than masking it.
      if (!failed) {
        try { assertContext(scope.context); }
        catch (error) {
          const late = safeFailure(error, scope.context);
          failed = new NativeProfileTransactionError(late.code,
            late.recovery_required || mutationEntered, late.operation_may_have_executed || actionEntered);
        }
      }
      scope.close();
    }
    if (failed) {
      if (actionEntered && !failed.operation_may_have_executed) {
        throw new NativeProfileTransactionError(failed.code, failed.recovery_required, true);
      }
      throw failed;
    }
    return result as T;
  }

  return Object.freeze({
    async run<T>(name: string, options: SecureProfileOptions,
      action: (credential: NativeResolvedCredential, context: NativeOperationContext) => Promise<T>): Promise<T> {
      return execute(name, options, 120_000, async (runtime, context, _mutation, markAction) => {
        const checked = optionsChecked(options);
        const env = checked.env ?? process.env;
        const selection: NativeSelectionOptions = { ...originSelection(checked, env), ...environmentSelection(env),
          ...(Object.hasOwn(checked, 'expectedBinding') ? { expectedBinding: checked.expectedBinding } : {}) };
        return runtime.engine.withCredential(name, selection, context, async (credential, sameContext) => {
          markAction();
          return action(credential, sameContext);
        });
      });
    },
    async enroll(input: SecureProfileEnrollment, options: SecureProfileOptions = {}): Promise<NativeProfileRecord> {
      const data = fields(input, ['name', 'apiOrigin', 'allowHttpLoopback', 'key', 'readKey']);
      nameChecked(data.name);
      if (typeof data.apiOrigin !== 'string' || data.allowHttpLoopback !== undefined && typeof data.allowHttpLoopback !== 'boolean'
        || Object.hasOwn(data, 'key') === Object.hasOwn(data, 'readKey')
        || Object.hasOwn(data, 'readKey') && typeof data.readKey !== 'function') failure('profile_invalid_input');
      let origin: string;
      try { origin = normalizeProfileOrigin(data.apiOrigin, data.allowHttpLoopback as boolean | undefined); }
      catch { return failure('profile_invalid_input'); }
      const name = data.name;
      const checked = optionsChecked(options);
      const assertOriginSelections = () => {
        const selected = originSelection(checked, checked.env ?? process.env);
        if (Object.hasOwn(selected, 'apiOriginOverride') && selected.apiOriginOverride !== origin) {
          throw new NativeProfileTransactionError('profile_origin_mismatch');
        }
      };
      // Enrollment has an explicit origin of its own. Every other supplied
      // origin must agree before even bootstrapping storage or reading a key.
      assertOriginSelections();
      return execute(name, checked, 30_000, async (runtime, context, markMutation) => {
        // Qualify platform/root and reject an existing reservation before secret
        // input. enroll repeats this check in its authoritative mutation lease.
        if (await runtime.engine.inspect(name, context) !== null) throw new NativeProfileTransactionError('profile_exists');
        assertContext(context);
        let key: unknown = data.key;
        if (Object.hasOwn(data, 'readKey')) {
          try { key = await (data.readKey as (context: NativeOperationContext) => Promise<string>)(context); }
          catch (error) {
            if (error && typeof error === 'object' && !types.isProxy(error)
              && error instanceof NativeProfileTransactionError
              && (error.code === 'profile_cancelled' || error.code === 'profile_deadline')) {
              throw new NativeProfileTransactionError(error.code, error.recovery_required, error.operation_may_have_executed);
            }
            return failure('profile_key_required');
          }
        }
        assertContext(context);
        if (typeof key !== 'string' || !/^[\x21-\x7e]{1,2560}$/.test(key)) failure('profile_key_required');
        // Input may await an interactive prompt. Refuse changed selections
        // before this credential can reach identity or native mutation.
        assertOriginSelections();
        markMutation();
        return runtime.engine.enroll({ name, apiOrigin: origin, allowHttpLoopback: data.allowHttpLoopback as boolean | undefined, key }, context);
      });
    },
    async inspect(name: string, options: SecureProfileOptions = {}): Promise<NativeProfileSnapshot | null> {
      return execute(name, options, 30_000, (runtime, context) => runtime.engine.inspect(name, context));
    },
    async remove(name: string, options: SecureProfileOptions = {}): Promise<NativeProfileRecord> {
      return execute(name, options, 30_000, (runtime, context, markMutation) => {
        markMutation(); return runtime.engine.remove(name, context);
      });
    },
    async recover(name: string, options: SecureProfileOptions = {}): Promise<NativeProfileRecord> {
      return execute(name, options, 30_000, (runtime, context, markMutation) => {
        markMutation(); return runtime.engine.recover(name, context);
      });
    },
  });
}

// Loading command help or an MCP schema never bootstraps native storage.
const production = createSecureProfileService({ async createRuntime(context) {
  const { createWindowsProfileRuntime } = await import('./windows-profile-runtime.js');
  return createWindowsProfileRuntime(context);
} });
export const runWithSecureProfile = production.run;
export const enrollSecureProfile = production.enroll;
export const inspectSecureProfile = production.inspect;
export const removeSecureProfile = production.remove;
export const recoverSecureProfile = production.recover;
