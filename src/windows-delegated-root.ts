/** Canonical location for the new delegated format; never a runtime fallback. */
import path from 'node:path';
import { types } from 'node:util';
import type { NativeOperationContext } from './native-profile-transaction.js';
import { NativeProfileTransactionError } from './native-profile-transaction.js';
import { createWindowsProfileDirectoryApi, nativeLeaseRootPath } from './windows-native-api.js';

const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
function guard(context: NativeOperationContext): () => void {
  const invalid = (): never => { throw new NativeProfileTransactionError('profile_invalid_input'); };
  if (!context || typeof context !== 'object' || types.isProxy(context)) return invalid();
  const fields = Object.getOwnPropertyDescriptors(context);
  const signal = fields.signal?.value as AbortSignal, budget = fields.budget?.value as NativeOperationContext['budget'];
  if (!Object.hasOwn(fields.signal ?? {}, 'value') || !Object.hasOwn(fields.budget ?? {}, 'value')
    || !signal || typeof signal !== 'object' || types.isProxy(signal)
    || !budget || typeof budget !== 'object' || types.isProxy(budget)) return invalid();
  try { aborted.call(signal); } catch { return invalid(); }
  const assertion = Object.getOwnPropertyDescriptor(budget, 'assertActive');
  if (!assertion || !Object.hasOwn(assertion, 'value') || typeof assertion.value !== 'function' || types.isProxy(assertion.value)) return invalid();
  const check = assertion.value as () => void;
  return () => {
    const current = Object.getOwnPropertyDescriptors(context), method = Object.getOwnPropertyDescriptor(budget, 'assertActive');
    if (current.signal?.value !== signal || current.budget?.value !== budget || method?.value !== check) return invalid();
    if (aborted.call(signal)) throw new NativeProfileTransactionError('profile_cancelled');
    try { Reflect.apply(check, budget, []); }
    catch { throw new NativeProfileTransactionError('profile_deadline'); }
    if (aborted.call(signal)) throw new NativeProfileTransactionError('profile_cancelled');
    const after = Object.getOwnPropertyDescriptors(context);
    if (after.signal?.value !== signal || after.budget?.value !== budget
      || Object.getOwnPropertyDescriptor(budget, 'assertActive')?.value !== check) return invalid();
  };
}
/** Lookup only: explicit process token and FOLDERID_Profile. Does not inspect,
 * migrate, repair or adopt any existing API-key root or delegated state. The
 * native lease separately checks and pins every ancestor and the private leaf. */
export async function getWindowsDelegatedRoot(context: NativeOperationContext): Promise<string> {
  const active = guard(context); active();
  const api = await createWindowsProfileDirectoryApi(); active();
  const profile = nativeLeaseRootPath(api.profileDirectory()); active();
  return nativeLeaseRootPath(path.win32.join(profile, 'BotaDeveloperToolchainDelegated'));
}
