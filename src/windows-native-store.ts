/** Inert Windows native-store adapter. No enrollment, provider or CLI wiring. */
import { types } from 'node:util';
import type { NativeOperationContext, NativeReference, NativeStorePort } from './native-profile-transaction.js';
import { createWindowsCredentialApi, WindowsNativeError, windowsCredentialKey,
  windowsCredentialReference, type WindowsCredentialApi } from './windows-native-api.js';
import { WindowsNativeLease, WindowsNativeLeaseContextError, WINDOWS_NATIVE_STORE_ID } from './windows-native-lease.js';

function active(context: NativeOperationContext): void {
  if (!(context.signal instanceof AbortSignal) || !context.budget || typeof context.budget.assertActive !== 'function') throw new WindowsNativeError('windows_native_untrusted');
  if (context.signal.aborted) throw new WindowsNativeLeaseContextError('windows_native_cancelled');
  try { context.budget.assertActive(); } catch { throw new WindowsNativeLeaseContextError('windows_native_deadline'); }
}
function safeFailure(error: unknown): never {
  if (error instanceof WindowsNativeError || error instanceof WindowsNativeLeaseContextError) throw error;
  throw new WindowsNativeError('windows_native_unavailable');
}
type LeaseAccess = Pick<WindowsNativeLease, 'assertCurrentAccess'>;

/** Native bootstrap alone performs no credential reads/writes. The selected
 * genuine lease must be open, and all store work runs in its active callback. */
export async function createWindowsNativeStore(lease: WindowsNativeLease): Promise<WindowsNativeStore> {
  if (!(lease instanceof WindowsNativeLease)) throw new WindowsNativeError('windows_native_untrusted');
  return WindowsNativeStore.open(await createWindowsCredentialApi(), lease);
}

export class WindowsNativeStore implements NativeStorePort {
  declare readonly id: typeof WINDOWS_NATIVE_STORE_ID;
  private constructor(private readonly api: WindowsCredentialApi, private readonly lease: LeaseAccess) {
    Object.defineProperty(this, 'id', { value: WINDOWS_NATIVE_STORE_ID, enumerable: true });
  }
  /** Internal trusted injection for portable fault tests. It is not a runtime
   * plugin, caller-selected namespace or authority derived from metadata. */
  static open(api: WindowsCredentialApi, lease: LeaseAccess): WindowsNativeStore { return new WindowsNativeStore(api, lease); }

  private admitted(context: NativeOperationContext): void {
    try {
      active(context);
      const access = this.lease.assertCurrentAccess(context);
      if (Object.hasOwn(access, 'metadataOnly') || access.storeId !== WINDOWS_NATIVE_STORE_ID || typeof access.name !== 'string'
        || !/^[a-z0-9-]{1,64}$/.test(access.name)) throw new WindowsNativeError('windows_native_untrusted');
      this.api.assertHealthy();
    } catch (error) { safeFailure(error); }
  }
  async read(value: NativeReference, context: NativeOperationContext): Promise<
    { readonly status: 'absent' } | { readonly status: 'present'; readonly key: unknown }> {
    const reference = windowsCredentialReference(value); this.admitted(context);
    try {
      const result = this.api.readCredential(reference); this.admitted(context);
      if (!result || typeof result !== 'object' || types.isProxy(result)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(result))) throw new WindowsNativeError('windows_native_untrusted');
      const fields = Object.getOwnPropertyDescriptors(result);
      if (Reflect.ownKeys(result).length !== Object.keys(fields).length
        || Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value'))) throw new WindowsNativeError('windows_native_untrusted');
      if (fields.status?.value === 'absent' && Object.keys(fields).length === 1) return Object.freeze({ status: 'absent' });
      if (fields.status?.value === 'present' && Object.keys(fields).length === 2 && Object.hasOwn(fields, 'key')) {
        return Object.freeze({ status: 'present', key: windowsCredentialKey(fields.key!.value) });
      }
      throw new WindowsNativeError('windows_native_untrusted');
    } catch (error) { return safeFailure(error); }
  }
  async write(value: NativeReference, key: string, context: NativeOperationContext): Promise<'stored' | 'not_stored' | 'unknown'> {
    const reference = windowsCredentialReference(value); windowsCredentialKey(key); this.admitted(context);
    try {
      const result = this.api.writeCredential(reference, key); this.admitted(context);
      return result === 'stored' || result === 'not_stored' ? result : 'unknown';
    } catch { return 'unknown'; }
  }
  async delete(value: NativeReference, context: NativeOperationContext): Promise<'deleted' | 'absent' | 'not_deleted' | 'unknown'> {
    const reference = windowsCredentialReference(value); this.admitted(context);
    try {
      const result = this.api.deleteCredential(reference); this.admitted(context);
      return result === 'deleted' || result === 'absent' || result === 'not_deleted' ? result : 'unknown';
    } catch { return 'unknown'; }
  }
}
