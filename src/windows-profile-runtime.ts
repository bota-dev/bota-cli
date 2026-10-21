/** Canonical Windows native enrollment assembly; no command or provider cycle. */
import path from 'node:path';
import { NativeProfileTransactions, NativeProfileTransactionError,
  type NativeOperationContext, type NativeProfilePorts, type NativeSnapshotPort,
  type NativeStorePort } from './native-profile-transaction.js';
import { createWindowsKnownFolderApi, nativeLeaseRootPath, WindowsNativeError } from './windows-native-api.js';
import { openWindowsNativeLease, WindowsNativeLease } from './windows-native-lease.js';
import { createWindowsNativeStore } from './windows-native-store.js';
import { createWindowsNativeSnapshots, qualifyWindowsSnapshotRuntime } from './windows-native-snapshots.js';
import { readSecureProfileIdentity } from './secure-profile-identity.js';

const ROOT_LEAF = 'BotaDeveloperToolchain';
export interface WindowsProfileRuntime {
  readonly engine: NativeProfileTransactions;
  close(): void;
}
/** Internal trusted injection for lifecycle fixtures. Production accepts no
 * root, known-folder override, store selection or identity option. */
export interface WindowsProfileRuntimePorts {
  qualify(): void | Promise<void>;
  localAppData(): Promise<string>;
  openLease(root: string, context: NativeOperationContext): Promise<WindowsNativeLease>;
  createStore(lease: WindowsNativeLease): Promise<NativeStorePort>;
  createSnapshots(lease: WindowsNativeLease): Promise<NativeSnapshotPort>;
  readIdentity: NativeProfilePorts['readIdentity'];
}
function active(context: NativeOperationContext): void {
  if (!(context.signal instanceof AbortSignal) || !context.budget || typeof context.budget.assertActive !== 'function') {
    throw new NativeProfileTransactionError('profile_invalid_input');
  }
  if (context.signal.aborted) throw new NativeProfileTransactionError('profile_cancelled');
  try { context.budget.assertActive(); }
  catch { throw new NativeProfileTransactionError('profile_deadline'); }
}
function fixed(error: unknown): never {
  if (error instanceof NativeProfileTransactionError || error instanceof WindowsNativeError) throw error;
  throw new WindowsNativeError('windows_native_unavailable');
}
/** A separate name makes test injection explicit; the production exports below
 * always use the fixed OS resolver and genuine native adapter factories. */
export function bindWindowsProfileRuntime(ports: WindowsProfileRuntimePorts): {
  root(context: NativeOperationContext): Promise<string>;
  create(context: NativeOperationContext): Promise<WindowsProfileRuntime>;
} {
  const root = async (context: NativeOperationContext): Promise<string> => {
    active(context);
    try {
      const local = nativeLeaseRootPath(await ports.localAppData()); active(context);
      return nativeLeaseRootPath(path.win32.join(local, ROOT_LEAF));
    } catch (error) { return fixed(error); }
  };
  const create = async (context: NativeOperationContext): Promise<WindowsProfileRuntime> => {
    let lease: WindowsNativeLease | undefined;
    try {
      active(context); await ports.qualify(); active(context);
      const directory = await root(context); active(context);
      lease = await ports.openLease(directory, context); active(context);
      const store = await ports.createStore(lease); active(context);
      const snapshots = await ports.createSnapshots(lease); active(context);
      const owned = lease;
      const engine = new NativeProfileTransactions({ lease: owned, store, snapshots,
        readIdentity: (origin, key, operation) => ports.readIdentity(origin, key, operation) });
      let closed = false;
      return Object.freeze({ engine, close(): void {
        if (closed) return;
        closed = true;
        try { owned.close(); }
        catch (error) {
          // NativeLease refuses an active callback before attempting closure.
          if (error instanceof WindowsNativeError && error.code === 'windows_native_busy') closed = false;
          return fixed(error);
        }
      } });
    } catch (error) {
      if (lease) {
        try { lease.close(); }
        catch { throw new WindowsNativeError('windows_native_close_unknown'); }
      }
      return fixed(error);
    }
  };
  return Object.freeze({ root, create });
}
const production = bindWindowsProfileRuntime({
  qualify: qualifyWindowsSnapshotRuntime,
  async localAppData() { return (await createWindowsKnownFolderApi()).localAppData(); },
  openLease: openWindowsNativeLease, createStore: createWindowsNativeStore,
  createSnapshots: createWindowsNativeSnapshots, readIdentity: readSecureProfileIdentity,
});
/** Lookup only; does not create or inspect the canonical Bota root. */
export const getWindowsProfileRoot = production.root;
/** One fixed existing LocalAppData ancestor and one private Bota leaf. The
 * genuine lease creates only that leaf and refuses differing existing ACLs. */
export const createWindowsProfileRuntime = production.create;
