/** Inert T06 Windows lease adapter. No native store, profile/provider or CLI wiring. */
import path from 'node:path';
import type { NativeLeasePort, NativeOperationContext } from './native-profile-transaction.js';
import { createWindowsLeaseApi, nativeLeaseRootPath, WindowsNativeError,
  type WindowsLeaseApi, type WindowsOwnedHandle } from './windows-native-api.js';

export const WINDOWS_NATIVE_STORE_ID = 'windows-credential-manager';
export class WindowsNativeLeaseContextError extends Error {
  declare readonly code: 'windows_native_cancelled' | 'windows_native_deadline';
  constructor(code: 'windows_native_cancelled' | 'windows_native_deadline') {
    super(code === 'windows_native_cancelled' ? 'The native lease operation was cancelled.' : 'The native lease operation deadline expired.');
    this.name = 'WindowsNativeLeaseContextError'; Object.defineProperty(this, 'code', { value: code, enumerable: true });
  }
}
function active(context: NativeOperationContext): void {
  if (!(context.signal instanceof AbortSignal) || !context.budget || typeof context.budget.assertActive !== 'function') throw new WindowsNativeError('windows_native_untrusted');
  if (context.signal.aborted) throw new WindowsNativeLeaseContextError('windows_native_cancelled');
  try { context.budget.assertActive(); } catch { throw new WindowsNativeLeaseContextError('windows_native_deadline'); }
}
function expectedPath(filename: string): string { return `\\\\?\\${filename}`.toLowerCase(); }
function assertFacts(api: WindowsLeaseApi, handle: WindowsOwnedHandle, filename: string,
  kind: 'ancestor' | 'private-directory' | 'private-file'): void {
  const facts = api.facts(handle);
  const directory = kind !== 'private-file';
  if ((facts.attributes & 0x400) !== 0 || ((facts.attributes & 0x10) !== 0) !== directory
    || facts.finalPath.toLowerCase() !== expectedPath(filename)
    || !directory && (facts.size !== 0n || facts.links !== 1)) throw new WindowsNativeError('windows_native_untrusted');
  api.trust(handle, kind);
}

/** The callsite chooses one root at construction; names/metadata can never
 * redirect it. No environment/home lookup, ACL repair, root deletion or lease
 * file deletion is performed. Existing roots must already satisfy admission. */
export async function openWindowsNativeLease(rootDirectory: string, context: NativeOperationContext): Promise<WindowsNativeLease> {
  active(context);
  const root = nativeLeaseRootPath(rootDirectory);
  const api = await createWindowsLeaseApi();
  active(context);
  return WindowsNativeLease.open(api, root, context);
}

/** Windows calls are synchronous and nonpreemptible. The unchanged opaque
 * budget/signal are checked around high-level native operations, not every
 * constituent FFI call; no universal hard-realtime deadline
 * is promised for a stalled OS/storage call. Close always runs despite abort. */
export class WindowsNativeLease implements NativeLeasePort {
  declare readonly rootDirectory: string;
  private active = false;
  private closed = false;
  private poisoned = false;
  private constructor(private readonly api: WindowsLeaseApi, rootDirectory: string,
    private readonly rootHandles: WindowsOwnedHandle[]) {
    Object.defineProperty(this, 'rootDirectory', { value: rootDirectory, enumerable: true });
  }

  /** Injected API is an internal test/trust port; production uses the fixed
   * native binding above. It must not be derived from metadata or user options. */
  static open(api: WindowsLeaseApi, rootDirectory: string, context: NativeOperationContext): WindowsNativeLease {
    const root = nativeLeaseRootPath(rootDirectory), handles: WindowsOwnedHandle[] = [];
    try {
      api.assertHealthy(); active(context);
      const parsed = path.win32.parse(root), segments = root.slice(parsed.root.length).split('\\');
      let current = parsed.root;
      for (let index = 0; index < segments.length; index++) {
        active(context);
        const handle = api.openDirectory(current); handles.push(handle);
        assertFacts(api, handle, current, 'ancestor');
        current = path.win32.join(current, segments[index]!);
      }
      api.localNtfs(current); active(context);
      api.createPrivateDirectory(current); active(context);
      const leaf = api.openDirectory(current); handles.push(leaf);
      assertFacts(api, leaf, current, 'private-directory'); active(context);
      return new WindowsNativeLease(api, root, handles);
    } catch (error) {
      let closeFailure: unknown;
      for (const handle of handles.reverse()) { try { api.close(handle); } catch (failure) { closeFailure = failure; } }
      if (closeFailure) throw new WindowsNativeError('windows_native_close_unknown');
      if (error instanceof WindowsNativeError || error instanceof WindowsNativeLeaseContextError) throw error;
      throw new WindowsNativeError('windows_native_unavailable');
    }
  }

  private healthy(): void {
    if (this.poisoned) throw new WindowsNativeError('windows_native_poisoned');
    if (this.closed) throw new WindowsNativeError('windows_native_unavailable');
    this.api.assertHealthy();
  }

  async runExclusive<T>(storeId: string, name: string, context: NativeOperationContext, work: () => Promise<T>): Promise<T> {
    this.healthy(); active(context);
    if (storeId !== WINDOWS_NATIVE_STORE_ID || typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(name)
      || typeof work !== 'function') throw new WindowsNativeError('windows_native_untrusted');
    if (this.active) throw new WindowsNativeError('windows_native_busy');
    this.active = true;
    const handles: WindowsOwnedHandle[] = [];
    try {
      // Existing non-secret lease files persist. Kernel handle ownership, not
      // file existence/age/PID, establishes exclusion across all sessions.
      for (const basename of ['store-windows-credential-manager.lease', `profile-${Buffer.from(name, 'ascii').toString('hex')}.lease`]) {
        this.healthy(); active(context);
        const filename = path.win32.join(this.rootDirectory, basename);
        const handle = this.api.openLease(filename); handles.push(handle);
        assertFacts(this.api, handle, filename, 'private-file'); active(context);
      }
      const result = await work();
      active(context);
      return result;
    } finally {
      let failed = false;
      for (const handle of handles.reverse()) {
        try { this.api.close(handle); } catch { this.poisoned = true; failed = true; }
      }
      this.active = false;
      if (failed) throw new WindowsNativeError('windows_native_close_unknown');
    }
  }

  /** Release pinned ancestry only after all callback work has joined. A failed
   * close poisons admission; each retired numeric handle is never retried. */
  close(): void {
    if (this.closed) return;
    if (this.active) throw new WindowsNativeError('windows_native_busy');
    this.closed = true;
    let failed = false;
    for (const handle of [...this.rootHandles].reverse()) {
      try { this.api.close(handle); } catch { this.poisoned = true; failed = true; }
    }
    if (failed) throw new WindowsNativeError('windows_native_close_unknown');
  }
}
