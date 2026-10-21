/** Fixed Windows snapshot file admission. No SQLite, credentials or CLI wiring. */
import { opendirSync } from 'node:fs';
import path from 'node:path';
import type { NativeOperationContext } from './native-profile-transaction.js';
import { createWindowsSnapshotFileApi, WindowsNativeError,
  type WindowsOwnedHandle, type WindowsSnapshotFileApi } from './windows-native-api.js';
import { WindowsNativeLease, WindowsNativeLeaseContextError, WINDOWS_NATIVE_STORE_ID } from './windows-native-lease.js';
import {
  WINDOWS_SNAPSHOT_APPLICATION_ID, WINDOWS_SNAPSHOT_DATABASE, WINDOWS_SNAPSHOT_JOURNAL,
  WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES, WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES,
  WINDOWS_SNAPSHOT_MAX_PROFILES, WINDOWS_SNAPSHOT_PAGE_SIZE, WINDOWS_SNAPSHOT_VERSION,
  type WindowsSnapshotBinding, type WindowsMetadataSnapshotBinding, type WindowsSnapshotFiles, type WindowsSnapshotGuard,
} from './windows-snapshot-contract.js';

type LeaseAuthority = Pick<WindowsNativeLease, 'assertCurrentAccess' | 'assertCurrentMetadataAccess'>;
type SnapshotAccess = WindowsSnapshotBinding | WindowsMetadataSnapshotBinding;
type Inventory = (directory: string) => readonly string[];
const STORE_LEASE = 'store-windows-credential-manager.lease';
const SQLITE_MAGIC = Buffer.from('SQLite format 3\0', 'ascii');
const JOURNAL_MAGIC = Buffer.from('d9d505f920a163d7', 'hex');

function directoryInventory(directory: string): readonly string[] {
  const opened = opendirSync(directory), names: string[] = [];
  try {
    for (;;) {
      const item = opened.readSync();
      if (!item) return names;
      names.push(item.name);
      if (names.length > WINDOWS_SNAPSHOT_MAX_PROFILES + 3) refuse();
    }
  } finally {
    try { opened.closeSync(); }
    catch { throw new WindowsNativeError('windows_native_close_unknown'); }
  }
}

function refuse(): never { throw new WindowsNativeError('windows_native_untrusted'); }
function safeFailure(error: unknown): never {
  if (error instanceof WindowsNativeError || error instanceof WindowsNativeLeaseContextError) throw error;
  throw new WindowsNativeError('windows_native_unavailable');
}
function selectedLease(binding: WindowsSnapshotBinding): string {
  return `profile-${Buffer.from(binding.name, 'ascii').toString('hex')}.lease`;
}
function knownLease(filename: string): boolean {
  if (filename === STORE_LEASE) return true;
  const match = /^profile-((?:[0-9a-f]{2}){1,64})\.lease$/.exec(filename);
  if (!match) return false;
  const name = Buffer.from(match[1]!, 'hex').toString('ascii');
  return /^[a-z0-9-]{1,64}$/.test(name) && Buffer.from(name, 'ascii').toString('hex') === match[1];
}
function headerChecked(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== 100) refuse();
  const bytes = Buffer.from(value);
  if (!bytes.subarray(0, 16).equals(SQLITE_MAGIC)
    || bytes.readUInt16BE(16) !== WINDOWS_SNAPSHOT_PAGE_SIZE || bytes[18] !== 1 || bytes[19] !== 1
    || bytes.readUInt32BE(60) !== WINDOWS_SNAPSHOT_VERSION
    || bytes.readUInt32BE(68) !== WINDOWS_SNAPSHOT_APPLICATION_ID) refuse();
  return new Uint8Array(bytes);
}

/** The injected constructor is a trusted fixture boundary. Production callers
 * use createWindowsNativeSnapshotGuard with the genuine lease and fixed native
 * API. Inventory reads only the live capability's pinned private root. */
export class WindowsNativeSnapshotGuard implements WindowsSnapshotGuard {
  #poisoned = false;
  #opened = false;
  constructor(private readonly lease: LeaseAuthority, private readonly api: WindowsSnapshotFileApi,
    private readonly inventory: Inventory = directoryInventory) {}

  assertCurrentAccess(context: NativeOperationContext): WindowsSnapshotBinding {
    if (this.#poisoned) throw new WindowsNativeError('windows_native_poisoned');
    this.api.assertHealthy();
    const binding = this.lease.assertCurrentAccess(context);
    if (Object.hasOwn(binding, 'metadataOnly')) refuse();
    return binding;
  }

  assertCurrentMetadataAccess(context: NativeOperationContext): WindowsMetadataSnapshotBinding {
    if (this.#poisoned) throw new WindowsNativeError('windows_native_poisoned');
    this.api.assertHealthy();
    const binding = this.lease.assertCurrentMetadataAccess(context);
    if (binding.metadataOnly !== true || Object.hasOwn(binding, 'name')) refuse();
    return binding;
  }

  private binding(binding: SnapshotAccess, context: NativeOperationContext): void {
    const current = 'metadataOnly' in binding ? this.assertCurrentMetadataAccess(context) : this.assertCurrentAccess(context);
    if (current !== binding || binding.storeId !== WINDOWS_NATIVE_STORE_ID) refuse();
  }

  private inventoryChecked(binding: SnapshotAccess, context: NativeOperationContext): void {
    this.binding(binding, context);
    let names: readonly string[];
    try { names = this.inventory(binding.rootDirectory); }
    catch (error) {
      if (error instanceof WindowsNativeError && error.code === 'windows_native_close_unknown') this.#poisoned = true;
      throw error;
    }
    if (!Array.isArray(names) || names.length > WINDOWS_SNAPSHOT_MAX_PROFILES + 3
      || new Set(names).size !== names.length) refuse();
    let profiles = 0;
    for (const filename of names) {
      this.binding(binding, context);
      if (typeof filename !== 'string') refuse();
      if (filename === WINDOWS_SNAPSHOT_DATABASE || filename === WINDOWS_SNAPSHOT_JOURNAL) continue;
      if (!knownLease(filename)) refuse();
      if (filename !== STORE_LEASE && ++profiles > WINDOWS_SNAPSHOT_MAX_PROFILES) refuse();
      // Only handles held by this exact ticket may be skipped. A metadata
      // ticket holds the namespace alone, so every profile lease is admitted.
      if (filename === STORE_LEASE || !('metadataOnly' in binding) && filename === selectedLease(binding)) continue;
      const handle = this.api.openDataFile(path.win32.join(binding.rootDirectory, filename), false);
      if (!handle) refuse();
      try { this.fileChecked(handle, filename, binding, context, 0n); }
      finally { this.closeOwned([handle]); }
    }
    if (!names.includes(STORE_LEASE)
      || !('metadataOnly' in binding) && !names.includes(selectedLease(binding))) refuse();
    this.binding(binding, context);
  }

  private fileChecked(handle: WindowsOwnedHandle, filename: string, binding: SnapshotAccess,
    context: NativeOperationContext, maximum: bigint): { readonly identity: string; readonly size: bigint } {
    this.binding(binding, context);
    const facts = this.api.facts(handle), expected = `\\\\?\\${path.win32.join(binding.rootDirectory, filename)}`;
    if ((facts.attributes & 0x410) !== 0 || facts.links !== 1 || facts.size < 0n || facts.size > maximum
      || typeof facts.identity !== 'string' || facts.identity.length === 0 || facts.identity.length > 128
      || facts.finalPath.toLowerCase() !== expected.toLowerCase()) refuse();
    this.api.trust(handle, 'private-file');
    this.binding(binding, context);
    return Object.freeze({ identity: facts.identity, size: facts.size });
  }

  private closeOwned(handles: readonly WindowsOwnedHandle[]): void {
    let failed = false;
    for (const handle of [...handles].reverse()) {
      try { this.api.close(handle); } catch { this.#poisoned = true; failed = true; }
    }
    if (failed) throw new WindowsNativeError('windows_native_close_unknown');
  }

  private journalChecked(handle: WindowsOwnedHandle, binding: SnapshotAccess,
    context: NativeOperationContext): { readonly identity: string; readonly size: bigint } {
    const before = this.fileChecked(handle, WINDOWS_SNAPSHOT_JOURNAL, binding, context,
      BigInt(WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES));
    const length = Number(before.size < 16n ? before.size : 16n);
    const tail = length === 0 ? new Uint8Array(0) : this.api.readTail(handle, length); this.binding(binding, context);
    const after = this.fileChecked(handle, WINDOWS_SNAPSHOT_JOURNAL, binding, context,
      BigInt(WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES));
    if (!(tail instanceof Uint8Array) || tail.byteLength !== length
      || before.identity !== after.identity || before.size !== after.size) refuse();
    // Both pinned SQLite readers require this EOF magic before interpreting a
    // super-journal filename. Refuse every matching footer, including corrupt
    // lengths/checksums and stale PERSIST data. Never decode or follow a path.
    // A journal shorter than 16 bytes cannot carry a recognized footer.
    if (before.size >= 16n && Buffer.from(tail).subarray(length - 8).equals(JOURNAL_MAGIC)) refuse();
    return after;
  }

  open(binding: WindowsSnapshotBinding, context: NativeOperationContext): WindowsSnapshotFiles {
    if (this.assertCurrentAccess(context) !== binding) refuse();
    const files = this.openFiles(binding, context);
    if (!files) refuse();
    return files;
  }

  openMetadata(binding: WindowsMetadataSnapshotBinding, context: NativeOperationContext): WindowsSnapshotFiles | null {
    if (this.assertCurrentMetadataAccess(context) !== binding) refuse();
    return this.openFiles(binding, context);
  }

  private openFiles(binding: SnapshotAccess, context: NativeOperationContext): WindowsSnapshotFiles | null {
    this.binding(binding, context);
    if (this.#opened) throw new WindowsNativeError('windows_native_busy');
    this.#opened = true;
    const handles: WindowsOwnedHandle[] = [];
    try {
      this.inventoryChecked(binding, context);
      const filename = (name: string) => path.win32.join(binding.rootDirectory, name);
      let database = this.api.openDataFile(filename(WINDOWS_SNAPSHOT_DATABASE), false);
      if (database) handles.push(database);
      this.binding(binding, context);
      let journal = this.api.openDataFile(filename(WINDOWS_SNAPSHOT_JOURNAL), false);
      if (journal) handles.push(journal);
      this.binding(binding, context);
      if ((database === null) !== (journal === null)) refuse();
      const fresh = database === null;
      if (fresh && 'metadataOnly' in binding) {
        this.inventoryChecked(binding, context); this.#opened = false;
        return null;
      }
      if (fresh) {
        database = this.api.openDataFile(filename(WINDOWS_SNAPSHOT_DATABASE), true);
        if (!database) refuse();
        handles.push(database); this.binding(binding, context);
        journal = this.api.openDataFile(filename(WINDOWS_SNAPSHOT_JOURNAL), true);
        if (!journal) refuse();
        handles.push(journal); this.binding(binding, context);
      }
      if (!database || !journal) refuse();
      const databaseHandle = database, journalHandle = journal;
      const databaseFacts = this.fileChecked(databaseHandle, WINDOWS_SNAPSHOT_DATABASE, binding, context,
        BigInt(WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES));
      const journalFacts = this.fileChecked(journalHandle, WINDOWS_SNAPSHOT_JOURNAL, binding, context,
        BigInt(WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES));
      if (databaseFacts.identity === journalFacts.identity
        || fresh && (databaseFacts.size !== 0n || journalFacts.size !== 0n)) refuse();
      let header: Uint8Array = new Uint8Array(0);
      if (!fresh) {
        if (databaseFacts.size < BigInt(WINDOWS_SNAPSHOT_PAGE_SIZE)
          || databaseFacts.size % BigInt(WINDOWS_SNAPSHOT_PAGE_SIZE) !== 0n) refuse();
        header = headerChecked(this.api.readPrefix(databaseHandle, 100));
      } else {
        this.api.flushDataFile(databaseHandle); this.binding(binding, context);
        this.api.flushDataFile(journalHandle); this.binding(binding, context);
      }
      this.inventoryChecked(binding, context);
      let closed = false;
      const validate = (): void => {
        if (closed) throw new WindowsNativeError('windows_native_unavailable');
        try {
          this.binding(binding, context); this.inventoryChecked(binding, context);
          const currentDatabase = this.fileChecked(databaseHandle, WINDOWS_SNAPSHOT_DATABASE, binding, context,
            BigInt(WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES));
          const currentJournal = this.journalChecked(journalHandle, binding, context);
          if (currentDatabase.identity !== databaseFacts.identity || currentJournal.identity !== journalFacts.identity
            || currentDatabase.identity === currentJournal.identity) refuse();
          // Only this invocation's fresh pair may still be empty before SQLite
          // bootstrap. Once bytes exist, the full fixed header is mandatory.
          if (fresh && currentDatabase.size === 0n && currentJournal.size === 0n) return;
          if (currentDatabase.size < BigInt(WINDOWS_SNAPSHOT_PAGE_SIZE)
            || currentDatabase.size % BigInt(WINDOWS_SNAPSHOT_PAGE_SIZE) !== 0n) refuse();
          headerChecked(this.api.readPrefix(databaseHandle, 100)); this.binding(binding, context);
        } catch (error) { safeFailure(error); }
      };
      const close = (): void => {
        if (closed) return;
        closed = true; this.#opened = false;
        // Cleanup is unconditional even when the capability was revoked/aborted.
        this.closeOwned(handles);
      };
      validate();
      const files: WindowsSnapshotFiles = {
        fresh, currentSid: this.api.currentSid,
        get databaseHeader() { return new Uint8Array(header); }, validate, close,
      };
      return Object.freeze(files);
    } catch (error) {
      this.#opened = false;
      this.closeOwned(handles);
      return safeFailure(error);
    }
  }
}

export async function createWindowsNativeSnapshotGuard(lease: WindowsNativeLease): Promise<WindowsNativeSnapshotGuard> {
  if (!(lease instanceof WindowsNativeLease)) refuse();
  const api = await createWindowsSnapshotFileApi();
  return new WindowsNativeSnapshotGuard(lease, api);
}
