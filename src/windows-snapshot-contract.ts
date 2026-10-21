/** Fixed physical cohort; never supplied by a profile or CLI path option. */
import type { NativeOperationContext } from './native-profile-transaction.js';
import type { WindowsNativeLeaseAccess } from './windows-native-lease.js';

export const WINDOWS_SNAPSHOT_DATABASE = 'native-profiles-v1.sqlite3';
export const WINDOWS_SNAPSHOT_JOURNAL = `${WINDOWS_SNAPSHOT_DATABASE}-journal`;
export const WINDOWS_SNAPSHOT_APPLICATION_ID = 0x42544331;
export const WINDOWS_SNAPSHOT_VERSION = 1;
export const WINDOWS_SNAPSHOT_PAGE_SIZE = 4096;
export const WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES = 64 * 1024 * 1024;
export const WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES = 128 * 1024 * 1024;
export const WINDOWS_SNAPSHOT_MAX_PROFILES = 1024;

export type WindowsSnapshotBinding = WindowsNativeLeaseAccess;
export interface WindowsSnapshotFiles {
  readonly fresh: boolean;
  readonly currentSid: string;
  readonly databaseHeader: Uint8Array;
  validate(): void;
  /** One attempt per pinned handle, even after cancellation. */
  close(): void;
}
/** Trusted test boundary. The production implementation admits/pins fixed names. */
export interface WindowsSnapshotGuard {
  assertCurrentAccess(context: NativeOperationContext): WindowsSnapshotBinding;
  open(binding: WindowsSnapshotBinding, context: NativeOperationContext): WindowsSnapshotFiles;
}
