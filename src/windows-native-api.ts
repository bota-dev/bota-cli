/** Narrow Windows x64 in-process bindings. No CLI/provider wiring. */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { types } from 'node:util';
import type { NativeReference } from './native-profile-transaction.js';
import { delegatedNativeSecretReference, delegatedNativeSecret, delegatedNativeCredentialNames,
  type DelegatedNativeSecretReference, type DelegatedNativeSecretApi } from './delegated-native-contract.js';

export type WindowsNativeErrorCode = 'windows_native_unsupported' | 'windows_native_environment'
  | 'windows_native_untrusted' | 'windows_native_unavailable' | 'windows_native_busy'
  | 'windows_native_close_unknown' | 'windows_native_poisoned';
const messages: Record<WindowsNativeErrorCode, string> = {
  windows_native_unsupported: 'This native lease supports Windows x64 only.',
  windows_native_environment: 'The native runtime environment is unsupported.',
  windows_native_untrusted: 'The native lease filesystem is not trusted.',
  windows_native_unavailable: 'The native lease filesystem is unavailable.',
  windows_native_busy: 'The native lease is already owned.',
  windows_native_close_unknown: 'Native lease closure could not be confirmed; restart the owning process.',
  windows_native_poisoned: 'The native lease session cannot admit more operations; restart the owning process.',
};
export class WindowsNativeError extends Error {
  declare readonly code: WindowsNativeErrorCode;
  constructor(code: WindowsNativeErrorCode) {
    super(messages[code]); this.name = 'WindowsNativeError';
    Object.defineProperty(this, 'code', { value: code, enumerable: true });
  }
}
function fail(code: WindowsNativeErrorCode): never { throw new WindowsNativeError(code); }

/** Koffi 3.3.3 call.cc reads these flags, including raw native call logging.
 * Node module-resolution/loader overrides and non-Node packaging are outside
 * this selected cohort. Never print their values. Check before require(). */
export function assertWindowsNativeEnvironment(): void {
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('windows_native_unsupported');
  const forbidden = /^(?:DEBUG_CALLS|DEBUG_ASYNC|RANDOMIZE_MEMORY|DUMP_CALLS|LOG_TIMES|LOG_DEBUG|OVERRIDE_CORES|NODE_OPTIONS|NODE_PATH|KOFFI(?:_|$))/i;
  if (Object.keys(process.env).some(name => forbidden.test(name))
    || Object.hasOwn(process, 'resourcesPath') || Object.hasOwn(process.versions, 'electron')) fail('windows_native_environment');
}

export interface WindowsOwnedHandle { value: bigint | null }
export interface WindowsFileFacts {
  readonly attributes: number; readonly size: bigint; readonly links: number;
  readonly identity: string; readonly finalPath: string;
}
export interface WindowsLeaseApi {
  readonly currentSid: string;
  assertHealthy(): void;
  openDirectory(filename: string): WindowsOwnedHandle;
  createPrivateDirectory(filename: string): void;
  openLease(filename: string): WindowsOwnedHandle;
  facts(handle: WindowsOwnedHandle): WindowsFileFacts;
  trust(handle: WindowsOwnedHandle, kind: 'ancestor' | 'private-directory' | 'private-file' | 'system-file'): void;
  localNtfs(filename: string): void;
  close(handle: WindowsOwnedHandle): void;
}
export interface WindowsSnapshotFileApi extends WindowsLeaseApi {
  /** Existing open returns null only for exact ERROR_FILE_NOT_FOUND. */
  openDataFile(filename: string, create: boolean): WindowsOwnedHandle | null;
  readPrefix(handle: WindowsOwnedHandle, limit: number): Uint8Array;
  readTail(handle: WindowsOwnedHandle, limit: number): Uint8Array;
  flushDataFile(handle: WindowsOwnedHandle): void;
}
export interface WindowsKnownFolderApi {
  /** Current user's existing OS-selected folder; no environment or creation. */
  localAppData(): string;
}
/** Trusted fixed-signature test port, never a user-selected folder or DLL. */
export interface WindowsKnownFolderBindings {
  assertHealthy(): void;
  poison(): void;
  openCurrentToken(): WindowsOwnedHandle;
  closeToken(token: WindowsOwnedHandle): void;
  lookup(identifier: Buffer, flags: number, token: bigint, output: Buffer): unknown;
  free(address: bigint): void;
  view(address: bigint, length: number): ArrayBuffer;
}
export interface WindowsProfileDirectoryApi { profileDirectory(): string }
export function bindWindowsKnownFolderApi(bindings: WindowsKnownFolderBindings): WindowsKnownFolderApi {
  return Object.freeze({ localAppData: () => lookupKnownFolder(bindings, '8527b3f1ba6fcf4f9d557b8e7f157091') });
}
/** Closed Profile lookup, separate from the unchanged LocalAppData API-key format. */
export function bindWindowsProfileDirectoryApi(bindings: WindowsKnownFolderBindings): WindowsProfileDirectoryApi {
  return Object.freeze({ profileDirectory: () => lookupKnownFolder(bindings, '8f856c5e220e60479afeea3317b67173') });
}
function lookupKnownFolder(bindings: WindowsKnownFolderBindings, identifier: string): string {
    bindings.assertHealthy();
    const output = Buffer.alloc(8);
    let token: WindowsOwnedHandle | undefined;
    let address = 0n;
    try {
      // An explicit process token makes user-folder expansion independent of
      // inherited USERPROFILE, unlike the shell API's null-token behavior.
      token = bindings.openCurrentToken();
      if (typeof token.value !== 'bigint' || token.value <= 0n || token.value >= 0xffffffffffffffffn) {
        bindings.poison(); fail('windows_native_unavailable');
      }
      // Only the two closed callers above supply a GUID. Its first three
      // integer fields use Windows little-endian layout.
      const result = bindings.lookup(Buffer.from(identifier, 'hex'), 0, token.value, output);
      address = output.readBigUInt64LE();
      if (address > 0xffffffffffffeffen) { address = 0n; bindings.poison(); fail('windows_native_unavailable'); }
      if (typeof result !== 'number' || !Number.isInteger(result) || result < -0x80000000 || result > 0x7fffffff) {
        bindings.poison(); fail('windows_native_unavailable');
      }
      if (result !== 0 || address === 0n) fail('windows_native_unavailable');
      const units: number[] = [];
      for (let index = 0; index <= 2048; index++) {
        const unit = Buffer.from(new Uint8Array(bindings.view(address + BigInt(index * 2), 2)));
        if (unit.length !== 2) { bindings.poison(); fail('windows_native_unavailable'); }
        const value = unit.readUInt16LE();
        if (value === 0) return nativeLeaseRootPath(String.fromCharCode(...units));
        units.push(value);
      }
      fail('windows_native_untrusted');
    } catch (error) {
      if (error instanceof WindowsNativeError) throw error;
      // A throwing FFI call can leave an uncaptured allocation until restart.
      bindings.poison(); fail('windows_native_unavailable');
    } finally {
      let cleanupFailed = false;
      if (address !== 0n) {
        const owned = address; address = 0n;
        // SHGetKnownFolderPath requires this even after a failing HRESULT.
        try { bindings.free(owned); }
        catch { bindings.poison(); cleanupFailed = true; }
      }
      if (token) { try { bindings.closeToken(token); } catch { bindings.poison(); cleanupFailed = true; } }
      if (cleanupFailed) fail('windows_native_close_unknown');
    }
    return fail('windows_native_unavailable');
}

export type WindowsCredentialRead = Readonly<{ status: 'absent' } | { status: 'present'; key: string }>;
export interface WindowsCredentialApi {
  assertHealthy(): void;
  readCredential(reference: NativeReference): WindowsCredentialRead;
  writeCredential(reference: NativeReference, key: string): 'stored' | 'not_stored' | 'unknown';
  deleteCredential(reference: NativeReference): 'deleted' | 'absent' | 'not_deleted' | 'unknown';
}

const CREDENTIAL_NAMESPACE = 'Bota/DeveloperToolchain/api-key/v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** Validate independently of the transaction engine; never invoke input hooks. */
export function windowsCredentialReference(value: unknown): Readonly<NativeReference> {
  if (!value || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('windows_native_untrusted');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== 2 || Object.keys(descriptors).length !== 2
    || !['profile_id', 'credential_ref'].every(name => {
      const descriptor = descriptors[name];
      return descriptor?.enumerable && Object.hasOwn(descriptor, 'value')
        && typeof descriptor.value === 'string' && UUID.test(descriptor.value);
    })) fail('windows_native_untrusted');
  const profile_id = descriptors.profile_id!.value as string, credential_ref = descriptors.credential_ref!.value as string;
  if (profile_id === credential_ref) fail('windows_native_untrusted');
  return Object.freeze({ profile_id, credential_ref });
}
export function windowsCredentialKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[\x21-\x7e]{1,2560}$/.test(value)) fail('windows_native_untrusted');
  return value;
}
function credentialNames(reference: NativeReference): { target: string; username: string } {
  return { target: `${CREDENTIAL_NAMESPACE}/${reference.profile_id}/${reference.credential_ref}`,
    username: `${CREDENTIAL_NAMESPACE}:${reference.profile_id}:${reference.credential_ref}` };
}

/** Internal trusted binding/test port. Production supplies only fixed verified
 * inbox functions below. No arbitrary target/type/persistence reaches them. */
export interface WindowsCredentialBindings {
  assertHealthy(): void;
  poison(): void;
  read(target: string, type: number, flags: number, output: Buffer): unknown;
  write(credential: Buffer, flags: number): unknown;
  delete(target: string, type: number, flags: number): unknown;
  free(address: bigint): void;
  lastError(): unknown;
  view(address: bigint, length: number): ArrayBuffer;
  address(buffer: Buffer): bigint;
}

/** Build the strict API over a trusted injected native port. This export is
 * for fault fixtures; it is not a runtime plugin or configurable store. */
export function bindWindowsCredentialApi(bindings: WindowsCredentialBindings): WindowsCredentialApi {
  return bindClosedWindowsCredentials(bindings, { reference: windowsCredentialReference,
    secret: (_reference, value) => windowsCredentialKey(value), names: credentialNames });
}
/** Closed delegated references only: no credential target or namespace override. */
export function bindWindowsDelegatedCredentialApi(bindings: WindowsCredentialBindings): DelegatedNativeSecretApi {
  const api = bindClosedWindowsCredentials<DelegatedNativeSecretReference>(bindings, {
    reference: delegatedNativeSecretReference, secret: delegatedNativeSecret, names: delegatedNativeCredentialNames });
  return Object.freeze({ assertHealthy: () => api.assertHealthy(),
    readCredential(reference: DelegatedNativeSecretReference) {
      const result = api.readCredential(reference);
      return result.status === 'absent' ? result : Object.freeze({ status: 'present' as const, secret: result.key });
    },
    writeCredential: (reference: DelegatedNativeSecretReference, secret: string) => api.writeCredential(reference, secret),
    deleteCredential: (reference: DelegatedNativeSecretReference) => api.deleteCredential(reference),
  });
}
interface ClosedCredentialApi<R> {
  assertHealthy(): void;
  readCredential(value: R): WindowsCredentialRead;
  writeCredential(value: R, key: string): 'stored' | 'not_stored' | 'unknown';
  deleteCredential(value: R): 'deleted' | 'absent' | 'not_deleted' | 'unknown';
}
function bindClosedWindowsCredentials<R>(bindings: WindowsCredentialBindings, family: {
  reference(value: unknown): R;
  secret(reference: R, value: unknown): string;
  names(reference: R): { readonly target: string; readonly username: string };
}): ClosedCredentialApi<R> {
  const checkedSecret = (reference: R, value: unknown): string => {
    try { return family.secret(reference, value); }
    catch { return fail('windows_native_untrusted'); }
  };
  const unknown = (): never => { bindings.poison(); return fail('windows_native_unavailable'); };
  const bool = (value: unknown): boolean => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff) return unknown();
    return value !== 0;
  };
  const boundedPointer = (value: unknown): bigint => {
    if (typeof value !== 'bigint' || value <= 0n || value > 0xffffffffffffffffn) return unknown();
    return value;
  };
  const copied = (address: bigint, size: number): Buffer => {
    const result = Buffer.from(new Uint8Array(bindings.view(boundedPointer(address), size)));
    if (result.length !== size) return unknown();
    return result;
  };
  const stringEquals = (address: bigint, expected: string, allowNull = false): boolean => {
    if (address === 0n) return allowNull && expected.length === 0;
    // Read one aligned UTF-16 unit at a time, bounded by the known marker.
    // Windows owns the returned allocation; no unbounded string decoder runs.
    for (let index = 0; index <= expected.length; index++) {
      const unit = copied(address + BigInt(index * 2), 2).readUInt16LE();
      if (unit !== (index === expected.length ? 0 : expected.charCodeAt(index))) return false;
    }
    return true;
  };
  const withCredential = <T>(reference: R, use: (address: bigint, names: ReturnType<typeof credentialNames>) => T): T | null => {
    bindings.assertHealthy();
    const names = family.names(reference), output = Buffer.alloc(8);
    let address = 0n;
    try {
      const found = bool(bindings.read(names.target, 1, 0, output));
      // Capture GetLastError immediately on FALSE, before any other native call.
      const status = found ? 0 : bindings.lastError();
      if (!found) {
        if (output.readBigUInt64LE() !== 0n) return unknown();
        if (status === 1168) return null;
        return fail('windows_native_unavailable');
      }
      address = boundedPointer(output.readBigUInt64LE());
      return use(address, names);
    } catch (error) {
      if (error instanceof WindowsNativeError) throw error;
      return unknown();
    } finally {
      if (address !== 0n) {
        const owned = address; address = 0n; // Retire before the one free attempt.
        try { bindings.free(owned); } catch { unknown(); }
      }
    }
  };
  const decoded = (address: bigint, names: ReturnType<typeof credentialNames>): string => {
    const header = copied(address, 80); // CREDENTIALW, Windows x64 ABI only.
    let secret: Buffer | undefined;
    try {
      const length = header.readUInt32LE(32), blob = header.readBigUInt64LE(40);
      if (header.readUInt32LE(0) !== 0 || header.readUInt32LE(4) !== 1
        || header.readUInt32LE(48) !== 2 || header.readUInt32LE(52) !== 0
        || header.readBigUInt64LE(56) !== 0n || header.readBigUInt64LE(64) !== 0n
        || length < 1 || length > 2560 || blob === 0n
        || !stringEquals(header.readBigUInt64LE(8), names.target)
        || !stringEquals(header.readBigUInt64LE(16), '', true)
        || !stringEquals(header.readBigUInt64LE(72), names.username)) fail('windows_native_untrusted');
      secret = copied(blob, length);
      if (secret.some(byte => byte < 0x21 || byte > 0x7e)) fail('windows_native_untrusted');
      return secret.toString('ascii');
    } finally { secret?.fill(0); header.fill(0); }
  };
  return Object.freeze({
    assertHealthy: () => bindings.assertHealthy(),
    readCredential(value: R): WindowsCredentialRead {
      const reference = family.reference(value);
      const key = withCredential(reference, (address, names) => checkedSecret(reference, decoded(address, names)));
      return key === null ? Object.freeze({ status: 'absent' }) : Object.freeze({ status: 'present', key });
    },
    writeCredential(value: R, key: string): 'stored' | 'not_stored' | 'unknown' {
      const reference = family.reference(value); checkedSecret(reference, key);
      // CredWriteW upserts. Never knowingly overwrite any prior entry, even
      // one whose fields/blob are malformed. The outer namespace lease covers
      // cooperating writers; arbitrary same-user/admin writes remain trusted.
      if (withCredential(reference, () => true) !== null) return 'not_stored';
      const names = family.names(reference), target = Buffer.from(`${names.target}\0`, 'utf16le');
      const username = Buffer.from(`${names.username}\0`, 'utf16le'), secret = Buffer.from(key, 'ascii');
      const header = Buffer.alloc(80);
      try {
        bindings.assertHealthy(); header.writeUInt32LE(1, 4);
        header.writeBigUInt64LE(boundedPointer(bindings.address(target)), 8);
        header.writeUInt32LE(secret.length, 32);
        header.writeBigUInt64LE(boundedPointer(bindings.address(secret)), 40);
        header.writeUInt32LE(2, 48);
        header.writeBigUInt64LE(boundedPointer(bindings.address(username)), 72);
        const stored = bool(bindings.write(header, 0));
        if (!stored) bindings.lastError();
        // FALSE is never claimed to prove rollback of this store mutation.
        return stored ? 'stored' : 'unknown';
      } catch { bindings.poison(); return 'unknown'; }
      finally { secret.fill(0); header.fill(0); target.fill(0); username.fill(0); }
    },
    deleteCredential(value: R): 'deleted' | 'absent' | 'not_deleted' | 'unknown' {
      const reference = family.reference(value);
      // Validate every ownership marker and blob before deleting the exact
      // reference. A malformed prior entry is never silently adopted/removed.
      let present: boolean | null;
      try { present = withCredential(reference, (address, names) => { checkedSecret(reference, decoded(address, names)); return true; }); }
      catch (error) {
        if (error instanceof WindowsNativeError && error.code === 'windows_native_untrusted') return 'not_deleted';
        throw error;
      }
      if (present === null) return 'absent';
      try {
        bindings.assertHealthy();
        const deleted = bool(bindings.delete(family.names(reference).target, 1, 0));
        const status = deleted ? 0 : bindings.lastError();
        return deleted ? 'deleted' : status === 1168 ? 'absent' : 'unknown';
      } catch { bindings.poison(); return 'unknown'; }
    },
  });
}

const SYSTEM = 'S-1-5-18', ADMINISTRATORS = 'S-1-5-32-544';
const INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
const SYSTEM_DIRECTORY = 'C:\\Windows\\System32';
const INVALID_HANDLE = 0xffffffffffffffffn;
let processPoisoned = false;
function pointer(value: unknown): bigint {
  if (value === null) return 0n;
  if (typeof value !== 'bigint' || value < 0n || value > INVALID_HANDLE) { processPoisoned = true; fail('windows_native_unavailable'); }
  return value;
}
function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) fail('windows_native_unavailable');
  return value;
}
function checkedHandle(handle: WindowsOwnedHandle): bigint {
  if (handle.value === null) fail('windows_native_poisoned');
  return handle.value;
}
function text(buffer: Buffer, count: number): string {
  if (count < 1 || count >= buffer.length / 2 || buffer.readUInt16LE(count * 2) !== 0) fail('windows_native_unavailable');
  return buffer.subarray(0, count * 2).toString('utf16le');
}
function samePath(a: string, b: string): boolean { return a.toLowerCase() === b.toLowerCase(); }

/** All functions are synchronous, fixed-signature and on this calling thread.
 * Native calls cannot be preempted by JS cancellation. No .async(), callbacks,
 * arbitrary DLL paths, library unloading or koffi.reset() are used. */
interface WindowsNativeApis {
  readonly lease: WindowsLeaseApi;
  readonly credentials: WindowsCredentialApi;
  readonly delegatedCredentials: DelegatedNativeSecretApi;
  readonly profileDirectory: WindowsProfileDirectoryApi;
  readonly snapshots: WindowsSnapshotFileApi;
  readonly knownFolders: WindowsKnownFolderApi;
}
async function loadWindowsNativeApis(): Promise<WindowsNativeApis> {
  assertWindowsNativeEnvironment();
  if (processPoisoned) fail('windows_native_poisoned');
  let koffi: typeof import('koffi');
  try {
    const require = createRequire(import.meta.url);
    // Refuse the dynamic build/resources fallback before evaluating the loader.
    const main = require.resolve('koffi');
    const nativeMain = require.resolve('@koromix/koffi-win32-x64');
    const pkg = JSON.parse(readFileSync(path.join(path.dirname(main), 'package.json'), 'utf8')) as { version?: unknown };
    const nativePkg = JSON.parse(readFileSync(path.join(path.dirname(nativeMain), 'package.json'), 'utf8')) as { version?: unknown };
    if (pkg.version !== '3.3.3' || nativePkg.version !== '3.3.3') fail('windows_native_environment');
    // A failed/missing selected prebuilt refuses; it cannot activate Koffi's
    // dynamic build/resources fallback. Its subsequent static require is cached.
    const prebuilt = require(nativeMain) as { version?: unknown };
    if (prebuilt.version !== '3.3.3') fail('windows_native_environment');
    koffi = require('koffi') as typeof import('koffi');
    if (koffi.version !== '3.3.3') fail('windows_native_environment');
  } catch (error) {
    if (error instanceof WindowsNativeError) throw error;
    return fail('windows_native_unavailable');
  }
  // Bootstrap uses the fixed already-loaded Windows KnownDLL, never a caller
  // path. Node's OS loader/known kernel is trusted. Refuse a different actual
  // inbox before loading any absolute DLL path: C:\\Windows is not universal.
  const kernel = koffi.load('kernel32.dll');
  const systemDirectory = kernel.func('uint32 __stdcall GetSystemDirectoryW(void *buffer, uint32 length)');
  const moduleHandle = kernel.func('void * __stdcall GetModuleHandleW(str16 name)');
  const moduleFilename = kernel.func('uint32 __stdcall GetModuleFileNameW(void *module, void *buffer, uint32 length)');
  const directoryOutput = Buffer.alloc(65536), kernelOutput = Buffer.alloc(65536);
  const kernelModule = pointer(moduleHandle('kernel32.dll'));
  if (!samePath(text(directoryOutput, number(systemDirectory(directoryOutput, 32768))), SYSTEM_DIRECTORY)
    || kernelModule === 0n
    || !samePath(text(kernelOutput, number(moduleFilename(kernelModule, kernelOutput, 32768))), `${SYSTEM_DIRECTORY}\\kernel32.dll`)) fail('windows_native_untrusted');
  const security = koffi.load(`${SYSTEM_DIRECTORY}\\advapi32.dll`);
  const shell = koffi.load(`${SYSTEM_DIRECTORY}\\shell32.dll`);
  const ole = koffi.load(`${SYSTEM_DIRECTORY}\\ole32.dll`);
  const open = kernel.func('void * __stdcall CreateFileW(str16 filename, uint32 access, uint32 share, void *security, uint32 disposition, uint32 flags, void *template)');
  const close = kernel.func('int __stdcall CloseHandle(void *handle)');
  const lastError = kernel.func('uint32 __stdcall GetLastError()');
  const readFile = kernel.func('int __stdcall ReadFile(void *handle, void *buffer, uint32 length, void *read, void *overlapped)');
  const seekFile = kernel.func('int __stdcall SetFilePointerEx(void *handle, int64 distance, void *position, uint32 method)');
  const flushFile = kernel.func('int __stdcall FlushFileBuffers(void *handle)');
  const fileInfo = kernel.func('int __stdcall GetFileInformationByHandle(void *handle, void *info)');
  const fileType = kernel.func('uint32 __stdcall GetFileType(void *handle)');
  const finalPath = kernel.func('uint32 __stdcall GetFinalPathNameByHandleW(void *handle, void *buffer, uint32 length, uint32 flags)');
  const createDirectory = kernel.func('int __stdcall CreateDirectoryW(str16 filename, void *security)');
  const volumePath = kernel.func('int __stdcall GetVolumePathNameW(str16 filename, void *buffer, uint32 length)');
  const driveType = kernel.func('uint32 __stdcall GetDriveTypeW(str16 root)');
  const volumeInfo = kernel.func('int __stdcall GetVolumeInformationW(str16 root, void *label, uint32 labelSize, void *serial, void *maxComponent, void *flags, void *filesystem, uint32 filesystemSize)');
  const localFree = kernel.func('void * __stdcall LocalFree(void *memory)');
  const openToken = security.func('int __stdcall OpenProcessToken(void *process, uint32 access, void *token)');
  const tokenInfo = security.func('int __stdcall GetTokenInformation(void *token, uint32 kind, void *buffer, uint32 length, void *required)');
  const sidString = security.func('int __stdcall ConvertSidToStringSidW(void *sid, void *text)');
  const descriptor = security.func('int __stdcall ConvertStringSecurityDescriptorToSecurityDescriptorW(str16 text, uint32 revision, void *descriptor, void *size)');
  const getSecurity = security.func('uint32 __stdcall GetSecurityInfo(void *handle, uint32 kind, uint32 information, void *owner, void *group, void *dacl, void *sacl, void *descriptor)');
  const descriptorControl = security.func('int __stdcall GetSecurityDescriptorControl(void *descriptor, void *control, void *revision)');
  const validAcl = security.func('int __stdcall IsValidAcl(void *acl)');
  const aclInfo = security.func('int __stdcall GetAclInformation(void *acl, void *buffer, uint32 length, uint32 kind)');
  const getAce = security.func('int __stdcall GetAce(void *acl, uint32 index, void *ace)');
  const credentialRead = security.func('int __stdcall CredReadW(str16 target, uint32 type, uint32 flags, void *credential)');
  const credentialWrite = security.func('int __stdcall CredWriteW(void *credential, uint32 flags)');
  const credentialDelete = security.func('int __stdcall CredDeleteW(str16 target, uint32 type, uint32 flags)');
  const credentialFree = security.func('void __stdcall CredFree(void *credential)');
  const knownFolder = shell.func('int __stdcall SHGetKnownFolderPath(void *identifier, uint32 flags, void *token, void *output)');
  const taskFree = ole.func('void __stdcall CoTaskMemFree(void *memory)');
  // Strong references retain libraries while their methods exist.
  const libraries = [kernel, security, shell, ole];
  const healthy = () => { void libraries; assertWindowsNativeEnvironment(); if (processPoisoned) fail('windows_native_poisoned'); };
  const closeOwned = (handle: WindowsOwnedHandle): void => {
    if (handle.value === null) return;
    const owned = handle.value; handle.value = null; // Retire before the one close attempt.
    try {
      if (close(owned) !== 0) return;
      lastError(); // Captured immediately; never render native diagnostics.
    } catch { /* Unknown closure is never retried, even if the numeric handle is reused. */ }
    processPoisoned = true; fail('windows_native_close_unknown');
  };
  const freeOwned = (owned: bigint): void => {
    if (owned === 0n) return;
    try { if (pointer(localFree(owned)) === 0n) return; }
    catch { /* A throwing/malformed free is ambiguous and is never repeated. */ }
    processPoisoned = true; fail('windows_native_close_unknown');
  };
  const boundary = <T>(work: () => T): T => {
    try { return work(); }
    catch (error) {
      if (error instanceof WindowsNativeError) throw error;
      processPoisoned = true; return fail('windows_native_unavailable');
    }
  };
  const stringifySid = (sid: bigint): string => {
    const result = Buffer.alloc(8);
    if (sid === 0n || sidString(sid, result) === 0) fail('windows_native_untrusted');
    const owned = result.readBigUInt64LE();
    try {
      const value = koffi.decode.string16(owned);
      if (typeof value !== 'string' || value.length > 184 || !/^S-1-(?:\d+-){1,15}\d+$/.test(value)) fail('windows_native_untrusted');
      return value;
    } finally { freeOwned(owned); }
  };
  let currentSid: string;
  const tokenOutput = Buffer.alloc(8);
  if (openToken(INVALID_HANDLE, 8, tokenOutput) === 0) fail('windows_native_unavailable');
  const token = { value: tokenOutput.readBigUInt64LE() };
  try {
    const required = Buffer.alloc(4);
    tokenInfo(checkedHandle(token), 1, null, 0, required);
    const length = required.readUInt32LE();
    if (length < 8 || length > 4096) fail('windows_native_unavailable');
    const buffer = Buffer.alloc(length);
    if (tokenInfo(checkedHandle(token), 1, buffer, length, required) === 0) fail('windows_native_unavailable');
    currentSid = stringifySid(buffer.readBigUInt64LE());
  } finally { closeOwned(token); }
  const trustedSids = new Set([currentSid, SYSTEM, ADMINISTRATORS, INSTALLER]);
  const privateSids = new Set([currentSid, SYSTEM, ADMINISTRATORS]);
  const privateSecurity = (work: (attributes: Buffer) => unknown): unknown => {
    const output = Buffer.alloc(8);
    const sddl = `O:${currentSid}D:P(A;OICI;FA;;;${currentSid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`;
    if (descriptor(sddl, 1, output, null) === 0) fail('windows_native_unavailable');
    const owned = output.readBigUInt64LE();
    try {
      const attributes = Buffer.alloc(24); attributes.writeUInt32LE(24); attributes.writeBigUInt64LE(owned, 8);
      return work(attributes);
    } finally { freeOwned(owned); }
  };
  const opened = (filename: string, access: number, share: number, disposition: number,
    flags: number, attributes: Buffer | null): WindowsOwnedHandle => {
    const value = pointer(open(filename, access, share, attributes, disposition, flags, null));
    if (value === INVALID_HANDLE || value === 0n) {
      const error = number(lastError());
      return fail(error === 32 || error === 33 ? 'windows_native_busy' : 'windows_native_unavailable');
    }
    return { value };
  };
  const facts = (handle: WindowsOwnedHandle): WindowsFileFacts => {
    const value = checkedHandle(handle), buffer = Buffer.alloc(52), result = Buffer.alloc(65536);
    if (fileType(value) !== 1 || fileInfo(value, buffer) === 0) fail('windows_native_untrusted');
    const count = number(finalPath(value, result, result.length / 2, 0));
    const filename = text(result, count);
    return Object.freeze({ attributes: buffer.readUInt32LE(),
      size: BigInt(buffer.readUInt32LE(32)) * 0x100000000n + BigInt(buffer.readUInt32LE(36)),
      links: buffer.readUInt32LE(40),
      identity: `${buffer.readUInt32LE(28)}:${buffer.readUInt32LE(44)}:${buffer.readUInt32LE(48)}`,
      finalPath: filename });
  };
  const trust: WindowsLeaseApi['trust'] = (handle, kind) => {
    const owner = Buffer.alloc(8), dacl = Buffer.alloc(8), output = Buffer.alloc(8);
    if (getSecurity(checkedHandle(handle), 1, 5, owner, null, dacl, null, output) !== 0) fail('windows_native_untrusted');
    const owned = output.readBigUInt64LE();
    try {
      const ownerSid = stringifySid(owner.readBigUInt64LE());
      const privateObject = kind === 'private-directory' || kind === 'private-file';
      if (privateObject ? ownerSid !== currentSid : !trustedSids.has(ownerSid)
        || kind === 'system-file' && ownerSid === currentSid && ![SYSTEM, ADMINISTRATORS, INSTALLER].includes(ownerSid)) fail('windows_native_untrusted');
      const acl = dacl.readBigUInt64LE(), control = Buffer.alloc(2), revision = Buffer.alloc(4), counts = Buffer.alloc(12);
      if (acl === 0n || descriptorControl(owned, control, revision) === 0 || validAcl(acl) === 0
        || aclInfo(acl, counts, 12, 2) === 0) fail('windows_native_untrusted');
      if (privateObject && (control.readUInt16LE() & 0x1000) === 0) fail('windows_native_untrusted');
      const count = counts.readUInt32LE(), bytes = counts.readUInt32LE(4);
      if (count < 1 || count > 128 || bytes < 8 || bytes > 65536) fail('windows_native_untrusted');
      const seen = new Set<string>();
      for (let index = 0; index < count; index++) {
        const aceOut = Buffer.alloc(8);
        if (getAce(acl, index, aceOut) === 0) fail('windows_native_untrusted');
        const ace = aceOut.readBigUInt64LE(), header = Buffer.from(koffi.view(ace, 8));
        const type = header[0]!, flags = header[1]!, size = header.readUInt16LE(2), mask = header.readUInt32LE(4);
        if (size < 16 || size > bytes || type !== 0 && type !== 1) fail('windows_native_untrusted');
        const sid = stringifySid(ace + 8n);
        if (privateObject) {
          if (type !== 0 || (flags & ~3) !== 0 || mask !== 0x1f01ff || !privateSids.has(sid) || seen.has(sid)) fail('windows_native_untrusted');
          seen.add(sid);
        } else if (type === 0 && (flags & 8) === 0) {
          const allowed = kind === 'system-file' ? [SYSTEM, ADMINISTRATORS, INSTALLER].includes(sid) : trustedSids.has(sid);
          // Ancestors may permit creating unrelated children. They may not let
          // another principal replace, retag or change authority of this path.
          const mutation = kind === 'system-file' ? 0x500d0156 : 0x500d0150;
          if (!allowed && (mask & mutation) !== 0) fail('windows_native_untrusted');
        }
      }
      if (privateObject && (seen.size !== privateSids.size || [...privateSids].some(sid => !seen.has(sid)))) fail('windows_native_untrusted');
    } finally { freeOwned(owned); }
  };
  const localNtfs = (filename: string): void => {
    const rootBuffer = Buffer.alloc(65536);
    if (volumePath(filename, rootBuffer, rootBuffer.length / 2) === 0) fail('windows_native_untrusted');
    // Find UTF-16 terminator on an aligned boundary.
    let chars = 0; while (chars < rootBuffer.length / 2 && rootBuffer.readUInt16LE(chars * 2) !== 0) chars++;
    const root = text(rootBuffer, chars), filesystem = Buffer.alloc(64);
    if (!/^[a-z]:\\$/i.test(root) || driveType(root) !== 3
      || volumeInfo(root, null, 0, null, null, null, filesystem, 32) === 0) fail('windows_native_untrusted');
    let length = 0; while (length < 32 && filesystem.readUInt16LE(length * 2) !== 0) length++;
    if (text(filesystem, length) !== 'NTFS') fail('windows_native_untrusted');
  };
  const api: WindowsLeaseApi = {
    currentSid, assertHealthy: healthy,
    openDirectory(filename) { healthy(); return boundary(() => opened(filename, 0x20080, 3, 3, 0x02200000, null)); },
    createPrivateDirectory(filename) {
      healthy(); boundary(() => privateSecurity(attributes => {
        if (createDirectory(filename, attributes) === 0 && number(lastError()) !== 183) fail('windows_native_unavailable');
      }));
    },
    openLease(filename) {
      healthy(); let acquired: WindowsOwnedHandle | undefined;
      try {
        return boundary(() => privateSecurity(attributes => {
          acquired = opened(filename, 0xc0020080, 0, 4, 0x00200000, attributes); return acquired;
        }) as WindowsOwnedHandle);
      } catch (error) {
        // Descriptor release can fail after CreateFile succeeded. Retain and
        // retire that kernel handle locally even before the caller receives it.
        if (acquired) closeOwned(acquired);
        throw error;
      }
    },
    facts(handle) { healthy(); return boundary(() => facts(handle)); },
    trust(handle, kind) { healthy(); return boundary(() => trust(handle, kind)); },
    localNtfs(filename) { healthy(); return boundary(() => localNtfs(filename)); },
    close: closeOwned,
  };
  // Bootstrap trusts the fixed inbox path, never SystemRoot/PATH or caller data.
  // Attestation refuses path aliases/reparse objects and non-system-writable DLLs.
  for (const basename of ['kernel32.dll', 'advapi32.dll', 'shell32.dll', 'ole32.dll']) {
    const expected = `${SYSTEM_DIRECTORY}\\${basename}`, output = Buffer.alloc(65536);
    const module = pointer(moduleHandle(basename));
    if (module === 0n || !samePath(text(output, number(moduleFilename(module, output, 32768))), expected)) fail('windows_native_untrusted');
    const handle = opened(expected, 0x20080, 3, 3, 0x00200000, null);
    try {
      const info = facts(handle);
      if ((info.attributes & 0x410) !== 0 || !samePath(info.finalPath, `\\\\?\\${expected}`)) fail('windows_native_untrusted');
      trust(handle, 'system-file'); localNtfs(expected);
    } finally { closeOwned(handle); }
  }
  const credentialBindings: WindowsCredentialBindings = { assertHealthy: healthy,
    poison() { processPoisoned = true; },
    read: credentialRead, write: credentialWrite, delete: credentialDelete, free: credentialFree,
    lastError, view: (address, length) => koffi.view(address, length),
    address: buffer => koffi.address(buffer),
  };
  const credentials = bindWindowsCredentialApi(credentialBindings);
  const delegatedCredentials = bindWindowsDelegatedCredentialApi(credentialBindings);
  const knownFolderBindings: WindowsKnownFolderBindings = { assertHealthy: healthy,
    poison() { processPoisoned = true; },
    openCurrentToken() {
      healthy(); return boundary(() => {
        const output = Buffer.alloc(8);
        // QUERY | IMPERSONATE | DUPLICATE, required by user-aware folder APIs.
        if (openToken(INVALID_HANDLE, 14, output) === 0) fail('windows_native_unavailable');
        const value = pointer(output.readBigUInt64LE());
        if (value === 0n || value === INVALID_HANDLE) { processPoisoned = true; fail('windows_native_unavailable'); }
        return { value };
      });
    },
    closeToken: closeOwned, lookup: knownFolder, free: taskFree,
    view: (address, length) => koffi.view(address, length),
  };
  const knownFolders = bindWindowsKnownFolderApi(knownFolderBindings);
  const profileDirectory = bindWindowsProfileDirectoryApi(knownFolderBindings);
  const snapshots: WindowsSnapshotFileApi = Object.freeze({ ...api,
    openDataFile(filename: string, create: boolean): WindowsOwnedHandle | null {
      healthy();
      let acquired: WindowsOwnedHandle | undefined;
      const operation = (attributes: Buffer | null): WindowsOwnedHandle | null => {
        // No truncation, replacement, delete sharing or reparse traversal.
        const value = pointer(open(filename, 0xc0020080, 3, attributes, create ? 1 : 3, 0x80200000, null));
        if (value === INVALID_HANDLE || value === 0n) {
          const error = number(lastError());
          if (!create && error === 2) return null;
          return fail(error === 32 || error === 33 ? 'windows_native_busy' : 'windows_native_unavailable');
        }
        acquired = { value }; return acquired;
      };
      try { return boundary(() => create ? privateSecurity(operation) as WindowsOwnedHandle : operation(null)); }
      catch (error) { if (acquired) closeOwned(acquired); throw error; }
    },
    readPrefix(handle: WindowsOwnedHandle, limit: number): Uint8Array {
      healthy();
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) fail('windows_native_untrusted');
      return boundary(() => {
        const value = checkedHandle(handle), bytes = Buffer.alloc(limit), count = Buffer.alloc(4);
        if (seekFile(value, 0n, null, 0) === 0) { lastError(); return fail('windows_native_unavailable'); }
        if (readFile(value, bytes, limit, count, null) === 0) { lastError(); return fail('windows_native_unavailable'); }
        const length = count.readUInt32LE();
        if (length > limit) { processPoisoned = true; return fail('windows_native_unavailable'); }
        return new Uint8Array(bytes.subarray(0, length));
      });
    },
    readTail(handle: WindowsOwnedHandle, limit: number): Uint8Array {
      healthy();
      if (!Number.isInteger(limit) || limit < 1 || limit > 16) fail('windows_native_untrusted');
      return boundary(() => {
        const value = checkedHandle(handle), bytes = Buffer.alloc(limit), count = Buffer.alloc(4);
        // Caller pins and checks size/identity around this bounded footer read.
        if (seekFile(value, -BigInt(limit), null, 2) === 0) { lastError(); return fail('windows_native_unavailable'); }
        if (readFile(value, bytes, limit, count, null) === 0) { lastError(); return fail('windows_native_unavailable'); }
        const length = count.readUInt32LE();
        if (length !== limit) { processPoisoned = true; return fail('windows_native_unavailable'); }
        return new Uint8Array(bytes);
      });
    },
    flushDataFile(handle: WindowsOwnedHandle): void {
      healthy(); boundary(() => {
        if (flushFile(checkedHandle(handle)) === 0) { lastError(); fail('windows_native_unavailable'); }
      });
    },
  });
  return Object.freeze({ lease: Object.freeze(api), credentials, delegatedCredentials, snapshots, knownFolders, profileDirectory });
}

let bootstrap: Promise<WindowsNativeApis> | undefined;
async function windowsNativeApis(): Promise<WindowsNativeApis> {
  assertWindowsNativeEnvironment();
  if (processPoisoned) fail('windows_native_poisoned');
  try { return await (bootstrap ??= loadWindowsNativeApis()); }
  catch (error) {
    if (error instanceof WindowsNativeError) throw error;
    // A startup FFI exception can follow an allocating native call before its
    // owned result is captured. Its address cannot be guessed or retried.
    processPoisoned = true;
    return fail('windows_native_unavailable');
  }
}
export async function createWindowsLeaseApi(): Promise<WindowsLeaseApi> { return (await windowsNativeApis()).lease; }
export async function createWindowsCredentialApi(): Promise<WindowsCredentialApi> { return (await windowsNativeApis()).credentials; }
export async function createWindowsDelegatedCredentialApi(): Promise<DelegatedNativeSecretApi> { return (await windowsNativeApis()).delegatedCredentials; }
export async function createWindowsProfileDirectoryApi(): Promise<WindowsProfileDirectoryApi> { return (await windowsNativeApis()).profileDirectory; }
export async function createWindowsSnapshotFileApi(): Promise<WindowsSnapshotFileApi> { return (await windowsNativeApis()).snapshots; }
export async function createWindowsKnownFolderApi(): Promise<WindowsKnownFolderApi> { return (await windowsNativeApis()).knownFolders; }

/** Strict DOS-root spelling, with no devices, streams, aliases or dot segments. */
export function nativeLeaseRootPath(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || !/^[a-z]:\\/i.test(value)
    || /[\x00-\x1f\x7f/]/.test(value) || value.length < 4 || value.endsWith('\\')) fail('windows_native_untrusted');
  const parts = value.slice(3).split('\\');
  if (parts.some(part => !part || part === '.' || part === '..' || /[. :]+$/.test(part)
    || /[:*?"<>|]/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) fail('windows_native_untrusted');
  if (path.win32.normalize(value) !== value) fail('windows_native_untrusted');
  return value;
}
