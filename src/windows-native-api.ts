/** Narrow Windows x64 in-process bindings. No credential-store functions. */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'node:path';

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
async function loadWindowsLeaseApi(): Promise<WindowsLeaseApi> {
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
  const open = kernel.func('void * __stdcall CreateFileW(str16 filename, uint32 access, uint32 share, void *security, uint32 disposition, uint32 flags, void *template)');
  const close = kernel.func('int __stdcall CloseHandle(void *handle)');
  const lastError = kernel.func('uint32 __stdcall GetLastError()');
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
  // Strong references retain both libraries while their methods exist.
  const libraries = [kernel, security];
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
  for (const basename of ['kernel32.dll', 'advapi32.dll']) {
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
  return Object.freeze(api);
}

export async function createWindowsLeaseApi(): Promise<WindowsLeaseApi> {
  assertWindowsNativeEnvironment();
  try { return await loadWindowsLeaseApi(); }
  catch (error) {
    if (error instanceof WindowsNativeError) throw error;
    // A startup FFI exception can follow an allocating native call before its
    // owned result is captured. Its address cannot be guessed or retried.
    processPoisoned = true;
    return fail('windows_native_unavailable');
  }
}

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
