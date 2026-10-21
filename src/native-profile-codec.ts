/** Bota native snapshot encoding v1. Pure bytes; no filesystem or native access. */
import { TextDecoder, types } from 'node:util';
import {
  decodeNativeProfileSnapshot,
  NativeProfileTransactionError,
  type NativeProfileRecord,
  type NativeProfileSnapshot,
} from './native-profile-transaction.js';

export const NATIVE_PROFILE_MAX_SNAPSHOT_BYTES = 24 * 1024;

const recordFields = ['format_version', 'name', 'store_id', 'api_origin', 'project_id', 'organization_id',
  'key_id', 'allow_http_loopback', 'state', 'profile_id', 'credential_ref'] as const;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength')!.get!;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')!.get!;
const byteSet = Uint8Array.prototype.set;

function invalid(): never { throw new NativeProfileTransactionError('profile_invalid_metadata'); }
function checked(value: unknown, name: string, storeId: string): NativeProfileSnapshot {
  // A codec caller cannot replace the engine's fixed namespace with an object
  // or a coercion hook. The core owns all remaining record/state decisions.
  if (typeof name !== 'string' || name.length > 64 || !/^[a-z0-9-]{1,64}$/.test(name)
    || typeof storeId !== 'string' || storeId.length > 64 || !/^[a-z][a-z0-9_-]{0,63}$/.test(storeId)) invalid();
  return decodeNativeProfileSnapshot(value, name, storeId);
}
function record(value: NativeProfileRecord): Record<string, unknown> {
  const result: Record<string, unknown> = Object.create(null);
  for (const field of recordFields) result[field] = value[field];
  return result;
}
function canonical(snapshot: NativeProfileSnapshot): Uint8Array {
  const result: Record<string, unknown> = Object.create(null);
  result.format_version = snapshot.format_version;
  result.revision = snapshot.revision;
  result.record = snapshot.record === null ? null : record(snapshot.record);
  if (snapshot.journal === null) result.journal = null;
  else {
    const journal: Record<string, unknown> = Object.create(null);
    journal.format_version = snapshot.journal.format_version;
    journal.transaction_id = snapshot.journal.transaction_id;
    journal.operation = snapshot.journal.operation;
    journal.phase = snapshot.journal.phase;
    journal.desired = record(snapshot.journal.desired);
    result.journal = journal;
  }
  // Fixed whitelist order, JSON string escaping and exactly one LF form this
  // Bota encoding. This is not a general JSON canonicalization standard.
  const bytes = Buffer.from(JSON.stringify(result) + '\n', 'utf8');
  if (bytes.byteLength > NATIVE_PROFILE_MAX_SNAPSHOT_BYTES) invalid();
  return new Uint8Array(bytes);
}
function ownedBytes(value: Uint8Array): Uint8Array {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !types.isUint8Array(value)
    || ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(value))) invalid();
  // Intrinsic accessors/set read typed-array storage, not user-overridden
  // length/buffer accessors or iterators. No mutable input alias is retained.
  const size: number = typedArrayByteLength.call(value);
  if (size === 0 || size > NATIVE_PROFILE_MAX_SNAPSHOT_BYTES
    || types.isSharedArrayBuffer(typedArrayBuffer.call(value))) invalid();
  const copy = new Uint8Array(size);
  byteSet.call(copy, value);
  return copy;
}

/** Return a fresh owned encoding of an exact core-validated snapshot. */
export function encodeNativeProfileSnapshot(value: unknown, name: string, storeId: string): Uint8Array {
  try { return canonical(checked(value, name, storeId)); }
  catch { return invalid(); }
}

/** Decode only the one Bota encoding; duplicates and alternate spellings fail. */
export function decodeNativeProfileSnapshotBytes(value: Uint8Array, name: string, storeId: string): NativeProfileSnapshot {
  try {
    const bytes = ownedBytes(value);
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid();
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const snapshot = checked(JSON.parse(text), name, storeId);
    const expected = canonical(snapshot);
    if (bytes.byteLength !== expected.byteLength || !bytes.every((byte, index) => byte === expected[index])) invalid();
    return snapshot;
  } catch { return invalid(); }
}
