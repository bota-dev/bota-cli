/** Adapter-neutral T06 state machine. No filesystem, native-store or CLI wiring. */
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { normalizeProfileOrigin } from './profiles.js';
import type { ProjectIdentity } from './client.js';

export interface NativeOperationBudget { assertActive(): void }
export interface NativeOperationContext {
  readonly signal: AbortSignal;
  /** Opaque capability: the engine never resets, serializes or replaces it. */
  readonly budget: NativeOperationBudget;
}
export interface NativeReference { readonly profile_id: string; readonly credential_ref: string }
export interface NativeProfileRecord extends NativeReference {
  readonly format_version: 2;
  readonly name: string;
  readonly store_id: string;
  readonly api_origin: string;
  readonly project_id: string;
  readonly organization_id: string;
  /** Safe backend identity, not a bearer hint, digest or permission cache. */
  readonly key_id: string;
  readonly allow_http_loopback: boolean;
  readonly state: 'ready' | 'disabled' | 'removed';
}
export interface NativeProfileJournal {
  readonly format_version: 1;
  readonly transaction_id: string;
  readonly operation: 'enroll' | 'remove';
  readonly phase: 'intent' | 'committed';
  readonly desired: NativeProfileRecord;
}
export interface NativeProfileSnapshot {
  readonly format_version: 1;
  readonly revision: string;
  readonly record: NativeProfileRecord | null;
  readonly journal: NativeProfileJournal | null;
}
export interface NativeSnapshotPort {
  /** Must also refuse a colliding v1/foreign name. null means proven absent. */
  load(name: string, context: NativeOperationContext): Promise<unknown>;
  /** Atomic durable compare-and-publish; unknown must never be retried blindly. */
  publish(name: string, expectedRevision: string | null, next: NativeProfileSnapshot,
    context: NativeOperationContext): Promise<'committed' | 'not_committed' | 'unknown'>;
}
export interface NativeStorePort {
  readonly id: string;
  /** Derive a fixed store namespace from this reference. Never enumerate. */
  read(reference: NativeReference, context: NativeOperationContext): Promise<
    { readonly status: 'absent' } | { readonly status: 'present'; readonly key: unknown }>;
  write(reference: NativeReference, key: string, context: NativeOperationContext): Promise<'stored' | 'not_stored' | 'unknown'>;
  delete(reference: NativeReference, context: NativeOperationContext): Promise<'deleted' | 'absent' | 'not_deleted' | 'unknown'>;
}
export interface NativeLeasePort {
  /** Process-lifetime exclusive store-namespace then profile ownership.
   * This conservative cohort serializes even distinct profiles in one store.
   * Hold through work, including identity and caller action; release/join in
   * finally even after abort. mkdir/PID/age are not this authority. */
  runExclusive<T>(storeId: string, name: string, context: NativeOperationContext, work: () => Promise<T>): Promise<T>;
}
export interface NativeProfilePorts {
  readonly lease: NativeLeasePort;
  readonly snapshots: NativeSnapshotPort;
  readonly store: NativeStorePort;
  readIdentity(origin: string, key: string, context: NativeOperationContext): Promise<unknown>;
  /** Testability only; production must generate independent random UUIDs. */
  newId?(): string;
}

const messages = {
  profile_invalid_input: 'Native profile input is invalid or unsupported.',
  profile_invalid_metadata: 'Native profile state is invalid or unsupported.',
  profile_not_found: 'The native profile does not exist.',
  profile_exists: 'The native profile name is already reserved.',
  profile_busy: 'The native profile lease or state is unavailable.',
  profile_lease_failed: 'Native profile lease cleanup or ownership could not be confirmed.',
  profile_cancelled: 'The native profile operation was cancelled.',
  profile_deadline: 'The native profile operation deadline expired.',
  profile_origin_mismatch: 'The selected API origin does not match the native profile.',
  profile_binding_mismatch: 'The selected native profile binding changed.',
  profile_identity_failed: 'The selected credential identity could not be verified.',
  profile_identity_mismatch: 'The selected credential identity does not match the native profile.',
  profile_key_required: 'A valid explicitly selected API credential is required.',
  profile_store_unavailable: 'The configured native credential store is unavailable.',
  profile_store_absent: 'The exact native credential reference is absent.',
  profile_store_mismatch: 'The exact native credential readback did not match.',
  profile_write_unknown: 'The native credential write outcome requires explicit recovery.',
  profile_delete_unknown: 'Native credential cleanup requires explicit recovery.',
  profile_state_unknown: 'Native profile publication requires explicit recovery.',
  profile_pending_recovery: 'The native profile requires explicit recovery before use.',
  profile_disabled: 'Stored credential selection is disabled for this native profile.',
  profile_operation_failed: 'The operation failed; its remote outcome may be unknown.',
} as const;
export type NativeProfileErrorCode = keyof typeof messages;
export class NativeProfileTransactionError extends Error {
  declare readonly code: NativeProfileErrorCode;
  declare readonly recovery_required: boolean;
  declare readonly operation_may_have_executed: boolean;
  constructor(code: NativeProfileErrorCode, recoveryRequired = false, operationMayHaveExecuted = false) {
    const safeCode = Object.hasOwn(messages, code) ? code : 'profile_invalid_input';
    super(messages[safeCode]); this.name = 'NativeProfileTransactionError';
    Object.defineProperties(this, {
      code: { value: safeCode, enumerable: true },
      recovery_required: { value: recoveryRequired === true, enumerable: true },
      operation_may_have_executed: { value: operationMayHaveExecuted === true, enumerable: true },
    });
  }
}
function fail(code: NativeProfileErrorCode, pending = false): never { throw new NativeProfileTransactionError(code, pending); }
function plain(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('profile_invalid_metadata');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== Object.keys(descriptors).length) fail('profile_invalid_metadata');
  const result: Record<string, unknown> = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('profile_invalid_metadata');
    result[key] = descriptor.value;
  }
  return result;
}
function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const result = plain(value);
  if (Object.keys(result).length !== fields.length || fields.some(field => !Object.hasOwn(result, field))) fail('profile_invalid_metadata');
  return result;
}
function uuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}
function nameChecked(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-z0-9-]{1,64}$/.test(value)) fail('profile_invalid_input');
}
function opaque(value: unknown): value is string {
  return typeof value === 'string' && value.length !== 0 && value.length <= 2048
    && Buffer.byteLength(value, 'utf8') <= 2048;
}
function keyChecked(value: unknown): string {
  if (typeof value !== 'string' || !/^[\x21-\x7e]{1,2560}$/.test(value)) fail('profile_key_required');
  return value;
}
function origin(value: unknown, loopback: unknown): string {
  if (typeof value !== 'string' || typeof loopback !== 'boolean') fail('profile_invalid_input');
  try { return normalizeProfileOrigin(value, loopback); }
  catch { return fail('profile_invalid_input'); }
}
function reflected(record: NativeProfileRecord, key: string): boolean {
  return Object.values(record).some(value => typeof value === 'string' && value.includes(key));
}
const recordFields = ['format_version', 'name', 'store_id', 'api_origin', 'project_id', 'organization_id',
  'key_id', 'allow_http_loopback', 'state', 'profile_id', 'credential_ref'];
function recordDecoded(value: unknown, name: string, storeId: string): NativeProfileRecord {
  const data = exact(value, recordFields);
  if (data.format_version !== 2 || data.name !== name || data.store_id !== storeId
    || !uuid(data.profile_id) || !uuid(data.credential_ref) || data.profile_id === data.credential_ref
    || !opaque(data.project_id) || !opaque(data.organization_id) || !opaque(data.key_id)
    || !['ready', 'disabled', 'removed'].includes(data.state as string)
    || origin(data.api_origin, data.allow_http_loopback) !== data.api_origin) fail('profile_invalid_metadata');
  const result = Object.freeze({ ...data }) as unknown as NativeProfileRecord;
  if (Buffer.byteLength(JSON.stringify(result)) > 8192) fail('profile_invalid_metadata');
  return result;
}
function sameRecord(a: NativeProfileRecord, b: NativeProfileRecord): boolean {
  return recordFields.every(field => a[field as keyof NativeProfileRecord] === b[field as keyof NativeProfileRecord]);
}
export function decodeNativeProfileSnapshot(value: unknown, name: string, storeId: string): NativeProfileSnapshot {
  nameChecked(name);
  const data = exact(value, ['format_version', 'revision', 'record', 'journal']);
  if (data.format_version !== 1 || !uuid(data.revision)) fail('profile_invalid_metadata');
  const record = data.record === null ? null : recordDecoded(data.record, name, storeId);
  let journal: NativeProfileJournal | null = null;
  if (data.journal !== null) {
    const item = exact(data.journal, ['format_version', 'transaction_id', 'operation', 'phase', 'desired']);
    if (item.format_version !== 1 || !uuid(item.transaction_id) || !['enroll', 'remove'].includes(item.operation as string)
      || !['intent', 'committed'].includes(item.phase as string)) fail('profile_invalid_metadata');
    journal = Object.freeze({ format_version: 1, transaction_id: item.transaction_id,
      operation: item.operation, phase: item.phase, desired: recordDecoded(item.desired, name, storeId) }) as NativeProfileJournal;
  }
  const valid = record === null ? journal?.operation === 'enroll' && journal.phase === 'intent' && journal.desired.state === 'ready'
    : record.state === 'ready' ? journal === null || journal.operation === 'enroll' && journal.phase === 'committed' && sameRecord(record, journal.desired)
      : record.state === 'disabled' ? journal?.operation === 'remove' && journal.phase === 'intent' && sameRecord(record, journal.desired)
        : journal === null;
  if (!valid) fail('profile_invalid_metadata');
  const result = Object.freeze({ format_version: 1 as const, revision: data.revision, record, journal });
  const target = record ?? journal!.desired;
  const ids = [data.revision, target.profile_id, target.credential_ref, ...(journal ? [journal.transaction_id] : [])];
  if (new Set(ids).size !== ids.length) fail('profile_invalid_metadata');
  if (Buffer.byteLength(JSON.stringify(result)) > 24 * 1024) fail('profile_invalid_metadata');
  return result;
}
export interface NativeProfileBinding {
  readonly profile_id: string; readonly api_origin: string; readonly project_id: string; readonly organization_id: string;
}
export interface NativeSelectionOptions {
  /** Own property means explicitly selected, even when empty/undefined. */
  readonly environmentKey?: unknown;
  readonly apiOriginOverride?: string;
  readonly expectedBinding?: NativeProfileBinding;
}
export interface NativeResolvedCredential {
  readonly apiKey: string;
  readonly apiOrigin: string;
  readonly source: 'environment' | 'store';
  readonly identity: Readonly<ProjectIdentity>;
  readonly profile: NativeProfileRecord;
}

export class NativeProfileTransactions {
  private readonly storeId: string;
  constructor(private readonly ports: NativeProfilePorts) {
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(ports.store.id)) fail('profile_invalid_input');
    this.storeId = ports.store.id;
  }
  private active(context: NativeOperationContext): void {
    if (!(context.signal instanceof AbortSignal) || !context.budget || typeof context.budget.assertActive !== 'function') fail('profile_invalid_input');
    if (context.signal.aborted) fail('profile_cancelled');
    try { context.budget.assertActive(); } catch { fail('profile_deadline'); }
  }
  private id(): string {
    const value = (this.ports.newId ?? randomUUID)();
    if (!uuid(value)) fail('profile_invalid_input');
    return value;
  }
  private async locked<T>(name: string, context: NativeOperationContext, work: () => Promise<T>): Promise<T> {
    nameChecked(name); this.active(context);
    let entered = false, finished = false;
    let workValue: T | undefined;
    let workFailure: NativeProfileTransactionError | undefined;
    try {
      const value = await this.ports.lease.runExclusive(this.storeId, name, context, async () => {
        if (entered) fail('profile_busy');
        entered = true; this.active(context);
        try { workValue = await work(); finished = true; return workValue; }
        catch (error) {
          if (error instanceof NativeProfileTransactionError) workFailure = error;
          throw error;
        }
      });
      if (!entered || !finished || !Object.is(value, workValue)) fail('profile_lease_failed', workFailure?.recovery_required ?? !finished);
      this.active(context);
      return value;
    } catch (error) {
      if (error instanceof NativeProfileTransactionError) throw error;
      throw new NativeProfileTransactionError(entered ? 'profile_lease_failed' : 'profile_busy',
        workFailure?.recovery_required ?? (entered && !finished), workFailure?.operation_may_have_executed ?? false);
    }
  }
  private async load(name: string, context: NativeOperationContext): Promise<NativeProfileSnapshot | null> {
    this.active(context);
    let value: unknown;
    try { value = await this.ports.snapshots.load(name, context); } catch { return fail('profile_busy'); }
    this.active(context);
    if (value === null) return null;
    try { return decodeNativeProfileSnapshot(value, name, this.storeId); }
    catch { return fail('profile_invalid_metadata'); }
  }
  private snapshot(name: string, record: NativeProfileRecord | null, journal: NativeProfileJournal | null): NativeProfileSnapshot {
    return decodeNativeProfileSnapshot({ format_version: 1, revision: this.id(), record, journal }, name, this.storeId);
  }
  private async publish(name: string, previous: NativeProfileSnapshot | null, next: NativeProfileSnapshot,
    context: NativeOperationContext): Promise<void> {
    this.active(context);
    if (previous?.revision === next.revision) fail('profile_invalid_metadata', true);
    let outcome: unknown;
    try { outcome = await this.ports.snapshots.publish(name, previous?.revision ?? null, next, context); }
    catch { return fail('profile_state_unknown', true); }
    if (outcome !== 'committed') fail(outcome === 'not_committed' ? 'profile_busy' : 'profile_state_unknown', outcome !== 'not_committed');
    try { this.active(context); } catch (error) {
      throw new NativeProfileTransactionError((error as NativeProfileTransactionError).code, true);
    }
  }
  private async read(reference: NativeReference, context: NativeOperationContext): Promise<
    { readonly status: 'absent' } | { readonly status: 'present'; readonly key: unknown }> {
    this.active(context);
    let result: unknown;
    try { result = await this.ports.store.read(Object.freeze({ profile_id: reference.profile_id, credential_ref: reference.credential_ref }), context); }
    catch { return fail('profile_store_unavailable'); }
    this.active(context);
    try {
      const data = plain(result);
      if (data.status === 'absent' && Object.keys(data).length === 1) return Object.freeze({ status: 'absent' });
      if (data.status === 'present' && Object.keys(data).length === 2 && Object.hasOwn(data, 'key')) return Object.freeze({ status: 'present', key: data.key });
    } catch { /* Only fixed native-store diagnostics leave this boundary. */ }
    return fail('profile_store_unavailable');
  }
  private async identity(record: Pick<NativeProfileRecord, 'api_origin' | 'project_id' | 'organization_id' | 'key_id'> | null,
    apiOrigin: string, key: string, stored: boolean, context: NativeOperationContext): Promise<Readonly<ProjectIdentity>> {
    this.active(context);
    let value: unknown;
    try { value = await this.ports.readIdentity(apiOrigin, key, context); }
    catch { return fail('profile_identity_failed'); }
    this.active(context);
    let identity: Readonly<ProjectIdentity>;
    try {
      const data = plain(value);
      let scopes: readonly string[] | null = null;
      if (data.key_type === 'restricted') {
        if (!Array.isArray(data.scopes) || types.isProxy(data.scopes) || Object.getPrototypeOf(data.scopes) !== Array.prototype
          || data.scopes.length > 256) fail('profile_identity_failed');
        const descriptors = Object.getOwnPropertyDescriptors(data.scopes);
        if (Reflect.ownKeys(data.scopes).length !== data.scopes.length + 1) fail('profile_identity_failed');
        const values: string[] = [];
        for (let index = 0; index < data.scopes.length; index++) {
          const descriptor = descriptors[index];
          if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || !opaque(descriptor.value)) fail('profile_identity_failed');
          values.push(descriptor.value);
        }
        scopes = Object.freeze(values);
      }
      if (!opaque(data.project_id) || !opaque(data.organization_id) || !opaque(data.key_id)
        || typeof data.is_test_mode !== 'boolean'
        || !(data.key_type === 'secret' && data.scope_mode === 'project_secret' && data.scopes === null
          || data.key_type === 'restricted' && data.scope_mode === 'restricted' && scopes !== null)) fail('profile_identity_failed');
      const strings = [data.project_id, data.organization_id, data.key_id, ...(scopes ?? [])];
      if (strings.some(item => item.includes(key))) fail('profile_identity_failed');
      identity = Object.freeze({ project_id: data.project_id, organization_id: data.organization_id, key_id: data.key_id,
        key_type: data.key_type, scope_mode: data.scope_mode, is_test_mode: data.is_test_mode,
        scopes }) as Readonly<ProjectIdentity>;
      if (Buffer.byteLength(JSON.stringify(identity)) > 64 * 1024) fail('profile_identity_failed');
    } catch { return fail('profile_identity_failed'); }
    if (record && (identity.project_id !== record.project_id || identity.organization_id !== record.organization_id
      || stored && identity.key_id !== record.key_id)) fail('profile_identity_mismatch');
    return identity;
  }
  async inspect(name: string, context: NativeOperationContext): Promise<NativeProfileSnapshot | null> {
    return this.locked(name, context, () => this.load(name, context));
  }
  async enroll(options: { readonly name: string; readonly apiOrigin: string; readonly allowHttpLoopback?: boolean; readonly key: string },
    context: NativeOperationContext): Promise<NativeProfileRecord> {
    return this.locked(options.name, context, async () => {
      const apiOrigin = origin(options.apiOrigin, options.allowHttpLoopback ?? false);
      if (await this.load(options.name, context) !== null) fail('profile_exists');
      const key = keyChecked(options.key);
      const identity = await this.identity(null, apiOrigin, key, false, context);
      const record = recordDecoded({ format_version: 2, name: options.name, store_id: this.storeId, api_origin: apiOrigin,
        project_id: identity.project_id, organization_id: identity.organization_id, key_id: identity.key_id,
        allow_http_loopback: options.allowHttpLoopback ?? false, state: 'ready', profile_id: this.id(), credential_ref: this.id() }, options.name, this.storeId);
      if (reflected(record, key)) fail('profile_invalid_input');
      // The namespace lease serializes cooperating writers. Never upsert or
      // claim cleanup ownership of a known prior native entry on collision.
      if ((await this.read(record, context)).status !== 'absent') fail('profile_store_mismatch');
      const journal: NativeProfileJournal = Object.freeze({ format_version: 1, transaction_id: this.id(), operation: 'enroll', phase: 'intent', desired: record });
      const intent = this.snapshot(options.name, null, journal);
      await this.publish(options.name, null, intent, context);
      try {
        this.active(context);
        let written: unknown;
        try { written = await this.ports.store.write(Object.freeze({ profile_id: record.profile_id, credential_ref: record.credential_ref }), key, context); }
        catch { fail('profile_write_unknown', true); }
        this.active(context);
        if (written !== 'stored') fail('profile_write_unknown', true);
        const readback = await this.read(record, context);
        if (readback.status !== 'present' || readback.key !== key) fail('profile_store_mismatch', true);
        const committed = this.snapshot(options.name, record, Object.freeze({ ...journal, phase: 'committed' }));
        await this.publish(options.name, intent, committed, context);
        await this.publish(options.name, committed, this.snapshot(options.name, record, null), context);
        return record;
      } catch (error) {
        throw new NativeProfileTransactionError(error instanceof NativeProfileTransactionError ? error.code : 'profile_write_unknown', true);
      }
    });
  }
  private async cleanup(name: string, snapshot: NativeProfileSnapshot, context: NativeOperationContext): Promise<NativeProfileRecord> {
    const journal = snapshot.journal;
    if (!journal || journal.phase !== 'intent') fail('profile_invalid_metadata');
    const target = journal.desired;
    try {
      const before = await this.read(target, context);
      if (before.status === 'present') {
        this.active(context);
        let deleted: unknown;
        try { deleted = await this.ports.store.delete(Object.freeze({ profile_id: target.profile_id, credential_ref: target.credential_ref }), context); }
        catch { fail('profile_delete_unknown', true); }
        this.active(context);
        if (deleted !== 'deleted' && deleted !== 'absent') fail('profile_delete_unknown', true);
        if ((await this.read(target, context)).status !== 'absent') fail('profile_delete_unknown', true);
      }
      const removed = recordDecoded({ ...target, state: 'removed' }, name, this.storeId);
      await this.publish(name, snapshot, this.snapshot(name, removed, null), context);
      return removed;
    } catch (error) {
      throw new NativeProfileTransactionError(error instanceof NativeProfileTransactionError ? error.code : 'profile_delete_unknown', true);
    }
  }
  async remove(name: string, context: NativeOperationContext): Promise<NativeProfileRecord> {
    return this.locked(name, context, async () => {
      const snapshot = await this.load(name, context);
      if (!snapshot) fail('profile_not_found');
      if (snapshot.journal?.phase === 'intent') return this.cleanup(name, snapshot, context);
      const record = snapshot.record;
      if (!record) fail('profile_invalid_metadata');
      if (record.state === 'removed') return record;
      const disabled = recordDecoded({ ...record, state: 'disabled' }, name, this.storeId);
      const journal: NativeProfileJournal = Object.freeze({ format_version: 1, transaction_id: this.id(), operation: 'remove', phase: 'intent', desired: disabled });
      const intent = this.snapshot(name, disabled, journal);
      await this.publish(name, snapshot, intent, context);
      return this.cleanup(name, intent, context);
    });
  }
  async recover(name: string, context: NativeOperationContext): Promise<NativeProfileRecord> {
    return this.locked(name, context, async () => {
      const snapshot = await this.load(name, context);
      if (!snapshot) fail('profile_not_found');
      if (snapshot.journal?.phase === 'intent') return this.cleanup(name, snapshot, context);
      const record = snapshot.record;
      if (!record) fail('profile_invalid_metadata');
      if (record.state === 'removed') return record;
      try {
        const readback = await this.read(record, context);
        if (readback.status === 'absent') fail('profile_store_absent');
        const key = keyChecked(readback.key);
        if (reflected(record, key)) fail('profile_invalid_metadata');
        await this.identity(record, record.api_origin, key, true, context);
        if (snapshot.journal) await this.publish(name, snapshot, this.snapshot(name, record, null), context);
        return record;
      } catch (error) {
        if (snapshot.journal && error instanceof NativeProfileTransactionError) {
          throw new NativeProfileTransactionError(error.code, true);
        }
        throw error;
      }
    });
  }
  async withCredential<T>(name: string, options: NativeSelectionOptions, context: NativeOperationContext,
    /** Return already-sanitized success/business-failure values; thrown failures
     * are opaque. Real business-error integration is a separate qualification. */
    action: (credential: NativeResolvedCredential, context: NativeOperationContext) => Promise<T>): Promise<T> {
    let actionEntered = false;
    try { return await this.locked(name, context, async () => {
      const snapshot = await this.load(name, context);
      if (!snapshot) fail('profile_not_found');
      if (snapshot.journal) fail('profile_pending_recovery', true);
      const record = snapshot.record;
      if (!record || record.state !== 'ready') fail('profile_disabled');
      const selection = plain(options);
      if (Object.keys(selection).some(field => !['environmentKey', 'apiOriginOverride', 'expectedBinding'].includes(field))) fail('profile_invalid_input');
      if (Object.hasOwn(selection, 'apiOriginOverride') && origin(selection.apiOriginOverride, record.allow_http_loopback) !== record.api_origin) fail('profile_origin_mismatch');
      if (Object.hasOwn(selection, 'expectedBinding')) {
        const expected = exact(selection.expectedBinding, ['profile_id', 'api_origin', 'project_id', 'organization_id']);
        if (Object.keys(expected).some(field => expected[field] !== record[field as keyof NativeProfileRecord])) fail('profile_binding_mismatch');
      }
      const fromEnvironment = Object.hasOwn(selection, 'environmentKey');
      let key: string;
      if (fromEnvironment) key = keyChecked(selection.environmentKey);
      else {
        const stored = await this.read(record, context);
        if (stored.status === 'absent') fail('profile_store_absent');
        key = keyChecked(stored.key);
      }
      if (reflected(record, key)) fail('profile_invalid_metadata');
      const identity = await this.identity(record, record.api_origin, key, !fromEnvironment, context);
      this.active(context);
      let value: T;
      try {
        const credential = { apiOrigin: record.api_origin,
          source: fromEnvironment ? 'environment' as const : 'store' as const, identity, profile: record } as NativeResolvedCredential;
        Object.defineProperty(credential, 'apiKey', { value: key, enumerable: false });
        actionEntered = true;
        value = await action(Object.freeze(credential), context);
      } catch { throw new NativeProfileTransactionError('profile_operation_failed', false, true); }
      try { this.active(context); }
      catch (error) { throw new NativeProfileTransactionError((error as NativeProfileTransactionError).code, false, true); }
      return value;
    }); } catch (error) {
      if (error instanceof NativeProfileTransactionError && actionEntered && !error.operation_may_have_executed) {
        throw new NativeProfileTransactionError(error.code, error.recovery_required, true);
      }
      throw error;
    }
  }
}
