/** Fixed delegated SQLite cohort. No secret payload is stored in this database. */
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { types } from 'node:util';
import type { NativeOperationContext } from './native-profile-transaction.js';
import type { WindowsSnapshotBinding, WindowsMetadataSnapshotBinding, WindowsSnapshotFiles, WindowsSnapshotGuard } from './windows-snapshot-contract.js';
import { qualifyWindowsSnapshotRuntime } from './windows-native-snapshots.js';
import { WINDOWS_NATIVE_STORE_ID } from './windows-native-lease.js';
import { DELEGATED_NATIVE_STORE_ID, DELEGATED_NATIVE_DATABASE, DELEGATED_NATIVE_APPLICATION_ID, DELEGATED_NATIVE_VERSION,
  DELEGATED_NATIVE_PAGE_SIZE, DELEGATED_NATIVE_MAX_DATABASE_BYTES, DELEGATED_NATIVE_MAX_RECORDS, DELEGATED_NATIVE_MAX_RECORD_BYTES } from './delegated-native-contract.js';
import { delegatedNativeName, decodeDelegatedNativeProfileBytes, encodeDelegatedNativeProfile, type DelegatedNativeProfileRecord } from './delegated-native-state.js';
import { delegatedFamilyKey, familyObject, familyUuid, familyFail, decodeDelegatedFamilySnapshotBytes,
  encodeDelegatedFamilySnapshot, type DelegatedFamilyKey, type DelegatedFamilySnapshot } from './delegated-family-state.js';

export type DelegatedNativeRecordKey = Readonly<{ kind: 'profile'; name: string }> | Readonly<{ kind: 'family'; key: DelegatedFamilyKey }>;
interface Statement { get(...values: unknown[]): unknown; all(...values: unknown[]): unknown[]; iterate(...values: unknown[]): Iterable<unknown>; run(...values: unknown[]): { changes: number | bigint } }
interface Database { readonly isTransaction: boolean; exec(sql: string): void; prepare(sql: string): Statement; close(): void; enableDefensive?(value: boolean): void }
interface Observation { readonly keyJson: string; readonly revision: string | null; readonly bytes: Uint8Array | null }
const metadataSql = 'CREATE TABLE delegated_store (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL CHECK(format_version=1), store_id TEXT NOT NULL, current_sid TEXT NOT NULL) STRICT';
const recordsSql = 'CREATE TABLE delegated_records (record_key TEXT PRIMARY KEY NOT NULL CHECK(length(record_key)=64 AND record_key NOT GLOB \'*[^a-f0-9]*\'), key_json TEXT NOT NULL CHECK(length(CAST(key_json AS BLOB)) BETWEEN 1 AND 4096), kind TEXT NOT NULL CHECK(kind IN (\'profile\',\'family\')), revision TEXT NOT NULL CHECK(length(revision)=36), snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 98304)) STRICT, WITHOUT ROWID';
function refuse(): never { return familyFail('metadata_unknown', true); }
function row(value: unknown): Record<string, unknown> {
  try { if (!value || typeof value !== 'object' || types.isProxy(value)) return refuse();
    return familyObject(value, Reflect.ownKeys(value) as string[]); } catch { return refuse(); }
}
function pragma(database: Database, name: string): unknown {
  const item = row(database.prepare(`PRAGMA ${name}`).get()); const keys = Object.keys(item); if (keys.length !== 1) return refuse(); return item[keys[0]!];
}
export function delegatedNativeRecordKey(value: unknown): DelegatedNativeRecordKey {
  const item = familyObject(value, ['kind'], ['name', 'key']);
  if (item.kind === 'profile' && Object.hasOwn(item, 'name') && !Object.hasOwn(item, 'key')) return Object.freeze({ kind: item.kind, name: delegatedNativeName(item.name) });
  if (item.kind === 'family' && Object.hasOwn(item, 'key') && !Object.hasOwn(item, 'name')) {
    const key = delegatedFamilyKey(item.key); if (key.storeId !== DELEGATED_NATIVE_STORE_ID) return familyFail('invalid_input');
    return Object.freeze({ kind: item.kind, key });
  }
  return familyFail('invalid_input');
}
export function delegatedNativeLeaseName(value: DelegatedNativeRecordKey): string {
  return createHash('sha256').update('bota.delegated-native.record.v1\0').update(JSON.stringify(delegatedNativeRecordKey(value))).digest('hex');
}
function decode(value: Uint8Array, key: DelegatedNativeRecordKey): DelegatedNativeProfileRecord | DelegatedFamilySnapshot {
  return key.kind === 'profile' ? decodeDelegatedNativeProfileBytes(value, key.name) : decodeDelegatedFamilySnapshotBytes(value, key.key);
}
function encode(value: unknown, key: DelegatedNativeRecordKey): Uint8Array {
  return key.kind === 'profile' ? encodeDelegatedNativeProfile(value, key.name) : encodeDelegatedFamilySnapshot(value, key.key);
}
function same(left: Uint8Array | null, right: Uint8Array | null): boolean { return left === null || right === null ? left === right : Buffer.from(left).equals(Buffer.from(right)); }
const nativeAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
function active(context: NativeOperationContext): void {
  let signal: AbortSignal, assertion: () => void, budget: object;
  try { const value = familyObject(context, ['signal', 'budget']);
    if (types.isProxy(value.signal) || !value.budget || typeof value.budget !== 'object' || types.isProxy(value.budget)) return refuse();
    nativeAborted.call(value.signal); signal = value.signal as AbortSignal; budget = value.budget;
    const field = Object.getOwnPropertyDescriptor(budget, 'assertActive');
    if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'function' || types.isProxy(field.value)) return refuse(); assertion = field.value;
  } catch { return refuse(); }
  if (nativeAborted.call(signal)) return familyFail('cancelled');
  try { Reflect.apply(assertion, budget, []); } catch { return familyFail('deadline'); }
  if (nativeAborted.call(signal)) return familyFail('cancelled');
}
function selected(database: Database, key: DelegatedNativeRecordKey): Observation {
  const keyJson = JSON.stringify(key), found = database.prepare('SELECT key_json,kind,revision,snapshot FROM delegated_records WHERE record_key=?').get(delegatedNativeLeaseName(key));
  if (found === undefined) return Object.freeze({ keyJson, revision: null, bytes: null });
  const item = row(found);
  if (item.key_json !== keyJson || item.kind !== key.kind || !familyUuid(item.revision) || types.isProxy(item.snapshot) || !types.isUint8Array(item.snapshot)
    || item.snapshot.byteLength > DELEGATED_NATIVE_MAX_RECORD_BYTES) return refuse();
  const bytes = Uint8Array.from(item.snapshot); if (decode(bytes, key).revision !== item.revision) return refuse();
  return Object.freeze({ keyJson, revision: item.revision, bytes });
}
function configure(database: Database): void {
  database.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA trusted_schema=OFF; PRAGMA synchronous=EXTRA; PRAGMA journal_mode=PERSIST; PRAGMA busy_timeout=0; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA journal_size_limit=-1; PRAGMA ignore_check_constraints=OFF;');
  for (const [name, expected] of [['locking_mode', 'exclusive'], ['journal_mode', 'persist'], ['synchronous', 3], ['trusted_schema', 0], ['mmap_size', 0], ['temp_store', 2], ['journal_size_limit', -1], ['ignore_check_constraints', 0]] as const)
    if (pragma(database, name) !== expected) return refuse();
  const pages = DELEGATED_NATIVE_MAX_DATABASE_BYTES / DELEGATED_NATIVE_PAGE_SIZE; database.exec(`PRAGMA max_page_count=${pages}`);
  if (pragma(database, 'max_page_count') !== pages) return refuse();
}
function verify(database: Database, sid: string): void {
  if (pragma(database, 'application_id') !== DELEGATED_NATIVE_APPLICATION_ID || pragma(database, 'user_version') !== DELEGATED_NATIVE_VERSION
    || pragma(database, 'page_size') !== DELEGATED_NATIVE_PAGE_SIZE || pragma(database, 'quick_check') !== 'ok') return refuse();
  const schemaBounds = row(database.prepare('SELECT count(*) AS total,coalesce(max(length(CAST(sql AS BLOB))),0) AS sql_length,coalesce(max(length(CAST(name AS BLOB))),0) AS name_length FROM sqlite_schema').get());
  if (schemaBounds.total !== 2 || typeof schemaBounds.sql_length !== 'number' || schemaBounds.sql_length > 2048
    || typeof schemaBounds.name_length !== 'number' || schemaBounds.name_length > 64) return refuse();
  const schema = database.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 3').all().map(row);
  if (schema.length !== 2 || schema[0]?.type !== 'table' || schema[0]?.name !== 'delegated_records' || schema[0]?.tbl_name !== 'delegated_records'
    || schema[0]?.sql !== recordsSql || schema[1]?.type !== 'table' || schema[1]?.name !== 'delegated_store'
    || schema[1]?.tbl_name !== 'delegated_store' || schema[1]?.sql !== metadataSql) return refuse();
  const metadataBounds = row(database.prepare('SELECT count(*) AS total,max(length(CAST(store_id AS BLOB))) AS store_length,max(length(CAST(current_sid AS BLOB))) AS sid_length FROM delegated_store').get());
  if (metadataBounds.total !== 1 || metadataBounds.store_length !== DELEGATED_NATIVE_STORE_ID.length || metadataBounds.sid_length !== sid.length) return refuse();
  const metadata = database.prepare('SELECT * FROM delegated_store LIMIT 2').all().map(row);
  if (metadata.length !== 1 || metadata[0]?.singleton !== 1 || metadata[0]?.format_version !== 1
    || metadata[0]?.store_id !== DELEGATED_NATIVE_STORE_ID || metadata[0]?.current_sid !== sid) return refuse();
  const count = row(database.prepare('SELECT count(*) AS total FROM delegated_records').get()).total;
  if (typeof count !== 'number' || count < 0 || count > DELEGATED_NATIVE_MAX_RECORDS || !Number.isInteger(count)) return refuse();
  for (const value of database.prepare('SELECT typeof(record_key) AS kt,length(CAST(record_key AS BLOB)) AS kl,typeof(key_json) AS jt,length(CAST(key_json AS BLOB)) AS jl,typeof(kind) AS t,length(CAST(kind AS BLOB)) AS l,typeof(revision) AS rt,length(CAST(revision AS BLOB)) AS rl,typeof(snapshot) AS bt,length(snapshot) AS bl FROM delegated_records LIMIT 2049').iterate()) {
    const item = row(value); if (item.kt !== 'text' || item.kl !== 64 || item.jt !== 'text' || typeof item.jl !== 'number' || item.jl < 1 || item.jl > 4096
      || item.t !== 'text' || typeof item.l !== 'number' || item.l < 1 || item.l > 7 || item.rt !== 'text' || item.rl !== 36
      || item.bt !== 'blob' || typeof item.bl !== 'number' || item.bl < 1 || item.bl > DELEGATED_NATIVE_MAX_RECORD_BYTES) return refuse();
  }
  for (const value of database.prepare('SELECT record_key,key_json,kind,revision,snapshot FROM delegated_records LIMIT 2049').iterate()) {
    const item = row(value);
    if (typeof item.key_json !== 'string' || Buffer.byteLength(item.key_json) > 4096 || !familyUuid(item.revision)
      || types.isProxy(item.snapshot) || !types.isUint8Array(item.snapshot) || item.snapshot.byteLength < 1 || item.snapshot.byteLength > DELEGATED_NATIVE_MAX_RECORD_BYTES) return refuse();
    const key = delegatedNativeRecordKey(JSON.parse(item.key_json));
    if (JSON.stringify(key) !== item.key_json || delegatedNativeLeaseName(key) !== item.record_key || key.kind !== item.kind
      || decode(item.snapshot, key).revision !== item.revision) return refuse();
  }
}
/** The only production guard is root-owned and pins the two CLOSED delegated
 * filenames. Injected guards are explicit synthetic test authority. */
export class DelegatedNativeSnapshots {
  private poisoned = false;
  private readonly observations = new WeakMap<WindowsSnapshotBinding, Map<string, Observation>>();
  private readonly uncertain = new WeakSet<WindowsSnapshotBinding>();
  constructor(private readonly guard: WindowsSnapshotGuard) {}
  private current(binding: WindowsSnapshotBinding, context: NativeOperationContext): void {
    try { if (this.poisoned || this.uncertain.has(binding) || this.guard.assertCurrentAccess(context) !== binding) return refuse(); active(context); }
    catch { return refuse(); }
  }
  private binding(key: DelegatedNativeRecordKey, context: NativeOperationContext): WindowsSnapshotBinding {
    try { active(context); const binding = this.guard.assertCurrentAccess(context);
      if (binding.storeId !== WINDOWS_NATIVE_STORE_ID || Object.hasOwn(binding, 'metadataOnly') || binding.name !== delegatedNativeLeaseName(key)) return refuse();
      this.current(binding, context); return binding;
    } catch { return refuse(); }
  }
  private closeDatabase(database: Database): void { try { database.close(); } catch { this.poisoned = true; return refuse(); } }
  private database(binding: { readonly rootDirectory: string }, files: WindowsSnapshotFiles): Database {
    qualifyWindowsSnapshotRuntime();
    if (typeof files.currentSid !== 'string' || files.currentSid.length > 184 || !/^S-1-(?:\d+-){1,15}\d+$/.test(files.currentSid)) return refuse();
    const header = files.databaseHeader;
    if (types.isProxy(header) || !types.isUint8Array(header)) return refuse();
    const bytes = Buffer.from(header);
    if (files.fresh ? bytes.length !== 0 : bytes.length !== 100 || bytes.subarray(0, 16).toString('binary') !== 'SQLite format 3\0'
      || bytes.readUInt16BE(16) !== DELEGATED_NATIVE_PAGE_SIZE || bytes[18] !== 1 || bytes[19] !== 1
      || bytes.readUInt32BE(60) !== DELEGATED_NATIVE_VERSION || bytes.readUInt32BE(68) !== DELEGATED_NATIVE_APPLICATION_ID) return refuse();
    const DatabaseSync = (createRequire(import.meta.url)('node:sqlite') as { DatabaseSync: new (filename: string, options: Record<string, unknown>) => Database }).DatabaseSync;
    const filename = path.win32.join(binding.rootDirectory, DELEGATED_NATIVE_DATABASE);
    if (!files.fresh) {
      const read = new DatabaseSync(filename, { readOnly: true, allowExtension: false, enableDoubleQuotedStringLiterals: false, timeout: 0 });
      try { read.enableDefensive?.(true); read.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON'); verify(read, files.currentSid); }
      catch (error) {
        // Only the exact admitted header can authorize this pinned SQLite's
        // ordinary hot-journal recovery; never follow another database path.
        const field = error && typeof error === 'object' && !types.isProxy(error) ? Object.getOwnPropertyDescriptor(error, 'errcode') : undefined;
        if (!field || !Object.hasOwn(field, 'value') || field.value !== 776) throw error;
      } finally { this.closeDatabase(read); }
    }
    const database = new DatabaseSync(filename, { allowExtension: false, enableDoubleQuotedStringLiterals: false, timeout: 0 });
    try {
      database.enableDefensive?.(true); configure(database);
      if (files.fresh) {
        database.exec('BEGIN IMMEDIATE');
        try { database.exec(`${metadataSql}; ${recordsSql}; PRAGMA application_id=${DELEGATED_NATIVE_APPLICATION_ID}; PRAGMA user_version=${DELEGATED_NATIVE_VERSION}`);
          database.prepare('INSERT INTO delegated_store VALUES(1,1,?,?)').run(DELEGATED_NATIVE_STORE_ID, files.currentSid); database.exec('COMMIT'); }
        catch (error) { if (database.isTransaction) database.exec('ROLLBACK'); throw error; }
      }
      verify(database, files.currentSid); return database;
    } catch (error) { this.closeDatabase(database); throw error; }
  }
  private async read(key: DelegatedNativeRecordKey, binding: WindowsSnapshotBinding, context: NativeOperationContext, observe: boolean): Promise<unknown> {
    let database: Database | undefined, files: WindowsSnapshotFiles | undefined, result: Observation | undefined, failed = false;
    try { this.current(binding, context); files = this.guard.open(binding, context); this.current(binding, context);
      database = this.database(binding, files); files.validate(); this.current(binding, context); result = selected(database, key); }
    catch { failed = true; }
    finally { try { if (database) this.closeDatabase(database); } catch { failed = true; }
      try { files?.validate(); } catch { failed = true; } try { files?.close(); } catch { this.poisoned = true; failed = true; } }
    if (failed || !result) return refuse(); this.current(binding, context);
    if (observe) { let observations = this.observations.get(binding); if (!observations) { observations = new Map(); this.observations.set(binding, observations); } observations.set(delegatedNativeLeaseName(key), result); }
    return result.bytes === null ? null : decode(result.bytes, key);
  }
  async load(value: DelegatedNativeRecordKey, context: NativeOperationContext): Promise<unknown> {
    const key = delegatedNativeRecordKey(value), binding = this.binding(key, context);
    this.observations.get(binding)?.delete(delegatedNativeLeaseName(key)); return this.read(key, binding, context, true);
  }
  /** Trusted adoption/removal may inspect one related family while holding the
   * selected profile and common namespace; it gains NO family CAS observation. */
  async readRelatedFamily(name: string, family: DelegatedFamilyKey, context: NativeOperationContext): Promise<unknown> {
    const selected = delegatedNativeRecordKey({ kind: 'profile', name }), key = delegatedNativeRecordKey({ kind: 'family', key: family });
    return this.read(key, this.binding(selected, context), context, false);
  }
  async publish(value: DelegatedNativeRecordKey, expectedRevision: string | null, next: unknown, context: NativeOperationContext): Promise<'committed' | 'not_committed' | 'unknown'> {
    let binding: WindowsSnapshotBinding | undefined, files: WindowsSnapshotFiles | undefined, database: Database | undefined;
    let submitted = false, changed = false, outcome: 'committed' | 'not_committed' | 'unknown' = 'not_committed', previous: Observation | undefined;
    let selectedKey: DelegatedNativeRecordKey | undefined;
    try {
      const key = delegatedNativeRecordKey(value); selectedKey = key; binding = this.binding(key, context); const digest = delegatedNativeLeaseName(key);
      previous = this.observations.get(binding)?.get(digest); if (!previous || previous.revision !== expectedRevision || expectedRevision !== null && !familyUuid(expectedRevision)) return refuse();
      const bytes = encode(next, key), revision = decode(bytes, key).revision; if (revision === expectedRevision) return refuse();
      files = this.guard.open(binding, context); if (files.fresh) return refuse(); database = this.database(binding, files); this.current(binding, context); files.validate();
      database.exec('BEGIN IMMEDIATE'); const found = selected(database, key);
      if (found.revision !== previous.revision || !same(found.bytes, previous.bytes)) return refuse(); this.current(binding, context); changed = true;
      const write = previous.revision === null
        ? database.prepare('INSERT INTO delegated_records(record_key,key_json,kind,revision,snapshot) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM delegated_records)<?').run(digest, JSON.stringify(key), key.kind, revision, bytes, DELEGATED_NATIVE_MAX_RECORDS)
        : database.prepare('UPDATE delegated_records SET revision=?,snapshot=? WHERE record_key=? AND key_json=? AND revision=? AND snapshot=?').run(revision, bytes, digest, JSON.stringify(key), previous.revision, previous.bytes);
      if (write.changes !== 1 && write.changes !== 1n) return refuse(); this.current(binding, context); files.validate(); submitted = true; database.exec('COMMIT');
      const readback = selected(database, key); if (readback.revision !== revision || !same(readback.bytes, bytes)) return refuse();
      verify(database, files.currentSid); files.validate(); this.current(binding, context); this.observations.get(binding)!.set(digest, readback); outcome = 'committed';
    } catch { outcome = submitted ? 'unknown' : 'not_committed'; }
    finally {
      if (database?.isTransaction) { try { database.exec('ROLLBACK'); } catch { outcome = 'unknown'; } }
      if (!submitted && changed && database && previous && selectedKey) { try {
        const readback = selected(database, selectedKey); if (readback.revision !== previous.revision || !same(readback.bytes, previous.bytes)) outcome = 'unknown';
      } catch { outcome = 'unknown'; } }
      try { if (database) this.closeDatabase(database); } catch { outcome = 'unknown'; }
      try { files?.validate(); } catch { outcome = 'unknown'; } try { files?.close(); } catch { this.poisoned = true; outcome = 'unknown'; }
    }
    if (binding) {
      if (outcome === 'unknown') { this.observations.delete(binding); this.uncertain.add(binding); }
      else if (outcome === 'committed') { try { this.current(binding, context); } catch { this.uncertain.add(binding); return 'unknown'; } }
    }
    return outcome;
  }
  async list(context: NativeOperationContext): Promise<readonly DelegatedNativeProfileRecord[]> {
    let binding: WindowsMetadataSnapshotBinding | undefined, files: WindowsSnapshotFiles | null | undefined, database: Database | undefined, failed = false;
    const output: DelegatedNativeProfileRecord[] = [];
    const current = () => { if (this.poisoned || !binding || this.guard.assertCurrentMetadataAccess(context) !== binding) return refuse(); active(context); };
    try { binding = this.guard.assertCurrentMetadataAccess(context); if (binding.storeId !== WINDOWS_NATIVE_STORE_ID || binding.metadataOnly !== true) return refuse(); current();
      files = this.guard.openMetadata(binding, context); current();
      if (files) { if (files.fresh) return refuse(); database = this.database(binding, files); database.exec('PRAGMA query_only=ON'); if (pragma(database, 'query_only') !== 1) return refuse(); database.exec('BEGIN');
        for (const item of database.prepare("SELECT key_json,snapshot FROM delegated_records WHERE kind='profile' ORDER BY record_key LIMIT 2049").iterate()) {
          const value = row(item); if (output.length >= DELEGATED_NATIVE_MAX_RECORDS || typeof value.key_json !== 'string' || !types.isUint8Array(value.snapshot)) return refuse();
          const key = delegatedNativeRecordKey(JSON.parse(value.key_json)); if (key.kind !== 'profile') return refuse(); output.push(decodeDelegatedNativeProfileBytes(value.snapshot, key.name)); current();
        } database.exec('COMMIT'); files.validate(); current(); }
    } catch { failed = true; }
    finally { if (database?.isTransaction) { try { database.exec('ROLLBACK'); } catch { failed = true; } }
      try { if (database) this.closeDatabase(database); } catch { failed = true; } try { files?.validate(); } catch { failed = true; }
      try { files?.close(); } catch { this.poisoned = true; failed = true; } }
    if (failed) return refuse(); current(); return Object.freeze(output.sort((left, right) => left.name.localeCompare(right.name)));
  }
}
