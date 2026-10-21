/** Windows SQLite snapshot persistence. No credential, CLI or provider wiring. */
import { createRequire } from 'node:module';
import path from 'node:path';
import { types } from 'node:util';
import { decodeNativeProfileSnapshotBytes, encodeNativeProfileSnapshot, NATIVE_PROFILE_MAX_SNAPSHOT_BYTES } from './native-profile-codec.js';
import { NativeProfileTransactionError, type NativeOperationContext, type NativeProfileSnapshot, type NativeSnapshotPort } from './native-profile-transaction.js';
import { WINDOWS_SNAPSHOT_APPLICATION_ID, WINDOWS_SNAPSHOT_DATABASE, WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES,
  WINDOWS_SNAPSHOT_MAX_PROFILES, WINDOWS_SNAPSHOT_PAGE_SIZE, WINDOWS_SNAPSHOT_VERSION,
  type WindowsSnapshotBinding, type WindowsMetadataSnapshotBinding, type WindowsSnapshotFiles, type WindowsSnapshotGuard } from './windows-snapshot-contract.js';
import type { WindowsNativeLease } from './windows-native-lease.js';

interface Statement {
  get(...values: unknown[]): unknown;
  all(...values: unknown[]): unknown[];
  iterate(...values: unknown[]): Iterable<unknown>;
  run(...values: unknown[]): { changes: number | bigint };
}
interface Database {
  readonly isTransaction: boolean;
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
  enableDefensive?(active: boolean): void;
}
interface SqliteModule {
  DatabaseSync: new (filename: string, options: { readOnly?: boolean; allowExtension: false;
    enableDoubleQuotedStringLiterals: false; timeout: 0 }) => Database;
}
interface Observation { readonly revision: string | null; readonly bytes: Uint8Array | null }
const STORE = 'windows-credential-manager';
const metadataSql = 'CREATE TABLE native_profile_store (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL CHECK(format_version=1), store_id TEXT NOT NULL, current_sid TEXT NOT NULL) STRICT';
const profilesSql = 'CREATE TABLE native_profiles (name TEXT PRIMARY KEY NOT NULL CHECK(length(name) BETWEEN 1 AND 64 AND name NOT GLOB \'*[^a-z0-9-]*\'), revision TEXT NOT NULL CHECK(length(revision)=36), snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 24576)) STRICT, WITHOUT ROWID';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
let runtimePoisoned = false;
function fail(): never { throw new NativeProfileTransactionError('profile_busy'); }
function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  return value as Record<string, unknown>;
}
function pragma(db: Database, name: string): unknown {
  const data = row(db.prepare(`PRAGMA ${name}`).get());
  if (Object.keys(data).length !== 1) fail();
  return Object.values(data)[0];
}
function same(a: Uint8Array | null, b: Uint8Array | null): boolean {
  return a === null || b === null ? a === b : Buffer.from(a).equals(Buffer.from(b));
}
function active(context: NativeOperationContext): void {
  if (!(context.signal instanceof AbortSignal) || !context.budget || typeof context.budget.assertActive !== 'function') fail();
  if (context.signal.aborted) throw new NativeProfileTransactionError('profile_cancelled');
  try { context.budget.assertActive(); } catch { throw new NativeProfileTransactionError('profile_deadline'); }
}
function header(files: WindowsSnapshotFiles): void {
  const input = files.databaseHeader;
  if (!(input instanceof Uint8Array) || types.isProxy(input) || types.isSharedArrayBuffer(input.buffer)) fail();
  const bytes = Buffer.from(input);
  if (files.fresh) { if (bytes.length !== 0) fail(); return; }
  if (bytes.length !== 100 || bytes.subarray(0, 16).toString('binary') !== 'SQLite format 3\0'
    || bytes.readUInt16BE(16) !== WINDOWS_SNAPSHOT_PAGE_SIZE || bytes[18] !== 1 || bytes[19] !== 1
    || bytes[20] !== 0 || bytes[21] !== 64 || bytes[22] !== 32 || bytes[23] !== 32
    || bytes.readUInt32BE(60) !== WINDOWS_SNAPSHOT_VERSION
    || bytes.readUInt32BE(68) !== WINDOWS_SNAPSHOT_APPLICATION_ID) fail();
}
function sqlite(close: (database: Database) => void): SqliteModule {
  if (runtimePoisoned) fail();
  // Built-in only. Requiring it here preserves the Node 22 experimental warning
  // and avoids evaluating this optional cohort for ordinary CLI commands.
  const module = createRequire(import.meta.url)('node:sqlite') as SqliteModule;
  if (typeof module.DatabaseSync !== 'function') fail();
  const expected = process.version === 'v22.23.2'
    ? '2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618'
    : process.version === 'v24.19.0'
      ? '2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62' : null;
  if (process.platform !== 'win32' || !expected) fail();
  const check = new module.DatabaseSync(':memory:', { allowExtension: false, enableDoubleQuotedStringLiterals: false, timeout: 0 });
  try { if (row(check.prepare('SELECT sqlite_source_id() AS id').get()).id !== expected) fail(); }
  finally { close(check); }
  return module;
}
/** In-memory qualification only. Production must call this before opening or
 * creating the canonical root; unsupported runtimes must leave no empty pair.
 * Uncertain qualification close retires SQLite admission for this process. */
export function qualifyWindowsSnapshotRuntime(): void {
  try { sqlite(database => {
    try { database.close(); }
    catch { runtimePoisoned = true; fail(); }
  }); }
  catch { fail(); }
}
function configure(db: Database): void {
  // EXCLUSIVE must precede schema-reading pragmas: recovery otherwise starts
  // with DELETE mode and may try to unlink the pinned persistent journal.
  db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA trusted_schema=OFF; PRAGMA synchronous=EXTRA; PRAGMA journal_mode=PERSIST; PRAGMA busy_timeout=0; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA journal_size_limit=-1; PRAGMA ignore_check_constraints=OFF;');
  if (pragma(db, 'locking_mode') !== 'exclusive' || pragma(db, 'journal_mode') !== 'persist'
    || pragma(db, 'synchronous') !== 3 || pragma(db, 'trusted_schema') !== 0
    || pragma(db, 'mmap_size') !== 0 || pragma(db, 'temp_store') !== 2
    || pragma(db, 'journal_size_limit') !== -1 || pragma(db, 'ignore_check_constraints') !== 0) fail();
  const limit = WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES / WINDOWS_SNAPSHOT_PAGE_SIZE;
  db.exec(`PRAGMA max_page_count=${limit}`);
  if (pragma(db, 'max_page_count') !== limit) fail();
}
function initialize(db: Database, sid: string): void {
  if (pragma(db, 'page_size') !== WINDOWS_SNAPSHOT_PAGE_SIZE) fail();
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(`${metadataSql}; ${profilesSql}; PRAGMA application_id=${WINDOWS_SNAPSHOT_APPLICATION_ID}; PRAGMA user_version=${WINDOWS_SNAPSHOT_VERSION}`);
    db.prepare('INSERT INTO native_profile_store VALUES(1,1,?,?)').run(STORE, sid);
    db.exec('COMMIT');
  } catch { if (db.isTransaction) { try { db.exec('ROLLBACK'); } catch { /* Retain exact files. */ } } fail(); }
}
function verify(db: Database, sid: string): void {
  if (pragma(db, 'application_id') !== WINDOWS_SNAPSHOT_APPLICATION_ID
    || pragma(db, 'user_version') !== WINDOWS_SNAPSHOT_VERSION
    || pragma(db, 'page_size') !== WINDOWS_SNAPSHOT_PAGE_SIZE) fail();
  const schemaShape = row(db.prepare('SELECT count(*) AS total,coalesce(max(length(CAST(type AS BLOB))),0) AS type_length,coalesce(max(length(CAST(sql AS BLOB))),0) AS sql_length,coalesce(max(length(CAST(name AS BLOB))),0) AS name_length,coalesce(max(length(CAST(tbl_name AS BLOB))),0) AS table_length FROM sqlite_schema').get());
  if (schemaShape.total !== 2 || typeof schemaShape.sql_length !== 'number' || schemaShape.sql_length > 2048
    || typeof schemaShape.name_length !== 'number' || schemaShape.name_length > 64
    || typeof schemaShape.table_length !== 'number' || schemaShape.table_length > 64
    || typeof schemaShape.type_length !== 'number' || schemaShape.type_length > 7) fail();
  const schema = db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 3').all().map(row);
  if (schema.length !== 2 || schema[0]?.type !== 'table' || schema[0]?.name !== 'native_profile_store'
    || schema[0]?.tbl_name !== 'native_profile_store' || schema[0]?.sql !== metadataSql
    || schema[1]?.type !== 'table' || schema[1]?.name !== 'native_profiles'
    || schema[1]?.tbl_name !== 'native_profiles' || schema[1]?.sql !== profilesSql) fail();
  const metadataShape = row(db.prepare('SELECT count(*) AS total,min(typeof(store_id)) AS store_type,min(length(CAST(store_id AS BLOB))) AS store_length,max(length(CAST(store_id AS BLOB))) AS max_store_length,min(typeof(current_sid)) AS sid_type,min(length(CAST(current_sid AS BLOB))) AS sid_length,max(length(CAST(current_sid AS BLOB))) AS max_sid_length FROM native_profile_store').get());
  if (metadataShape.total !== 1 || metadataShape.store_type !== 'text' || metadataShape.store_length !== STORE.length
    || metadataShape.max_store_length !== STORE.length || metadataShape.sid_type !== 'text'
    || metadataShape.sid_length !== sid.length || metadataShape.max_sid_length !== sid.length) fail();
  const metadata = db.prepare('SELECT singleton,format_version,store_id,current_sid FROM native_profile_store LIMIT 2').all().map(row);
  if (metadata.length !== 1 || metadata[0]?.singleton !== 1 || metadata[0]?.format_version !== 1
    || metadata[0]?.store_id !== STORE || metadata[0]?.current_sid !== sid) fail();
  if (pragma(db, 'quick_check') !== 'ok') fail();
  const count = row(db.prepare('SELECT count(*) AS total FROM native_profiles').get()).total;
  if (typeof count !== 'number' || !Number.isInteger(count) || count < 0 || count > WINDOWS_SNAPSHOT_MAX_PROFILES) fail();
  // Inspect lengths/types before asking the binding to allocate any row bodies.
  for (const item of db.prepare('SELECT typeof(name) AS ntype,length(CAST(name AS BLOB)) AS nlength,typeof(revision) AS rtype,length(CAST(revision AS BLOB)) AS rlength,typeof(snapshot) AS stype,length(snapshot) AS slength FROM native_profiles LIMIT 1025').iterate()) {
    const data = row(item);
    if (data.ntype !== 'text' || typeof data.nlength !== 'number' || data.nlength < 1 || data.nlength > 64
      || data.rtype !== 'text' || data.rlength !== 36 || data.stype !== 'blob'
      || typeof data.slength !== 'number' || data.slength < 1 || data.slength > NATIVE_PROFILE_MAX_SNAPSHOT_BYTES) fail();
  }
  for (const item of db.prepare('SELECT name,revision,snapshot FROM native_profiles LIMIT 1025').iterate()) {
    const data = row(item);
    if (typeof data.name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(data.name)
      || typeof data.revision !== 'string' || !uuid.test(data.revision) || !(data.snapshot instanceof Uint8Array)) fail();
    if (decodeNativeProfileSnapshotBytes(data.snapshot, data.name, STORE).revision !== data.revision) fail();
  }
}
function selected(db: Database, name: string): Observation {
  const found = db.prepare('SELECT revision,snapshot FROM native_profiles WHERE name=?').get(name);
  if (found === undefined) return Object.freeze({ revision: null, bytes: null });
  const data = row(found);
  if (typeof data.revision !== 'string' || !uuid.test(data.revision) || !(data.snapshot instanceof Uint8Array)
    || data.snapshot.byteLength > NATIVE_PROFILE_MAX_SNAPSHOT_BYTES) fail();
  const bytes = Uint8Array.from(data.snapshot);
  if (decodeNativeProfileSnapshotBytes(bytes, name, STORE).revision !== data.revision) fail();
  return Object.freeze({ revision: data.revision, bytes });
}

/** Normal SQLite/VFS durability, conditional on the OS/storage honoring flush.
 * The guard pins one private local NTFS database/journal pair; this class never
 * repairs/deletes a file, uses WAL, exports SQL handles, or loads extensions.
 * Synchronous SQLite calls cannot be preempted by a JavaScript timer. */
export class WindowsNativeSnapshots implements NativeSnapshotPort {
  private readonly observed = new WeakMap<WindowsSnapshotBinding, Observation>();
  private readonly uncertain = new WeakSet<WindowsSnapshotBinding>();
  private poisoned = false;
  constructor(private readonly guard: WindowsSnapshotGuard) {}

  private binding(name: string, context: NativeOperationContext): WindowsSnapshotBinding {
    if (this.poisoned) fail();
    active(context);
    const binding = this.guard.assertCurrentAccess(context);
    if (!binding || typeof binding !== 'object' || Object.hasOwn(binding, 'metadataOnly') || binding.name !== name || binding.storeId !== STORE
      || typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(name) || this.uncertain.has(binding)) fail();
    return binding;
  }
  private current(binding: WindowsSnapshotBinding, context: NativeOperationContext): void {
    if (this.guard.assertCurrentAccess(context) !== binding) fail();
    active(context);
  }
  private metadataBinding(context: NativeOperationContext): WindowsMetadataSnapshotBinding {
    if (this.poisoned) fail();
    active(context);
    const binding = this.guard.assertCurrentMetadataAccess(context);
    if (!binding || typeof binding !== 'object' || binding.metadataOnly !== true
      || Object.hasOwn(binding, 'name') || binding.storeId !== STORE) fail();
    return binding;
  }
  private metadataCurrent(binding: WindowsMetadataSnapshotBinding, context: NativeOperationContext): void {
    if (this.guard.assertCurrentMetadataAccess(context) !== binding) fail();
    active(context);
  }
  private closeDatabase(database: Database): void {
    try { database.close(); } catch { this.poisoned = true; fail(); }
  }
  private database(binding: { readonly rootDirectory: string }, files: WindowsSnapshotFiles): Database {
    header(files);
    if (typeof files.currentSid !== 'string' || files.currentSid.length > 184 || !/^S-1-(?:\d+-){1,15}\d+$/.test(files.currentSid)) fail();
    const filename = path.win32.join(binding.rootDirectory, WINDOWS_SNAPSHOT_DATABASE);
    const { DatabaseSync } = sqlite(database => this.closeDatabase(database));
    if (!files.fresh) {
      const readonly = new DatabaseSync(filename, { readOnly: true, allowExtension: false, enableDoubleQuotedStringLiterals: false, timeout: 0 });
      try {
        readonly.enableDefensive?.(true);
        readonly.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON');
        verify(readonly, files.currentSid);
      } catch (error) {
        // A protected, exact app/version header admits SQLite's own hot-journal
        // recovery. Read-only failure alone never establishes that authority.
        if (!error || typeof error !== 'object' || !('errcode' in error) || error.errcode !== 776) throw error;
      } finally { this.closeDatabase(readonly); }
    }
    const database = new DatabaseSync(filename, { allowExtension: false, enableDoubleQuotedStringLiterals: false, timeout: 0 });
    try { database.enableDefensive?.(true); configure(database); if (files.fresh) initialize(database, files.currentSid); verify(database, files.currentSid); return database; }
    catch (error) { this.closeDatabase(database); throw error; }
  }

  /** Namespace-only metadata inventory. No credentials, bootstrap, or named
   * compare-and-publish observations are created by this read. */
  async list(context: NativeOperationContext): Promise<readonly { readonly name: string; readonly snapshot: NativeProfileSnapshot }[]> {
    let binding: WindowsMetadataSnapshotBinding | undefined, files: WindowsSnapshotFiles | null | undefined;
    let db: Database | undefined, failed = false;
    const result: { readonly name: string; readonly snapshot: NativeProfileSnapshot }[] = [];
    try {
      binding = this.metadataBinding(context);
      files = this.guard.openMetadata(binding, context); this.metadataCurrent(binding, context);
      if (files) {
        if (files.fresh) fail();
        db = this.database(binding, files); files.validate(); this.metadataCurrent(binding, context);
        db.exec('PRAGMA query_only=ON');
        if (pragma(db, 'query_only') !== 1) fail();
        db.exec('BEGIN');
        verify(db, files.currentSid);
        for (const value of db.prepare('SELECT name,revision,snapshot FROM native_profiles ORDER BY name COLLATE BINARY LIMIT 1025').iterate()) {
          const data = row(value);
          if (result.length >= WINDOWS_SNAPSHOT_MAX_PROFILES || typeof data.name !== 'string'
            || !/^[a-z0-9-]{1,64}$/.test(data.name) || !(data.snapshot instanceof Uint8Array)) fail();
          const snapshot = decodeNativeProfileSnapshotBytes(data.snapshot, data.name, STORE);
          if (snapshot.revision !== data.revision) fail();
          result.push(Object.freeze({ name: data.name, snapshot }));
          this.metadataCurrent(binding, context);
        }
        db.exec('COMMIT'); files.validate(); this.metadataCurrent(binding, context);
      }
    } catch { failed = true; }
    finally {
      if (db?.isTransaction) { try { db.exec('ROLLBACK'); } catch { failed = true; } }
      try { if (db) this.closeDatabase(db); } catch { failed = true; }
      try { files?.validate(); } catch { failed = true; }
      try { files?.close(); } catch { failed = true; this.poisoned = true; }
    }
    if (failed || !binding) fail();
    this.metadataCurrent(binding, context);
    return Object.freeze(result);
  }

  async load(name: string, context: NativeOperationContext): Promise<unknown> {
    let db: Database | undefined, files: WindowsSnapshotFiles | undefined, binding: WindowsSnapshotBinding | undefined;
    let result: Observation | undefined, failed = false;
    try {
      binding = this.binding(name, context); this.observed.delete(binding);
      files = this.guard.open(binding, context); this.current(binding, context);
      db = this.database(binding, files); files.validate(); this.current(binding, context);
      result = selected(db, name); this.current(binding, context);
    } catch { failed = true; }
    finally {
      try { if (db) this.closeDatabase(db); } catch { failed = true; }
      try { files?.validate(); } catch { failed = true; }
      try { files?.close(); } catch { failed = true; this.poisoned = true; if (binding) this.uncertain.add(binding); }
    }
    if (failed || !binding || !result) fail();
    this.current(binding, context); this.observed.set(binding, result);
    return result.bytes === null ? null : decodeNativeProfileSnapshotBytes(result.bytes, name, STORE);
  }

  async publish(name: string, expectedRevision: string | null, next: NativeProfileSnapshot, context: NativeOperationContext): Promise<'committed' | 'not_committed' | 'unknown'> {
    let binding: WindowsSnapshotBinding | undefined, files: WindowsSnapshotFiles | undefined, db: Database | undefined;
    let submitted = false, changed = false, outcome: 'committed' | 'not_committed' | 'unknown' = 'not_committed';
    let previous: Observation | undefined;
    try {
      binding = this.binding(name, context); previous = this.observed.get(binding);
      if (!previous || previous.revision !== expectedRevision || expectedRevision !== null && !uuid.test(expectedRevision)) fail();
      const bytes = encodeNativeProfileSnapshot(next, name, STORE);
      const revision = decodeNativeProfileSnapshotBytes(bytes, name, STORE).revision;
      if (revision === expectedRevision) fail();
      files = this.guard.open(binding, context); this.current(binding, context);
      if (files.fresh) fail();
      db = this.database(binding, files); files.validate(); this.current(binding, context);
      db.exec('BEGIN IMMEDIATE');
      const found = selected(db, name);
      if (found.revision !== previous.revision || !same(found.bytes, previous.bytes)) fail();
      this.current(binding, context); changed = true;
      const written = previous.revision === null
        ? db.prepare('INSERT INTO native_profiles(name,revision,snapshot) SELECT ?,?,? WHERE (SELECT count(*) FROM native_profiles)<?').run(name, revision, bytes, WINDOWS_SNAPSHOT_MAX_PROFILES)
        : db.prepare('UPDATE native_profiles SET revision=?,snapshot=? WHERE name=? AND revision=? AND snapshot=?').run(revision, bytes, name, previous.revision, previous.bytes);
      if (written.changes !== 1 && written.changes !== 1n) fail();
      this.current(binding, context); files.validate(); submitted = true;
      db.exec('COMMIT');
      const readback = selected(db, name);
      if (readback.revision !== revision || !same(readback.bytes, bytes)) fail();
      verify(db, files.currentSid); files.validate(); this.current(binding, context);
      this.observed.set(binding, readback); outcome = 'committed';
    } catch {
      outcome = submitted ? 'unknown' : 'not_committed';
      if (db?.isTransaction) { try { db.exec('ROLLBACK'); } catch { outcome = 'unknown'; } }
      if (!submitted && changed && db && previous) {
        try { const found = selected(db, name); if (found.revision !== previous.revision || !same(found.bytes, previous.bytes)) outcome = 'unknown'; }
        catch { outcome = 'unknown'; }
      }
    } finally {
      try { if (db) this.closeDatabase(db); } catch { outcome = 'unknown'; }
      try { files?.validate(); } catch { outcome = 'unknown'; }
      try { files?.close(); } catch { this.poisoned = true; outcome = 'unknown'; }
    }
    if (binding) {
      if (outcome === 'unknown') { this.observed.delete(binding); this.uncertain.add(binding); }
      else if (outcome === 'committed') {
        try { this.current(binding, context); } catch { this.observed.delete(binding); this.uncertain.add(binding); return 'unknown'; }
      }
    }
    return outcome;
  }
}

/** Inert construction only; enrollment and invocation providers remain separate. */
export async function createWindowsNativeSnapshots(lease: WindowsNativeLease): Promise<WindowsNativeSnapshots> {
  const { createWindowsNativeSnapshotGuard } = await import('./windows-native-snapshot-files.js');
  return new WindowsNativeSnapshots(await createWindowsNativeSnapshotGuard(lease));
}
