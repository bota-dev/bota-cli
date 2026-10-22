import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WindowsNativeSnapshotGuard, createWindowsNativeSnapshotGuard, bindWindowsDelegatedSnapshotGuardForTrustedPorts } from '../src/windows-native-snapshot-files.ts';
import { DELEGATED_NATIVE_DATABASE, DELEGATED_NATIVE_JOURNAL, DELEGATED_NATIVE_APPLICATION_ID } from '../src/delegated-native-contract.ts';
import { WindowsNativeError } from '../src/windows-native-api.ts';
import { openWindowsNativeLease, WINDOWS_NATIVE_STORE_ID } from '../src/windows-native-lease.ts';
import {
  WINDOWS_SNAPSHOT_APPLICATION_ID, WINDOWS_SNAPSHOT_DATABASE as DATABASE,
  WINDOWS_SNAPSHOT_JOURNAL as JOURNAL, WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES,
  WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES,
} from '../src/windows-snapshot-contract.ts';

const root = 'C:\\synthetic\\root';
const storeLease = 'store-windows-credential-manager.lease';
const journalMagic = Buffer.from('d9d505f920a163d7', 'hex');
const profileLease = name => `profile-${Buffer.from(name, 'ascii').toString('hex')}.lease`;
const errorCode = code => error => { assert.equal(error.code, code); assert.equal(error.cause, undefined); return true; };
function context() { return { signal: new AbortController().signal, budget: { assertActive() {} } }; }
function databaseBytes() {
  const bytes = Buffer.alloc(4096);
  bytes.write('SQLite format 3\0', 'ascii'); bytes.writeUInt16BE(4096, 16);
  bytes[18] = 1; bytes[19] = 1; bytes[21] = 64; bytes[22] = 32; bytes[23] = 32;
  bytes.writeUInt32BE(1, 60); bytes.writeUInt32BE(WINDOWS_SNAPSHOT_APPLICATION_ID, 68);
  return bytes;
}
function harness(existing = false, metadata = false, delegated = false) {
  const selectedDatabase = delegated ? DELEGATED_NATIVE_DATABASE : DATABASE;
  const selectedJournal = delegated ? DELEGATED_NATIVE_JOURNAL : JOURNAL;
  const ctx = context(), binding = Object.freeze(metadata
    ? { metadataOnly: true, storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: root }
    : { name: delegated ? 'a'.repeat(64) : 'work', storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: root });
  const files = new Map(), handles = new Map(), calls = [];
  let sequence = 0;
  const h = { ctx, binding, files, handles, calls, live: true, fault: undefined, closed: [], accessCount: 0 };
  const entry = (name, bytes = Buffer.alloc(0)) => {
    const file = { name, bytes, identity: `synthetic-${++sequence}`, attributes: 0, links: 1, badAcl: false };
    files.set(name, file); return file;
  };
  h.entry = entry;
  entry(storeLease); if (!metadata) entry(profileLease(binding.name));
  if (existing) { const bytes = databaseBytes(); if (delegated) bytes.writeUInt32BE(DELEGATED_NATIVE_APPLICATION_ID, 68); entry(selectedDatabase, bytes); entry(selectedJournal, Buffer.alloc(512)); }
  h.lease = { assertCurrentAccess(value) {
    h.accessCount++;
    if (!h.live || value !== ctx || metadata) throw new WindowsNativeError('windows_native_untrusted');
    return binding;
  }, assertCurrentMetadataAccess(value) {
    h.accessCount++;
    if (!h.live || value !== ctx || !metadata) throw new WindowsNativeError('windows_native_untrusted');
    return binding;
  } };
  h.api = {
    currentSid: 'S-1-5-21-synthetic',
    assertHealthy() { if (h.poisoned) throw new WindowsNativeError('windows_native_poisoned'); },
    openDirectory() { assert.fail('guard must not resolve or create roots'); },
    createPrivateDirectory() { assert.fail('guard must not resolve or create roots'); },
    openLease() { assert.fail('guard must not replace active leases'); },
    localNtfs() { assert.fail('root capability already owns volume admission'); },
    openDataFile(filename, create) {
      assert.equal(path.win32.dirname(filename), root);
      const name = path.win32.basename(filename); calls.push(['open', name, create]);
      if (h.fault === `open-${name}`) throw new Error('raw-native-canary');
      let file = files.get(name);
      if (create) { if (file) throw new WindowsNativeError('windows_native_unavailable'); file = entry(name); }
      if (!file) return null;
      const handle = { value: BigInt(++sequence) }; handles.set(handle, file); return handle;
    },
    facts(handle) {
      const file = handles.get(handle); assert.notEqual(handle.value, null);
      if (h.fault === 'facts') throw new Error('raw-native-canary');
      return { attributes: file.attributes, links: file.links, size: file.size ?? BigInt(file.bytes.length),
        identity: file.identity, finalPath: file.finalPath ?? `\\\\?\\${path.win32.join(root, file.name)}` };
    },
    trust(handle, kind) {
      assert.equal(kind, 'private-file');
      if (handles.get(handle).badAcl) throw new WindowsNativeError('windows_native_untrusted');
    },
    readPrefix(handle, limit) {
      calls.push(['prefix', handles.get(handle).name, limit]); assert.equal(limit, 100);
      return new Uint8Array(handles.get(handle).bytes.subarray(0, limit));
    },
    readTail(handle, limit) {
      calls.push(['tail', handles.get(handle).name, limit]); assert.ok(limit >= 0 && limit <= 16);
      const bytes = handles.get(handle).bytes;
      return new Uint8Array(bytes.subarray(Math.max(0, bytes.length - limit)));
    },
    flushDataFile(handle) {
      calls.push(['flush', handles.get(handle).name]);
      if (h.fault === 'flush') throw new Error('raw-native-canary');
    },
    close(handle) {
      if (handle.value === null) return;
      const value = handle.value; handle.value = null; calls.push(['close', handles.get(handle).name]); h.closed.push(value);
      if (h.fault === 'close') { h.fault = undefined; h.poisoned = true; throw new Error('raw-native-canary'); }
    },
  };
  h.inventory = () => { calls.push(['inventory']); return h.inventoryOverride ?? [...files.keys()]; };
  h.guard = delegated ? bindWindowsDelegatedSnapshotGuardForTrustedPorts(h.lease, h.api, h.inventory) : new WindowsNativeSnapshotGuard(h.lease, h.api, h.inventory);
  return h;
}

test('metadata-only empty inventory returns null without creating or flushing fixed files', () => {
  const h = harness(false, true);
  assert.equal(h.guard.openMetadata(h.binding, h.ctx), null);
  assert.deepEqual([...h.files.keys()], [storeLease]);
  assert.deepEqual(h.calls.filter(call => call[0] === 'open'), [['open', DATABASE, false], ['open', JOURNAL, false]]);
  assert.equal(h.calls.some(call => call[0] === 'flush'), false);
  assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
  assert.throws(() => h.guard.openMetadata({ ...h.binding }, h.ctx), errorCode('windows_native_untrusted'));
  assert.equal(h.guard.openMetadata(h.binding, h.ctx), null);
});

test('metadata-only admission validates every persisted profile lease without a selected-name exemption', () => {
  const h = harness(true, true);
  const first = profileLease('alpha'), last = profileLease('zulu'); h.entry(first); h.entry(last);
  const files = h.guard.openMetadata(h.binding, h.ctx);
  assert.equal(files.fresh, false); files.validate(); files.close();
  for (const name of [first, last]) assert.ok(h.calls.some(call => call[0] === 'open' && call[1] === name));
  h.files.get(first).bytes = Buffer.from('retained');
  assert.throws(() => h.guard.openMetadata(h.binding, h.ctx), errorCode('windows_native_untrusted'));
  assert.equal(h.files.get(first).bytes.toString(), 'retained');
  assert.equal(h.calls.some(call => call[0] === 'open' && call[2] === true), false);
});

for (const fault of ['missing-database', 'missing-journal', 'zero-database', 'foreign-header', 'journal-footer', 'unknown-entry']) {
  test(`metadata-only ${fault} refuses without creation or file mutation`, () => {
    const h = harness(true, true);
    if (fault === 'missing-database') h.files.delete(DATABASE);
    else if (fault === 'missing-journal') h.files.delete(JOURNAL);
    else if (fault === 'zero-database') h.files.get(DATABASE).bytes = Buffer.alloc(0);
    else if (fault === 'foreign-header') h.files.get(DATABASE).bytes[68] = 0;
    else if (fault === 'journal-footer') h.files.get(JOURNAL).bytes = Buffer.concat([Buffer.alloc(8), journalMagic]);
    else h.entry('unrecognized');
    const before = [...h.files.values()].map(file => [file.name, Buffer.from(file.bytes)]);
    assert.throws(() => h.guard.openMetadata(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.deepEqual([...h.files.values()].map(file => [file.name, file.bytes]), before);
    assert.equal(h.calls.some(call => call[0] === 'open' && call[2] === true || call[0] === 'flush'), false);
  });
}

test('named snapshot ownership never grants aggregate metadata access', () => {
  const h = harness(true);
  assert.throws(() => h.guard.openMetadata(h.binding, h.ctx), errorCode('windows_native_untrusted'));
  assert.equal(h.calls.some(call => call[0] === 'open'), false);
});

test('portable fresh pair uses only live root/fixed names, exclusive creation, both flushes and one reverse cleanup', () => {
  const h = harness(), files = h.guard.open(h.binding, h.ctx);
  assert.equal(files.fresh, true); assert.equal(files.currentSid, h.api.currentSid);
  assert.equal(Object.isFrozen(files), true); assert.equal(files.databaseHeader.length, 0);
  assert.deepEqual(h.calls.filter(call => call[0] === 'open'),
    [['open', DATABASE, false], ['open', JOURNAL, false], ['open', DATABASE, true], ['open', JOURNAL, true]]);
  assert.deepEqual(h.calls.filter(call => call[0] === 'flush'), [['flush', DATABASE], ['flush', JOURNAL]]);
  files.validate();
  h.files.get(DATABASE).bytes = databaseBytes(); h.files.get(JOURNAL).bytes = Buffer.alloc(512); files.validate();
  files.close(); files.close();
  assert.deepEqual(h.calls.filter(call => call[0] === 'close'), [['close', JOURNAL], ['close', DATABASE]]);
  assert.throws(() => files.validate(), errorCode('windows_native_unavailable'));
  assert.equal(h.files.size, 4, 'close must not unlink persistent data or lease files');
});
test('portable existing fixed header is copied and no file is created or flushed', () => {
  const h = harness(true), files = h.guard.open(h.binding, h.ctx);
  assert.equal(files.fresh, false); assert.deepEqual(files.databaseHeader, new Uint8Array(databaseBytes().subarray(0, 100)));
  const returned = files.databaseHeader; returned.fill(0); assert.equal(files.databaseHeader[0], 83);
  assert.equal(h.calls.some(call => call[0] === 'flush' || call[0] === 'open' && call[2]), false);
  files.validate(); files.close();
});
test('portable valid initialized database may retain a zero-byte nonhot journal', () => {
  const h = harness(true); h.files.get(JOURNAL).bytes = Buffer.alloc(0);
  const files = h.guard.open(h.binding, h.ctx); files.validate(); files.close();
});
for (const size of [0, 1, 8, 15]) {
  test(`portable ${size}-byte journal cannot contain a recognized super-journal footer`, () => {
    const h = harness(true), bytes = Buffer.alloc(size);
    if (size >= 8) journalMagic.copy(bytes, size - 8);
    h.files.get(JOURNAL).bytes = bytes;
    const files = h.guard.open(h.binding, h.ctx); files.validate(); files.close();
    assert.equal(h.calls.some(call => call[0] === 'tail' && call[2] === size), size !== 0);
  });
}
function superJournalFooter(mode = 'valid') {
  const name = Buffer.from('C:\\synthetic\\never-follow-mj123456789', 'utf8');
  const prefix = Buffer.alloc(512); if (mode !== 'zero-head' && mode !== 'stale-persist') journalMagic.copy(prefix);
  const footer = Buffer.alloc(4 + name.length + 16);
  footer.writeUInt32BE(0x40001, 0); name.copy(footer, 4);
  footer.writeUInt32BE(mode === 'bad-length' ? 0xffffffff : mode === 'zero-length' ? 0 : name.length, footer.length - 16);
  footer.writeUInt32BE(mode === 'bad-checksum' ? 0 : [...name].reduce((sum, byte) => (sum + (byte < 128 ? byte : byte - 256)) >>> 0, 0), footer.length - 12);
  journalMagic.copy(footer, footer.length - 8);
  return Buffer.concat([prefix, footer]);
}
for (const mode of ['valid', 'bad-length', 'zero-length', 'bad-checksum', 'zero-head', 'stale-persist']) {
  test(`portable ${mode} super-journal footer refuses before return and preserves the fixed pair`, () => {
    const h = harness(true), bytes = superJournalFooter(mode); h.files.get(JOURNAL).bytes = bytes;
    const databaseBefore = Buffer.from(h.files.get(DATABASE).bytes);
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.deepEqual(h.files.get(JOURNAL).bytes, bytes); assert.deepEqual(h.files.get(DATABASE).bytes, databaseBefore);
    assert.equal(h.closed.length, 2); assert.ok(h.calls.some(call => call[0] === 'tail' && call[2] === 16));
  });
}
test('portable footer mutation and torn reads refuse on revalidation without following any journal path', () => {
  for (const mode of ['footer', 'size-change', 'identity-change', 'short-read']) {
    const h = harness(true), files = h.guard.open(h.binding, h.ctx);
    if (mode === 'footer') h.files.get(JOURNAL).bytes = superJournalFooter();
    else {
      const original = h.api.readTail;
      h.api.readTail = (...args) => {
        const tail = original(...args);
        if (mode === 'size-change') h.files.get(JOURNAL).size = 513n;
        if (mode === 'identity-change') h.files.get(JOURNAL).identity += '-changed';
        return mode === 'short-read' ? tail.subarray(0, 15) : tail;
      };
    }
    assert.throws(() => files.validate(), errorCode('windows_native_untrusted')); files.close(); assert.equal(h.closed.length, 2);
    assert.equal(h.calls.filter(call => call[0] === 'open').every(call => [DATABASE, JOURNAL].includes(call[1])), true);
  }
});
test('portable outside, wrong-context and copied bindings refuse before filesystem access', () => {
  const h = harness(); h.live = false;
  assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
  h.live = true;
  assert.throws(() => h.guard.open(h.binding, context()), errorCode('windows_native_untrusted'));
  assert.throws(() => h.guard.open({ ...h.binding }, h.ctx), errorCode('windows_native_untrusted'));
  assert.equal(h.calls.length, 0);
});
test('portable active pair prevents overlapping opens; revoked descendants cannot validate but can close', () => {
  const h = harness(true), files = h.guard.open(h.binding, h.ctx);
  assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_busy'));
  h.live = false;
  assert.throws(() => files.validate(), errorCode('windows_native_untrusted'));
  files.close(); assert.equal(h.closed.length, 2);
});
for (const missing of [DATABASE, JOURNAL]) {
  test(`portable existing one-sided pair missing ${missing} refuses without repair or deletion`, () => {
    const h = harness(true); h.files.delete(missing); const retained = [...h.files.keys()];
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.deepEqual([...h.files.keys()], retained); assert.equal(h.calls.some(call => call[0] === 'open' && call[2]), false);
    assert.equal(h.closed.length, 1);
  });
}
for (const name of ['retained.txt', `${DATABASE}-wal`, `${DATABASE}-shm`, '776f726b.json', 'profile-574f524b.lease',
  'profile-00.lease', 'profile-2e2e.lease', 'profile-.lease', 'store-other.lease']) {
  test(`portable inventory refuses ${name} before opening data or changing retained contents`, () => {
    const h = harness(); h.entry(name, Buffer.from('retained'));
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.equal(h.calls.some(call => call[0] === 'open'), false);
    assert.equal(h.files.get(name).bytes.toString(), 'retained');
  });
}
test('portable inventory checks other canonical leases are empty/private/singlelink and does not reopen active leases', () => {
  const h = harness(true); h.entry(profileLease('other'));
  const files = h.guard.open(h.binding, h.ctx); files.close();
  assert.ok(h.calls.some(call => call[0] === 'open' && call[1] === profileLease('other')));
  assert.equal(h.calls.some(call => call[0] === 'open' && [storeLease, profileLease('work')].includes(call[1])), false);
  for (const fault of ['size', 'acl', 'links']) {
    const invalid = harness(); const file = invalid.entry(profileLease('other'));
    if (fault === 'size') file.bytes = Buffer.from('x');
    if (fault === 'acl') file.badAcl = true;
    if (fault === 'links') file.links = 2;
    assert.throws(() => invalid.guard.open(invalid.binding, invalid.ctx), errorCode('windows_native_untrusted'));
    assert.equal(invalid.closed.length, 1);
  }
});
test('portable inventory bounds and duplicate names refuse before opening data', () => {
  for (const names of [Array(1028).fill('x'), [storeLease, profileLease('work'), storeLease]]) {
    const h = harness(); h.inventoryOverride = names;
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.equal(h.calls.some(call => call[0] === 'open'), false);
  }
});
for (const fault of ['zero', 'short', 'alignment', 'too-large', 'magic', 'page-size', 'wal-read', 'wal-write', 'app-id', 'version']) {
  test(`portable existing database ${fault} refuses without publication or cleanup`, () => {
    const h = harness(true), file = h.files.get(DATABASE);
    if (fault === 'zero') file.bytes = Buffer.alloc(0);
    if (fault === 'short') file.bytes = Buffer.alloc(100);
    if (fault === 'alignment') file.bytes = Buffer.alloc(4097);
    if (fault === 'too-large') file.size = BigInt(WINDOWS_SNAPSHOT_MAX_DATABASE_BYTES) + 4096n;
    if (fault === 'magic') file.bytes[0] = 0;
    if (fault === 'page-size') file.bytes.writeUInt16BE(512, 16);
    if (fault === 'wal-read') file.bytes[18] = 2;
    if (fault === 'wal-write') file.bytes[19] = 2;
    if (fault === 'app-id') file.bytes.writeUInt32BE(42, 68);
    if (fault === 'version') file.bytes.writeUInt32BE(2, 60);
    const before = Buffer.from(file.bytes);
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.deepEqual(file.bytes, before); assert.equal(h.closed.length, 2);
  });
}
for (const name of [DATABASE, JOURNAL]) {
  for (const fault of ['reparse', 'directory', 'links', 'acl', 'path', 'identity']) {
    test(`portable ${name} ${fault} refuses and joins both pinned handles`, () => {
      const h = harness(true), file = h.files.get(name);
      if (fault === 'reparse') file.attributes = 0x400;
      if (fault === 'directory') file.attributes = 0x10;
      if (fault === 'links') file.links = 2;
      if (fault === 'acl') file.badAcl = true;
      if (fault === 'path') file.finalPath = '\\\\?\\C:\\other\\target';
      if (fault === 'identity') file.identity = '';
      assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
      assert.equal(h.closed.length, 2);
    });
  }
}
test('portable excessive journal and identical pair identities refuse', () => {
  for (const mode of ['size', 'identity']) {
    const h = harness(true);
    if (mode === 'size') h.files.get(JOURNAL).size = BigInt(WINDOWS_SNAPSHOT_MAX_JOURNAL_BYTES) + 1n;
    else h.files.get(JOURNAL).identity = h.files.get(DATABASE).identity;
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted')); assert.equal(h.closed.length, 2);
  }
});
test('portable post-open identity/header/inventory changes refuse while exact files remain retained', () => {
  for (const fault of ['identity', 'header', 'inventory']) {
    const h = harness(true), files = h.guard.open(h.binding, h.ctx);
    if (fault === 'identity') h.files.get(JOURNAL).identity += '-changed';
    if (fault === 'header') h.files.get(DATABASE).bytes[0] = 0;
    if (fault === 'inventory') h.entry('unknown-retained');
    assert.throws(() => files.validate(), errorCode('windows_native_untrusted')); files.close(); assert.equal(h.closed.length, 2);
  }
});
test('portable partial creation and flush failure preserve owned files and never leak raw diagnostics', () => {
  for (const fault of [`open-${JOURNAL}`, 'flush']) {
    const h = harness();
    if (fault === `open-${JOURNAL}`) {
      const original = h.api.openDataFile;
      h.api.openDataFile = (filename, create) => {
        if (create && filename.endsWith(JOURNAL)) throw new Error('raw-native-canary'); return original(filename, create);
      };
    } else h.fault = fault;
    assert.throws(() => h.guard.open(h.binding, h.ctx), error => {
      errorCode('windows_native_unavailable')(error); assert.ok(!String(error).includes('canary')); return true;
    });
    assert.ok(h.files.has(DATABASE)); assert.equal(h.closed.length, fault === 'flush' ? 2 : 1);
  }
});
test('portable authority revocation after native acquisition or flush still joins every known owned handle', () => {
  for (const mode of ['acquire', 'flush']) {
    const h = harness(mode === 'acquire');
    if (mode === 'acquire') {
      const original = h.api.openDataFile;
      h.api.openDataFile = (...args) => { const handle = original(...args); h.live = false; return handle; };
    } else {
      const original = h.api.flushDataFile;
      h.api.flushDataFile = (...args) => { original(...args); h.live = false; };
    }
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.equal(h.closed.length, mode === 'acquire' ? 1 : 2);
  }
});
test('portable short native header read refuses without creating or changing the pair', () => {
  const h = harness(true); h.api.readPrefix = () => new Uint8Array(99);
  assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
  assert.equal(h.closed.length, 2);
});
test('portable ambiguous close attempts every handle once and poisons future admission', () => {
  const h = harness(true), files = h.guard.open(h.binding, h.ctx); h.fault = 'close';
  assert.throws(() => files.close(), errorCode('windows_native_close_unknown')); files.close();
  assert.equal(h.closed.length, 2);
  assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_poisoned'));
});

const windows = process.platform === 'win32' && process.arch === 'x64';
const workspace = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const artifactRoot = path.join(workspace, '.artifacts', 'developer-toolchain-20261020');
async function temporary() { await fs.mkdir(artifactRoot, { recursive: true }); return fs.mkdtemp(path.join(artifactRoot, 'win-snapshot-files-')); }
async function cleanup(directory) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), artifactRoot); assert.match(path.basename(resolved), /^win-snapshot-files-/);
  await fs.rm(resolved, { recursive: true, force: true });
}
test('actual fresh Windows pair stays pinned against deletion and empty interrupted bootstrap refuses on next open', { skip: !windows }, async () => {
  const directory = await temporary(), privateRoot = path.join(directory, 'private'); let lease;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(privateRoot, ctx);
    const guard = await createWindowsNativeSnapshotGuard(lease);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {
      const files = guard.open(lease.assertCurrentAccess(ctx), ctx); assert.equal(files.fresh, true);
      assert.equal(files.databaseHeader.length, 0); files.validate();
      for (const name of [DATABASE, JOURNAL]) {
        await assert.rejects(fs.unlink(path.join(privateRoot, name)), error => ['EPERM', 'EBUSY', 'EACCES'].includes(error.code));
      }
      files.close();
      assert.throws(() => guard.open(lease.assertCurrentAccess(ctx), ctx), errorCode('windows_native_untrusted'));
    });
    assert.equal((await fs.stat(path.join(privateRoot, DATABASE))).size, 0);
    assert.equal((await fs.stat(path.join(privateRoot, JOURNAL))).size, 0);
  } finally { lease?.close(); await cleanup(directory); }
});
test('actual Windows existing initialized pair admits header and refuses extra retained files without deletion', { skip: !windows }, async () => {
  const directory = await temporary(), privateRoot = path.join(directory, 'private'); let lease;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(privateRoot, ctx);
    const guard = await createWindowsNativeSnapshotGuard(lease);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {
      const files = guard.open(lease.assertCurrentAccess(ctx), ctx);
      await fs.writeFile(path.join(privateRoot, DATABASE), databaseBytes());
      await fs.writeFile(path.join(privateRoot, JOURNAL), Buffer.alloc(512));
      files.validate(); files.close();
      const reopened = guard.open(lease.assertCurrentAccess(ctx), ctx);
      assert.equal(reopened.fresh, false); assert.equal(reopened.databaseHeader.length, 100); reopened.close();
      await fs.writeFile(path.join(privateRoot, 'retained.txt'), 'synthetic-retained');
      assert.throws(() => guard.open(lease.assertCurrentAccess(ctx), ctx), errorCode('windows_native_untrusted'));
      assert.equal(await fs.readFile(path.join(privateRoot, 'retained.txt'), 'utf8'), 'synthetic-retained');
    });
  } finally { lease?.close(); await cleanup(directory); }
});
test('actual Windows missing, hard-linked or inherited-ACL database pairs refuse and retain exact data', { skip: !windows }, async () => {
  for (const mode of ['missing-journal', 'hard-link', 'inherited-acl']) {
    const directory = await temporary(), privateRoot = path.join(directory, 'private'); let lease;
    try {
      const ctx = context(); lease = await openWindowsNativeLease(privateRoot, ctx);
      const guard = await createWindowsNativeSnapshotGuard(lease);
      await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {
        const files = guard.open(lease.assertCurrentAccess(ctx), ctx);
        await fs.writeFile(path.join(privateRoot, DATABASE), databaseBytes());
        await fs.writeFile(path.join(privateRoot, JOURNAL), Buffer.alloc(512)); files.close();
        if (mode === 'missing-journal') await fs.unlink(path.join(privateRoot, JOURNAL));
        if (mode === 'hard-link') await fs.link(path.join(privateRoot, DATABASE), path.join(directory, 'retained-link'));
        if (mode === 'inherited-acl') {
          await fs.unlink(path.join(privateRoot, DATABASE)); await fs.writeFile(path.join(privateRoot, DATABASE), databaseBytes());
        }
        assert.throws(() => guard.open(lease.assertCurrentAccess(ctx), ctx), errorCode('windows_native_untrusted'));
        assert.deepEqual(await fs.readFile(path.join(privateRoot, DATABASE)), databaseBytes());
      });
    } finally { lease?.close(); await cleanup(directory); }
  }
});
test('actual Windows super-journal footer refuses before SQLite and retains both owned files', { skip: !windows }, async () => {
  const directory = await temporary(), privateRoot = path.join(directory, 'private'); let lease;
  try {
    const ctx = context(); lease = await openWindowsNativeLease(privateRoot, ctx);
    const guard = await createWindowsNativeSnapshotGuard(lease);
    await lease.runExclusive(WINDOWS_NATIVE_STORE_ID, 'fresh', ctx, async () => {
      const files = guard.open(lease.assertCurrentAccess(ctx), ctx);
      await fs.writeFile(path.join(privateRoot, DATABASE), databaseBytes());
      const footer = superJournalFooter('zero-head'); await fs.writeFile(path.join(privateRoot, JOURNAL), footer); files.close();
      assert.throws(() => guard.open(lease.assertCurrentAccess(ctx), ctx), errorCode('windows_native_untrusted'));
      assert.deepEqual(await fs.readFile(path.join(privateRoot, DATABASE)), databaseBytes());
      assert.deepEqual(await fs.readFile(path.join(privateRoot, JOURNAL)), footer);
    });
  } finally { lease?.close(); await cleanup(directory); }
});

test('delegated guard uses separate fixed filenames/application ID and hashed ticket leases', () => {
  const h = harness(true, false, true), files = h.guard.open(h.binding, h.ctx);
  assert.equal(files.fresh, false); files.validate(); files.close();
  assert.ok(h.calls.filter(row => row[0] === 'open').every(row => !row[1].startsWith('native-profiles-')));
  assert.equal(h.handles.size, h.closed.length);
});
for (const fault of ['api-key-pair', 'api-key-header', 'plain-name-lease', 'unknown-file', 'super-journal']) {
  test(`delegated guard refuses ${fault} without repairing retained state`, () => {
    const h = harness(true, false, true);
    if (fault === 'api-key-pair') { h.entry(DATABASE, databaseBytes()); h.entry(JOURNAL); }
    if (fault === 'api-key-header') h.files.get(DELEGATED_NATIVE_DATABASE).bytes.writeUInt32BE(WINDOWS_SNAPSHOT_APPLICATION_ID, 68);
    if (fault === 'plain-name-lease') h.entry(profileLease('work'));
    if (fault === 'unknown-file') h.entry('retained-unknown');
    if (fault === 'super-journal') journalMagic.copy(h.files.get(DELEGATED_NATIVE_JOURNAL).bytes, 504);
    const before = [...h.files].map(([name, value]) => [name, Buffer.from(value.bytes)]);
    assert.throws(() => h.guard.open(h.binding, h.ctx), errorCode('windows_native_untrusted'));
    assert.deepEqual([...h.files].map(([name, value]) => [name, value.bytes]), before);
    assert.equal(h.handles.size, h.closed.length);
  });
}
