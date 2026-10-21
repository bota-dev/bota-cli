import assert from 'node:assert/strict';
import test from 'node:test';
import { bindWindowsCredentialApi, WindowsNativeError, windowsCredentialReference } from '../src/windows-native-api.ts';
import { WindowsNativeStore } from '../src/windows-native-store.ts';
import { WINDOWS_NATIVE_STORE_ID } from '../src/windows-native-lease.ts';
import { NativeProfileTransactions } from '../src/native-profile-transaction.ts';

const reference = Object.freeze({ profile_id: '11111111-1111-4111-8111-111111111111', credential_ref: '22222222-2222-4222-8222-222222222222' });
const namespace = 'Bota/DeveloperToolchain/api-key/v1';
const target = `${namespace}/${reference.profile_id}/${reference.credential_ref}`;
const username = `${namespace}:${reference.profile_id}:${reference.credential_ref}`;
const errorCode = code => error => { assert.equal(error.code, code); assert.equal(error.cause, undefined); return true; };
function context() {
  const controller = new AbortController(); let expired = false;
  return { controller, expire() { expired = true; }, signal: controller.signal,
    budget: { assertActive() { if (expired) throw new Error('private budget detail'); } } };
}
function fixture() {
  let address = 0x1000n;
  const memory = new Map(), calls = [], retained = [];
  const h = { memory, calls, retained, poison: false, readError: 1168, writeResult: 1, deleteResult: 1,
    writeError: 5, deleteError: 5, credential: null, freeThrows: false, readThrows: false, writeThrows: false, deleteThrows: false };
  const allocate = value => { const at = address; address += 0x10000n; memory.set(at, Buffer.from(value)); return at; };
  h.credentialAt = (key = 'synthetic-api-key', mutate = () => {}) => {
    const header = Buffer.alloc(80), secret = Buffer.from(key);
    header.writeUInt32LE(1, 4); header.writeBigUInt64LE(allocate(Buffer.from(`${target}\0`, 'utf16le')), 8);
    header.writeUInt32LE(secret.length, 32); header.writeBigUInt64LE(allocate(secret), 40);
    header.writeUInt32LE(2, 48); header.writeBigUInt64LE(allocate(Buffer.from(`${username}\0`, 'utf16le')), 72);
    mutate(header, allocate); h.credential = allocate(header); return h.credential;
  };
  h.bindings = {
    assertHealthy() { if (h.poison) throw new WindowsNativeError('windows_native_poisoned'); },
    poison() { h.poison = true; },
    read(name, type, flags, output) {
      calls.push(['read', name, type, flags]); if (h.readThrows) throw new Error('private native read detail');
      if (h.credential !== null) { output.writeBigUInt64LE(h.credential); return 1; }
      return 0;
    },
    write(header, flags) {
      calls.push(['write', flags]); h.writtenHeader = Buffer.from(header);
      h.writtenKey = memory.get(header.readBigUInt64LE(40)).toString('ascii');
      retained.push(header);
      if (h.writeThrows) throw new Error('private native write detail');
      return h.writeResult;
    },
    delete(name, type, flags) {
      calls.push(['delete', name, type, flags]); if (h.deleteThrows) throw new Error('private native delete detail');
      return h.deleteResult;
    },
    free(at) { calls.push(['free', at]); if (h.freeThrows) throw new Error('private native free detail'); },
    lastError() {
      const last = calls.at(-1)?.[0]; calls.push(['lastError']);
      return last === 'write' ? h.writeError : last === 'delete' ? h.deleteError : h.readError;
    },
    view(at, length) {
      for (const [base, value] of memory) {
        const offset = Number(at - base);
        if (at >= base && offset + length <= value.length) return value.buffer.slice(value.byteOffset + offset, value.byteOffset + offset + length);
      }
      throw new Error('private synthetic pointer detail');
    },
    address(value) {
      const at = address; address += 0x10000n; memory.set(at, value); retained.push(value); return at;
    },
  };
  h.api = bindWindowsCredentialApi(h.bindings); return h;
}
function lease(contextValue, options = {}) {
  let admitted = true;
  return { close() { admitted = false; }, assertCurrentAccess(ctx) {
    assert.equal(ctx, contextValue);
    if (!admitted) throw new WindowsNativeError('windows_native_untrusted');
    return Object.freeze({ name: 'synthetic-profile', storeId: WINDOWS_NATIVE_STORE_ID, rootDirectory: 'C:\\synthetic', ...options });
  } };
}

test('strict exact references copy/freeze without invoking hooks or accepting aliases', () => {
  assert.deepEqual(windowsCredentialReference(reference), reference); assert.notEqual(windowsCredentialReference(reference), reference);
  assert.equal(Object.isFrozen(windowsCredentialReference(reference)), true);
  let invoked = 0;
  for (const value of [null, [], { ...reference, extra: true }, { ...reference, credential_ref: reference.profile_id },
    { ...reference, profile_id: 'A1111111-1111-4111-8111-111111111111' }, { ...reference, profile_id: '../escape' },
    { ...reference, credential_ref: '22222222-2222-1222-8222-222222222222' },
    Object.defineProperty({}, 'profile_id', { enumerable: true, get() { invoked++; return reference.profile_id; } }),
    new Proxy(reference, { get() { invoked++; throw new Error('must not invoke'); } }),
    Object.assign(Object.create({}), reference), { ...reference, [Symbol('foreign')]: true }]) {
    assert.throws(() => windowsCredentialReference(value), errorCode('windows_native_untrusted'));
  }
  assert.equal(invoked, 0);
});

test('exact absent read uses fixed target/type/flags; logon-session errors never mean absence', () => {
  const h = fixture(); assert.deepEqual(h.api.readCredential(reference), { status: 'absent' });
  assert.deepEqual(h.calls, [['read', target, 1, 0], ['lastError']]);
  for (const error of [1312, 5, 87, 1004, 0, '1168', undefined]) {
    const failed = fixture(); failed.readError = error;
    assert.throws(() => failed.api.readCredential(reference), errorCode('windows_native_unavailable'));
    assert.equal(failed.calls.some(row => row[0] === 'free'), false);
  }
});

for (const length of [1, 2560]) {
  test(`read validates the owned marker and raw ASCII key at length ${length}, then frees once`, () => {
    const h = fixture(), at = h.credentialAt('K'.repeat(length));
    const result = h.api.readCredential(reference);
    assert.deepEqual(result, { status: 'present', key: 'K'.repeat(length) }); assert.equal(Object.isFrozen(result), true);
    assert.deepEqual(h.calls.filter(row => row[0] === 'free'), [['free', at]]);
  });
}

const malformed = {
  flags: header => header.writeUInt32LE(2, 0), type: header => header.writeUInt32LE(2, 4),
  persistence: header => header.writeUInt32LE(3, 48), attributesCount: header => header.writeUInt32LE(1, 52),
  attributesPointer: header => header.writeBigUInt64LE(1n, 56), alias: header => header.writeBigUInt64LE(1n, 64),
  emptyBlob: header => header.writeUInt32LE(0, 32), oversizedBlob: header => header.writeUInt32LE(2561, 32),
  nullBlob: header => header.writeBigUInt64LE(0n, 40), nullTarget: header => header.writeBigUInt64LE(0n, 8),
  wrongTarget: (header, allocate) => header.writeBigUInt64LE(allocate(Buffer.from('Foreign\0', 'utf16le')), 8),
  wrongMarker: (header, allocate) => header.writeBigUInt64LE(allocate(Buffer.from('Foreign\0', 'utf16le')), 72),
  missingMarker: header => header.writeBigUInt64LE(0n, 72),
  comment: (header, allocate) => header.writeBigUInt64LE(allocate(Buffer.from('Foreign\0', 'utf16le')), 16),
};
for (const [name, mutate] of Object.entries(malformed)) {
  test(`read/delete refuse ${name}, preserve entry and release each read exactly once`, () => {
    const h = fixture(), at = h.credentialAt('valid-looking-key', mutate);
    assert.throws(() => h.api.readCredential(reference), errorCode('windows_native_untrusted'));
    assert.equal(h.api.deleteCredential(reference), 'not_deleted');
    assert.equal(h.calls.some(row => row[0] === 'delete'), false);
    assert.deepEqual(h.calls.filter(row => row[0] === 'free'), [['free', at], ['free', at]]);
  });
}
for (const value of ['contains space', 'null\0byte', 'line\nbreak', 'high\u00e9', '\x7f']) {
  test(`nonportable blob ${JSON.stringify(value)} is refused without delete`, () => {
    const h = fixture(); h.credentialAt(value);
    assert.throws(() => h.api.readCredential(reference), errorCode('windows_native_untrusted'));
    assert.equal(h.api.deleteCredential(reference), 'not_deleted');
    assert.equal(h.calls.some(row => row[0] === 'delete'), false);
  });
}
test('empty comment is accepted while target/marker matching is exact and bounded', () => {
  const h = fixture(); h.credentialAt('valid', (header, allocate) => header.writeBigUInt64LE(allocate(Buffer.from('\0', 'utf16le')), 16));
  assert.equal(h.api.readCredential(reference).key, 'valid');
  for (const field of [8, 72]) {
    const bad = fixture(); bad.credentialAt('valid', (header, allocate) => header.writeBigUInt64LE(allocate(Buffer.from(`${field === 8 ? target : username}x\0`, 'utf16le')), field));
    assert.throws(() => bad.api.readCredential(reference), errorCode('windows_native_untrusted'));
  }
});

test('write refuses any existing exact entry, including malformed, with no upsert or retry', () => {
  for (const mutate of [() => {}, malformed.wrongMarker, malformed.oversizedBlob]) {
    const h = fixture(), at = h.credentialAt('prior-key', mutate);
    assert.equal(h.api.writeCredential(reference, 'new-key'), 'not_stored');
    assert.deepEqual(h.calls, [['read', target, 1, 0], ['free', at]]);
  }
});
for (const length of [1, 2560]) {
  test(`write fixed x64 record preserves full key bound ${length} and zeros mutable temporary buffers`, () => {
    const h = fixture(); assert.equal(h.api.writeCredential(reference, 'K'.repeat(length)), 'stored');
    assert.equal(h.writtenKey, 'K'.repeat(length));
    const header = h.writtenHeader;
    assert.equal(header.length, 80); assert.equal(header.readUInt32LE(0), 0); assert.equal(header.readUInt32LE(4), 1);
    assert.equal(header.readUInt32LE(32), length); assert.equal(header.readUInt32LE(48), 2);
    assert.equal(header.readUInt32LE(52), 0); assert.equal(header.readBigUInt64LE(56), 0n); assert.equal(header.readBigUInt64LE(64), 0n);
    assert.equal(h.calls.filter(row => row[0] === 'write').length, 1);
    assert.equal(h.retained.every(buffer => buffer.every(byte => byte === 0)), true);
  });
}
test('invalid keys refuse before any native call', () => {
  for (const key of ['', 'a'.repeat(2561), 'space key', '\0', 'é', undefined, new String('key')]) {
    const h = fixture(); assert.throws(() => h.api.writeCredential(reference, key), errorCode('windows_native_untrusted'));
    assert.equal(h.calls.length, 0);
  }
});
test('mutation FALSE/throw remain unknown, capture last error immediately, and never retry', () => {
  for (const mode of ['false', 'throw']) {
    const h = fixture(); if (mode === 'false') h.writeResult = 0; else h.writeThrows = true;
    assert.equal(h.api.writeCredential(reference, 'synthetic-key'), 'unknown');
    assert.equal(h.calls.filter(row => row[0] === 'write').length, 1);
    if (mode === 'false') assert.equal(h.calls[h.calls.findIndex(row => row[0] === 'write') + 1][0], 'lastError');
    assert.equal(h.retained.every(buffer => buffer.every(byte => byte === 0)), true);
  }
  for (const mode of ['false', 'throw']) {
    const h = fixture(); h.credentialAt(); if (mode === 'false') h.deleteResult = 0; else h.deleteThrows = true;
    assert.equal(h.api.deleteCredential(reference), 'unknown'); assert.equal(h.calls.filter(row => row[0] === 'delete').length, 1);
    if (mode === 'false') assert.equal(h.calls.at(-1)[0], 'lastError');
  }
});
test('delete independently reads and validates, then calls only its exact target; not-found is absent', () => {
  const h = fixture(), at = h.credentialAt(); assert.equal(h.api.deleteCredential(reference), 'deleted');
  assert.deepEqual(h.calls, [['read', target, 1, 0], ['free', at], ['delete', target, 1, 0]]);
  const absent = fixture(); assert.equal(absent.api.deleteCredential(reference), 'absent');
  assert.equal(absent.calls.some(row => row[0] === 'delete'), false);
  const raced = fixture(); raced.credentialAt(); raced.deleteResult = 0; raced.deleteError = 1168;
  assert.equal(raced.api.deleteCredential(reference), 'absent');
});
test('free ambiguity retires once and poisons future store work across API instances', () => {
  const h = fixture(), at = h.credentialAt(); h.freeThrows = true;
  assert.throws(() => h.api.readCredential(reference), errorCode('windows_native_unavailable'));
  assert.deepEqual(h.calls.filter(row => row[0] === 'free'), [['free', at]]);
  const next = bindWindowsCredentialApi(h.bindings), count = h.calls.length;
  assert.throws(() => next.readCredential(reference), errorCode('windows_native_poisoned')); assert.equal(h.calls.length, count);
});
test('invalid native allocation/output/call outcomes poison instead of declaring absence', () => {
  const h = fixture(); h.bindings.read = (_target, _type, _flags, output) => { output.writeBigUInt64LE(1n); return 0; };
  assert.throws(() => h.api.readCredential(reference), errorCode('windows_native_unavailable')); assert.equal(h.poison, true);
  const nullResult = fixture(); nullResult.bindings.read = () => 1;
  assert.throws(() => nullResult.api.readCredential(reference), errorCode('windows_native_unavailable')); assert.equal(nullResult.poison, true);
  const throwing = fixture(); throwing.readThrows = true;
  assert.throws(() => throwing.api.readCredential(reference), errorCode('windows_native_unavailable')); assert.equal(throwing.poison, true);
});

test('store requires active exact lease/context and immutable fixed id', async () => {
  const h = fixture(), ctx = context(), selected = lease(ctx), store = WindowsNativeStore.open(h.api, selected);
  assert.equal(store.id, WINDOWS_NATIVE_STORE_ID); assert.throws(() => { store.id = 'foreign'; }, TypeError);
  assert.deepEqual(await store.read(reference, ctx), { status: 'absent' });
  selected.close(); const count = h.calls.length;
  await assert.rejects(store.read(reference, ctx), errorCode('windows_native_untrusted')); assert.equal(h.calls.length, count);
  const foreign = WindowsNativeStore.open(h.api, lease(ctx, { storeId: 'foreign' }));
  await assert.rejects(foreign.read(reference, ctx), errorCode('windows_native_untrusted'));
});
test('pre-cancel/expired context causes zero credential calls', async () => {
  for (const mode of ['cancel', 'expire']) {
    const h = fixture(), ctx = context(), store = WindowsNativeStore.open(h.api, lease(ctx));
    if (mode === 'cancel') ctx.controller.abort('private reason'); else ctx.expire();
    for (const action of [() => store.read(reference, ctx), () => store.write(reference, 'valid-key', ctx), () => store.delete(reference, ctx)]) {
      await assert.rejects(action(), errorCode(mode === 'cancel' ? 'windows_native_cancelled' : 'windows_native_deadline'));
    }
    assert.equal(h.calls.length, 0);
  }
});
test('post-mutation cancellation/lease loss/opaque errors refuse success as unknown', async () => {
  for (const method of ['write', 'delete']) for (const mode of ['cancel', 'expire', 'lease', 'throw']) {
    const h = fixture(), ctx = context(), selected = lease(ctx);
    if (method === 'delete') h.credentialAt();
    const original = h.api[`${method}Credential`];
    const api = { ...h.api, [`${method}Credential`](...args) {
      const result = original(...args);
      if (mode === 'cancel') ctx.controller.abort(); else if (mode === 'expire') ctx.expire(); else if (mode === 'lease') selected.close();
      else throw new Error('private secret native detail');
      return result;
    } };
    const store = WindowsNativeStore.open(api, selected);
    assert.equal(await (method === 'write' ? store.write(reference, 'valid-key', ctx) : store.delete(reference, ctx)), 'unknown');
    assert.equal(h.calls.filter(row => row[0] === method).length, 1);
  }
});
test('opaque read errors/malformed injected results produce fixed errors without causes or hooks', async () => {
  const ctx = context(); let invoked = 0;
  for (const value of [{ status: 'present', key: '' }, { status: 'absent', extra: true },
    Object.defineProperty({}, 'status', { enumerable: true, get() { invoked++; return 'absent'; } }),
    new Proxy({}, { get() { invoked++; throw new Error('private'); } })]) {
    const store = WindowsNativeStore.open({ assertHealthy() {}, readCredential() { return value; } }, lease(ctx));
    await assert.rejects(store.read(reference, ctx), errorCode('windows_native_untrusted'));
  }
  const store = WindowsNativeStore.open({ assertHealthy() {}, readCredential() { throw new Error('private bearer material'); } }, lease(ctx));
  await assert.rejects(store.read(reference, ctx), error => { assert.equal(error.message.includes('bearer'), false); return errorCode('windows_native_unavailable')(error); });
  assert.equal(invoked, 0);
});

test('late foreign collision retains enrollment intent and recovery never deletes its mismatched marker', async () => {
  const h = fixture(), ctx = context(); let nativeReads = 0, snapshot = null;
  const rawRead = h.bindings.read; h.bindings.read = (...args) => {
    if (++nativeReads === 2) h.credentialAt('valid-looking-foreign-key', malformed.wrongMarker);
    return rawRead(...args);
  };
  const ids = [reference.profile_id, reference.credential_ref,
    '33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444'];
  const store = WindowsNativeStore.open(h.api, lease(ctx));
  const transactions = new NativeProfileTransactions({ store, lease: { async runExclusive(_store, _name, _context, work) { return work(); } },
    snapshots: { async load() { return snapshot; }, async publish(_name, _revision, next) { snapshot = next; return 'committed'; } },
    async readIdentity() { return { project_id: 'project', organization_id: 'org', key_id: 'key-id', key_type: 'secret', is_test_mode: false, scope_mode: 'project_secret', scopes: null }; },
    newId() { return ids.shift(); },
  });
  await assert.rejects(transactions.enroll({ name: 'synthetic-profile', apiOrigin: 'https://api.bota.dev', key: 'new-key' }, ctx), errorCode('profile_write_unknown'));
  assert.equal(snapshot.journal.operation, 'enroll'); assert.equal(snapshot.journal.phase, 'intent');
  await assert.rejects(transactions.recover('synthetic-profile', ctx), errorCode('profile_store_unavailable'));
  assert.equal(h.calls.some(row => row[0] === 'write' || row[0] === 'delete'), false);
  assert.equal(snapshot.journal.phase, 'intent');
});

for (const committed of [false, true]) {
  test(`valid store marker with a substituted key still fails current pinned identity (${committed ? 'committed recovery' : 'ready selection'})`, async () => {
    const h = fixture(), ctx = context(); h.credentialAt('different-synthetic-key');
    const store = WindowsNativeStore.open(h.api, lease(ctx));
    assert.equal((await store.read(reference, ctx)).status, 'present');
    const record = Object.freeze({ format_version: 2, name: 'synthetic-profile', store_id: WINDOWS_NATIVE_STORE_ID,
      api_origin: 'https://api.bota.dev', project_id: 'project', organization_id: 'org', key_id: 'pinned-key-id',
      allow_http_loopback: false, state: 'ready', ...reference });
    const snapshot = Object.freeze({ format_version: 1, revision: '44444444-4444-4444-8444-444444444444', record,
      journal: committed ? Object.freeze({ format_version: 1, transaction_id: '33333333-3333-4333-8333-333333333333',
        operation: 'enroll', phase: 'committed', desired: record }) : null });
    let actions = 0, publications = 0;
    const transactions = new NativeProfileTransactions({ store,
      lease: { async runExclusive(_store, _name, _context, work) { return work(); } },
      snapshots: { async load() { return snapshot; }, async publish() { publications++; return 'committed'; } },
      async readIdentity(_origin, key) {
        assert.equal(key, 'different-synthetic-key');
        return { project_id: 'project', organization_id: 'org', key_id: 'different-key-id', key_type: 'secret',
          is_test_mode: false, scope_mode: 'project_secret', scopes: null };
      },
    });
    await assert.rejects(committed ? transactions.recover('synthetic-profile', ctx)
      : transactions.withCredential('synthetic-profile', {}, ctx, async () => { actions++; }),
    error => { assert.equal(error.recovery_required, committed); return errorCode('profile_identity_mismatch')(error); });
    assert.equal(actions, 0); assert.equal(publications, 0);
    assert.equal(h.calls.some(row => row[0] === 'write' || row[0] === 'delete'), false);
  });
}
