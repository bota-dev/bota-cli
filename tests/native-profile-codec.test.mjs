import assert from 'node:assert/strict';
import test from 'node:test';
import {
  NATIVE_PROFILE_MAX_SNAPSHOT_BYTES,
  encodeNativeProfileSnapshot,
  decodeNativeProfileSnapshotBytes,
} from '../src/native-profile-codec.ts';
import { NativeProfileTransactionError } from '../src/native-profile-transaction.ts';

const canary = 'SYNTHETIC_CODEC_PRIVATE_CANARY';
const name = 'work', store = 'synthetic';
const ids = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004'];
const record = extra => ({ format_version: 2, name, store_id: store, api_origin: 'https://api.example.invalid',
  project_id: 'project:opaque', organization_id: 'org:opaque', key_id: 'key:stored', allow_http_loopback: false,
  state: 'ready', profile_id: ids[0], credential_ref: ids[1], ...extra });
const journal = (desired, extra) => ({ format_version: 1, transaction_id: ids[2], operation: 'enroll',
  phase: 'committed', desired, ...extra });
const snapshot = (saved = record(), pending = null) => ({ format_version: 1, revision: ids[3], record: saved, journal: pending });
const bytes = text => Buffer.from(text, 'utf8');
const decode = value => decodeNativeProfileSnapshotBytes(value, name, store);
const encode = value => encodeNativeProfileSnapshot(value, name, store);
const text = value => Buffer.from(value).toString('utf8');
const golden = '{"format_version":1,"revision":"00000000-0000-4000-8000-000000000004","record":{"format_version":2,"name":"work","store_id":"synthetic","api_origin":"https://api.example.invalid","project_id":"project:opaque","organization_id":"org:opaque","key_id":"key:stored","allow_http_loopback":false,"state":"ready","profile_id":"00000000-0000-4000-8000-000000000001","credential_ref":"00000000-0000-4000-8000-000000000002"},"journal":null}\n';
function failure(error) {
  assert.ok(error instanceof NativeProfileTransactionError); assert.equal(error.code, 'profile_invalid_metadata');
  assert.equal(error.cause, undefined);
  for (const rendered of [String(error), error.stack, JSON.stringify(error)]) assert.ok(!rendered.includes(canary));
  return true;
}
function refused(value) { assert.throws(() => decode(value), failure); }
function reversed(value) {
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reversed(item)]));
}

test('native codec has a fixed golden byte encoding and exactly one LF', () => {
  assert.equal(NATIVE_PROFILE_MAX_SNAPSHOT_BYTES, 24576);
  assert.equal(text(encode(snapshot())), golden); assert.deepEqual(decode(bytes(golden)), snapshot());
  assert.equal(text(encode(reversed(snapshot()))), golden, 'input property insertion order is not wire order');
});

for (const [state, value] of [
  ['enrollment intent', snapshot(null, journal(record(), { phase: 'intent' }))],
  ['committed enrollment', snapshot(record(), journal(record()))],
  ['ready', snapshot()],
  ['removal intent', snapshot(record({ state: 'disabled' }), journal(record({ state: 'disabled' }), { operation: 'remove', phase: 'intent' }))],
  ['removed tombstone', snapshot(record({ state: 'removed' }))],
]) {
  test(`native codec preserves the complete ${state} state and freezes decoded authority`, () => {
    const first = encode(value), decoded = decode(first), second = encode(decoded);
    assert.deepEqual(decoded, value); assert.deepEqual(second, first); assert.ok(Object.isFrozen(decoded));
    if (decoded.record) assert.ok(Object.isFrozen(decoded.record));
    if (decoded.journal) { assert.ok(Object.isFrozen(decoded.journal)); assert.ok(Object.isFrozen(decoded.journal.desired)); }
    assert.throws(() => { decoded.revision = ids[0]; }, TypeError);
  });
}

test('native codec preserves exact opaque Unicode/control/code-unit identities without normalization', () => {
  for (const id of ['项目/é/😀', 'e\u0301', 'line\n\t\u0000value', '\ud800', '\udc00', 'prefix\ud800suffix']) {
    const value = snapshot(record({ project_id: id })), encoded = encode(value);
    assert.equal(decode(encoded).record.project_id, id); assert.deepEqual(encode(decode(encoded)), encoded);
  }
  assert.match(text(encode(snapshot(record({ project_id: '\ud800' })))), /\\ud800/);
});

for (const [label, mutate] of [
  ['duplicate top-level key', raw => raw.replace('"format_version":1,', '"format_version":9,"format_version":1,')],
  ['equal duplicate key', raw => raw.replace('"name":"work",', '"name":"work","name":"work",')],
  ['escaped alias duplicate', raw => raw.replace('"name":"work",', '"\\u006eame":"foreign","name":"work",')],
  ['escaped key spelling', raw => raw.replace('"name":"work"', '"\\u006eame":"work"')],
  ['noncanonical number', raw => raw.replace('"format_version":1,', '"format_version":1.0,')],
  ['exponent number', raw => raw.replace('"format_version":1,', '"format_version":1e0,')],
  ['escaped value spelling', raw => raw.replace('"work"', '"\\u0077ork"')],
  ['escaped slash spelling', raw => raw.replace('https://', 'https:\\/\\/')],
  ['missing terminal LF', raw => raw.slice(0, -1)],
  ['CRLF', raw => raw.slice(0, -1) + '\r\n'],
  ['second LF', raw => raw + '\n'],
  ['leading whitespace', raw => ' ' + raw],
  ['internal whitespace', raw => raw.replace(':1,', ': 1,')],
  ['trailing object', raw => raw + '{}'],
]) {
  test(`native codec refuses ${label} rather than accepting JSON equivalence`, () => refused(bytes(mutate(golden))));
}

test('native codec refuses alternate field ordering and nested journal duplicate keys', () => {
  refused(bytes(JSON.stringify(reversed(snapshot())) + '\n'));
  const committed = text(encode(snapshot(record(), journal(record()))));
  refused(bytes(committed.replace('"phase":"committed",', '"phase":"intent","phase":"committed",')));
  refused(bytes(committed.replace('"desired":{', '"desired":{"name":"foreign",')));
});

test('native codec refuses BOM, malformed UTF-8 and byte-limit violations before permissive conversion', () => {
  refused(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes(golden)]));
  for (const invalid of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf0, 0x9f, 0x98]]) refused(Buffer.from(invalid));
  refused(new Uint8Array()); refused(new Uint8Array(24576)); refused(new Uint8Array(24577));
  refused(Buffer.concat([bytes(golden), Buffer.alloc(24577 - bytes(golden).length, 0x20)]));
});

test('native codec accepts Buffer subranges and owns all returned bytes and decoded metadata', () => {
  const allocation = Buffer.concat([bytes('before'), bytes(golden), bytes('after')]);
  const range = allocation.subarray(6, 6 + bytes(golden).length);
  const decoded = decode(range), first = encode(decoded), second = encode(decoded);
  assert.notEqual(first.buffer, second.buffer); first.fill(0); allocation.fill(0);
  assert.equal(text(second), golden); assert.deepEqual(decoded, snapshot()); assert.equal(text(encode(decoded)), golden);
});

test('native codec reads typed-array storage without overridden accessors or iterators', () => {
  const value = new Uint8Array(bytes(golden)); let hooks = 0;
  for (const field of ['length', 'byteLength', 'buffer', 'byteOffset', 'constructor']) Object.defineProperty(value, field, { get() { hooks++; throw new Error(canary); } });
  Object.defineProperty(value, Symbol.iterator, { get() { hooks++; throw new Error(canary); } });
  assert.deepEqual(decode(value), snapshot()); assert.equal(hooks, 0);
});

test('native codec refuses unsupported/proxied/shared byte containers without coercion', () => {
  let hooks = 0;
  const proxy = new Proxy(new Uint8Array(bytes(golden)), { get() { hooks++; throw new Error(canary); }, getPrototypeOf() { hooks++; throw new Error(canary); } });
  class BytesSubclass extends Uint8Array {}
  for (const value of [golden, [...bytes(golden)], new ArrayBuffer(8), new DataView(new ArrayBuffer(8)),
    new BytesSubclass(bytes(golden)), proxy, { toString() { hooks++; throw new Error(canary); } }, new Uint8Array(new SharedArrayBuffer(8))]) refused(value);
  assert.equal(hooks, 0);
});

test('native codec refuses malformed record/state/authority without retaining raw reflected fields', () => {
  const variants = [
    value => { value.record.secret = canary; }, value => { value.extra = canary; },
    value => { value.record = null; }, value => { value.record.state = 'disabled'; },
    value => { value.record.credential_ref = value.record.profile_id; }, value => { value.record.store_id = 'foreign'; },
    value => { value.record.project_id = canary.repeat(1000); }, value => { value.record.api_origin += '/path'; },
    value => { value.format_version = 2; }, value => { value.record.scopes = ['read']; },
  ];
  for (const mutate of variants) {
    const value = snapshot(); mutate(value); assert.throws(() => encode(value), failure); refused(bytes(JSON.stringify(value) + '\n'));
  }
  const pending = snapshot(record(), journal(record({ key_id: 'different' })));
  assert.throws(() => encode(pending), failure); refused(bytes(JSON.stringify(pending) + '\n'));
});

test('native codec rejects source accessors, proxies, classes, sparse shapes and cycles without hooks', () => {
  let hooks = 0;
  const accessor = snapshot(); Object.defineProperty(accessor, 'record', { enumerable: true, get() { hooks++; throw new Error(canary); } });
  const proxied = new Proxy(snapshot(), { ownKeys() { hooks++; throw new Error(canary); } });
  class Snapshot { constructor() { Object.assign(this, snapshot()); } }
  const cyclic = snapshot(); cyclic.record = cyclic;
  const hook = snapshot(); hook.toJSON = () => { hooks++; throw new Error(canary); };
  for (const value of [accessor, proxied, new Snapshot(), new Array(4), cyclic, hook]) assert.throws(() => encode(value), failure);
  assert.equal(hooks, 0);
});

test('native codec binds both caller name and fixed store without coercion or guessing', () => {
  let hooks = 0;
  for (const [selectedName, selectedStore] of [['other', store], [name, 'foreign'], ['', store], [name, ''], [name, 'A'],
    [{ toString() { hooks++; return name; } }, store], [name, { toString() { hooks++; return store; } }]]) {
    assert.throws(() => encodeNativeProfileSnapshot(snapshot(), selectedName, selectedStore), failure);
    assert.throws(() => decodeNativeProfileSnapshotBytes(bytes(golden), selectedName, selectedStore), failure);
  }
  assert.equal(hooks, 0);
});
