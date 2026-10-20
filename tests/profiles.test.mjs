import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, mkdir, writeFile, rm, symlink, stat, chmod } from 'node:fs/promises';
import { join, relative, isAbsolute, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
  ProfileError, normalizeProfileOrigin, listEnvironmentProfiles,
  readEnvironmentProfile, removeEnvironmentProfile,
  enrollEnvironmentProfile, resolveEnvironmentProfile,
} from '../src/profiles.ts';

const credential = 'rk_PROFILE_CREDENTIAL_CANARY';
const origin = 'https://api.example.invalid';
const ids = { project_id: 'project:opaque-1', organization_id: 'org_opaque.1', key_id: 'key_opaque-1' };
const restricted = (scopes = []) => ({ ...ids, key_type: 'restricted', is_test_mode: false, scope_mode: 'restricted', scopes });
const secret = () => ({ ...ids, key_type: 'secret', is_test_mode: true, scope_mode: 'project_secret', scopes: null });
const env = () => ({ BOTA_API_KEY: credential });
const filename = name => `${Buffer.from(name).toString('hex')}.json`;

async function location(t) {
  const root = await mkdtemp(join(tmpdir(), 'bota-profile-contract-'));
  t.after(async () => {
    const path = relative(resolve(tmpdir()), root);
    assert.ok(path && !path.startsWith('..') && !isAbsolute(path));
    await rm(root, { recursive: true, force: true });
  });
  return { root, directory: join(root, 'metadata') };
}

function errorCode(code) {
  return error => {
    assert.ok(error instanceof ProfileError);
    assert.equal(error.code, code);
    assert.doesNotMatch(String(error), /CANARY|example\.invalid|https?:\/\//);
    assert.equal(error.cause, undefined);
    return true;
  };
}

async function enrolled(t, extra = {}) {
  const paths = await location(t);
  const profile = await enrollEnvironmentProfile({ name: 'work', apiUrl: origin, env: env(), readIdentity: async () => restricted(), ...paths, ...extra });
  return { ...paths, profile };
}

test('environment enrollment verifies once, stores only routing metadata and handles portable reserved labels', async t => {
  const { directory } = await location(t);
  const calls = [];
  for (const [name, identity] of [['work', restricted(['devices:read'])], ['con', secret()]]) {
    const result = await enrollEnvironmentProfile({ name, apiUrl: 'HTTPS://API.EXAMPLE.INVALID:443/', env: env(), directory,
      readIdentity: async (...args) => { calls.push(args); return { ...identity, raw_key: credential, extra: 'EXTRA_CANARY' }; } });
    assert.deepEqual(result, { name, format_version: 1, api_origin: origin, project_id: ids.project_id,
      organization_id: ids.organization_id, credential_source: 'environment', allow_http_loopback: false });
    const content = await readFile(join(directory, filename(name)), 'utf8');
    assert.deepEqual(JSON.parse(content), result);
    assert.doesNotMatch(content, /CANARY|key_id|scopes|is_test_mode|key_type/);
    assert.equal((await stat(join(directory, filename(name)))).isFile(), true);
  }
  assert.deepEqual(calls, [[origin, credential], [origin, credential]]);
  assert.deepEqual((await listEnvironmentProfiles(directory)).map(profile => profile.name), ['con', 'work']);
  assert.equal((await readdir(directory)).length, 2);
});

test('local list/read/remove never need an environment credential or identity request', async t => {
  const { directory, profile } = await enrolled(t);
  assert.deepEqual(await listEnvironmentProfiles(directory), [profile]);
  assert.deepEqual(await readEnvironmentProfile('work', directory), profile);
  await removeEnvironmentProfile('work', directory);
  assert.deepEqual(await listEnvironmentProfiles(directory), []);
  await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_not_found'));
  await assert.rejects(removeEnvironmentProfile('work', directory), errorCode('profile_not_found'));
  const missing = join(directory, 'not-created');
  assert.deepEqual(await listEnvironmentProfiles(missing), []);
  await assert.rejects(stat(missing), { code: 'ENOENT' });
});

test('existing names refuse replacement before credential access or identity and preserve exact file bytes', async t => {
  const { directory } = await enrolled(t);
  const before = await readFile(join(directory, filename('work')));
  const guardedEnv = Object.defineProperty({}, 'BOTA_API_KEY', { get() { assert.fail('No key access for existing profile'); } });
  await assert.rejects(enrollEnvironmentProfile({ name: 'work', apiUrl: origin, env: guardedEnv, directory,
    readIdentity: async () => assert.fail('No network for existing profile') }), errorCode('profile_exists'));
  assert.deepEqual(await readFile(join(directory, filename('work'))), before);
});

test('profile resolution uses only the explicitly injected key and preserves exact restricted grant metadata', async t => {
  const { directory, profile } = await enrolled(t);
  const value = restricted(['custom:future', 'custom:future', 'line\n\u001b\u202e']);
  const calls = [];
  const result = await resolveEnvironmentProfile({ name: 'work', directory, env: { ...env(), BOTA_API_URL: 'https://API.EXAMPLE.INVALID:443/' },
    apiUrlOverride: `${origin}/`, readIdentity: async (...args) => { calls.push(args); return value; } });
  assert.deepEqual(result, { profile, apiKey: credential, apiUrl: origin, identity: value });
  assert.notEqual(result.identity, value);
  assert.notEqual(result.identity.scopes, value.scopes);
  assert.deepEqual(calls, [[origin, credential]]);
});

test('every mismatched origin refuses before environment key access and identity', async t => {
  const { directory } = await enrolled(t);
  for (const options of [
    { apiUrlOverride: 'https://different.invalid' },
    { environmentOrigin: 'https://different.invalid' },
    { apiUrlOverride: origin, environmentOrigin: 'https://different.invalid' },
    { apiUrlOverride: 'http://127.0.0.1:9999' },
    { environmentOrigin: '' },
  ]) {
    const source = Object.defineProperty({}, 'BOTA_API_KEY', { get() { assert.fail('Key read before origin refusal'); } });
    if (options.environmentOrigin !== undefined) source.BOTA_API_URL = options.environmentOrigin;
    await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: source,
      apiUrlOverride: options.apiUrlOverride, readIdentity: async () => assert.fail('Unexpected identity') }),
    error => { assert.ok(error instanceof ProfileError); assert.ok(['profile_origin_mismatch', 'profile_invalid_origin'].includes(error.code)); return true; });
  }
});

test('missing, empty and malformed selected environment keys never fall back or issue identity', async t => {
  const { directory } = await enrolled(t);
  for (const [source, code] of [
    [{}, 'profile_key_required'], [{ BOTA_API_KEY: '' }, 'profile_invalid_key'],
    [{ BOTA_API_KEY: 'contains space' }, 'profile_invalid_key'], [{ BOTA_API_KEY: 'line\n' }, 'profile_invalid_key'],
    [{ BOTA_API_KEY: 'NUL\0CANARY' }, 'profile_invalid_key'], [{ BOTA_API_KEY: 'nonASCIIé' }, 'profile_invalid_key'],
    [{ BOTA_API_KEY: 'x'.repeat(16385) }, 'profile_invalid_key'],
    [Object.create({ BOTA_API_KEY: credential }), 'profile_key_required'],
  ]) {
    await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: source,
      readIdentity: async () => assert.fail('Invalid selected key must not cause network') }), errorCode(code));
  }
  const source = Object.defineProperty({}, 'BOTA_API_KEY', { get() { throw new Error(credential); } });
  await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: source, readIdentity: async () => restricted() }), errorCode('profile_invalid_key'));
});

test('enrollment also refuses a conflicting environment origin before accessing its key', async t => {
  const { directory } = await location(t);
  const source = Object.defineProperty({ BOTA_API_URL: 'https://different.invalid' }, 'BOTA_API_KEY', {
    get() { assert.fail('Enrollment must compare the environment origin before key access'); },
  });
  await assert.rejects(enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: source,
    readIdentity: async () => assert.fail('Conflicting origins must refuse before identity') }), errorCode('profile_origin_mismatch'));
  await assert.rejects(stat(directory), { code: 'ENOENT' });
});

test('HTTP loopback is explicit, literal, persisted and limited to the enrolled origin', async t => {
  const { directory } = await location(t);
  for (const [name, apiUrl] of [['v4', 'http://127.0.0.1:4321'], ['v6', 'http://[::1]:4321']]) {
    await assert.rejects(enrollEnvironmentProfile({ name, apiUrl, directory, env: env(), readIdentity: async () => restricted() }), errorCode('profile_invalid_origin'));
    await enrollEnvironmentProfile({ name, apiUrl, allowHttpLoopback: true, directory, env: env(), readIdentity: async () => restricted() });
    const result = await resolveEnvironmentProfile({ name, directory, env: env(), readIdentity: async () => restricted() });
    assert.equal(result.apiUrl, apiUrl);
    assert.equal(result.profile.allow_http_loopback, true);
  }
  await assert.rejects(resolveEnvironmentProfile({ name: 'v4', directory, apiUrlOverride: 'http://127.0.0.1:4322', env: env(),
    readIdentity: async () => assert.fail('Mismatch must refuse') }), errorCode('profile_origin_mismatch'));
});

test('origin normalization refuses non-origin URLs, parsing ambiguities and nonliteral loopback forms', () => {
  assert.equal(normalizeProfileOrigin('https://EXAMPLE.invalid:443/'), 'https://example.invalid');
  for (const value of [undefined, '', ' https://example.invalid', 'https://example.invalid ', 'https://user:pass@example.invalid',
    'https://example.invalid/v1', 'https://example.invalid/a/..', 'https://example.invalid/%2e%2e',
    'https://example.invalid/?q=1', 'https://example.invalid/#fragment', 'https://example.invalid?', 'https://example.invalid#',
    'https://@example.invalid', 'https:///example.invalid',
    'https://example.invalid\\evil', 'https://example.invalid:0', 'file:///tmp/x', 'http://localhost:80',
    'http://127.1:80', 'http://2130706433', 'http://0x7f000001', 'http://[0:0:0:0:0:0:0:1]',
    'http://0.0.0.0:80', 'http://192.168.1.1:80', 'https://example.invalid/\n', 'https://' + 'a'.repeat(2050)]) {
    assert.throws(() => normalizeProfileOrigin(value, true), errorCode('profile_invalid_origin'));
  }
});

test('project and organization mismatch fail without rewriting profile metadata', async t => {
  const { directory } = await enrolled(t);
  const before = await readFile(join(directory, filename('work')));
  for (const value of [{ ...restricted(), project_id: 'different_project' }, { ...secret(), organization_id: 'different_org' }]) {
    await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: env(), readIdentity: async () => value }), errorCode('profile_identity_mismatch'));
  }
  assert.deepEqual(await readFile(join(directory, filename('work'))), before);
});

test('credential reflection through an operator-supplied name or origin refuses before identity or persistence', async t => {
  const { directory } = await location(t);
  const apiKey = 'private-profile-key';
  for (const options of [
    { name: apiKey, apiUrl: origin },
    { name: 'work', apiUrl: `https://${apiKey}.invalid` },
  ]) {
    await assert.rejects(enrollEnvironmentProfile({ ...options, directory, env: { BOTA_API_KEY: apiKey },
      readIdentity: async () => assert.fail('Reflected key must not be sent in an identity URL') }), errorCode('profile_invalid_key'));
  }
  await assert.rejects(stat(directory), { code: 'ENOENT' });
  await enrollEnvironmentProfile({ name: 'work', apiUrl: `https://${apiKey}.invalid`, directory, env: env(), readIdentity: async () => restricted() });
  await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: { BOTA_API_KEY: apiKey },
    readIdentity: async () => assert.fail('Current key reflected by stored routing metadata must refuse') }), errorCode('profile_invalid_metadata'));
});

test('identity reader errors and malformed/reflected identity cannot persist or expose credentials', async t => {
  const { directory } = await location(t);
  const invalid = [null, [], {}, { ...restricted(), key_type: 'end_user_token' }, { ...restricted(), is_test_mode: 'false' },
    { ...restricted(), scopes: [1] }, { ...restricted(), scope_mode: 'project_secret' }, { ...secret(), scopes: [] },
    { ...restricted(), project_id: credential }, { ...restricted(), key_id: `prefix_${credential}` },
    { ...restricted(), scopes: [`grant:${credential}`] }, { ...restricted(), organization_id: '' },
    { ...restricted(), project_id: 'x'.repeat(2049) }, { ...restricted(), project_id: 'é'.repeat(1025) }];
  for (const value of invalid) {
    await assert.rejects(enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(), readIdentity: async () => value }), errorCode('profile_identity_failed'));
    assert.deepEqual(await listEnvironmentProfiles(directory), []);
  }
  await assert.rejects(enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(),
    readIdentity: async () => { throw new Error(`${credential} ${origin}`); } }), errorCode('profile_identity_failed'));
  await assert.rejects(stat(directory), { code: 'ENOENT' });
});

test('strict metadata rejects unknown fields, invalid versions/domains and tampering rather than falling back', async t => {
  const { directory, profile } = await enrolled(t);
  for (const value of [[], null, { ...profile, apiKey: credential }, { ...profile, format_version: 2 },
    { ...profile, name: 'other' }, { ...profile, credential_source: 'legacy' },
    { ...profile, api_origin: `${origin}/` }, { ...profile, allow_http_loopback: 'false' },
    { ...profile, organization_id: '' }, { ...profile, project_id: 'a'.repeat(2049) },
    { ...profile, api_origin: 'http://localhost:9999', allow_http_loopback: true }]) {
    await writeFile(join(directory, filename('work')), JSON.stringify(value));
    await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_invalid_metadata'));
    await assert.rejects(resolveEnvironmentProfile({ name: 'work', directory, env: env(), readIdentity: async () => assert.fail('Invalid metadata must refuse') }), errorCode('profile_invalid_metadata'));
  }
  for (const value of ['', '{', 'x'.repeat(8193), Buffer.from([0xff, 0xfe])]) {
    await writeFile(join(directory, filename('work')), value);
    await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_invalid_metadata'));
  }
});

test('opaque Unicode, slash and control IDs retain exact values without acquiring format semantics', async t => {
  const { directory } = await location(t);
  const identity = { ...restricted(), project_id: '项目/opaque\n\u0085\u202e', organization_id: 'org/é\0\t\u2066', key_id: 'clé/\n\u202e' };
  const profile = await enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(), readIdentity: async () => identity });
  assert.equal(profile.project_id, identity.project_id);
  assert.equal(profile.organization_id, identity.organization_id);
  assert.deepEqual(await readEnvironmentProfile('work', directory), profile);
  assert.deepEqual((await resolveEnvironmentProfile({ name: 'work', directory, env: env(), readIdentity: async () => identity })).identity, identity);
  const content = await readFile(join(directory, filename('work')), 'utf8');
  assert.doesNotMatch(content, /[\u0000-\u0009\u000b-\u001f]/);
  assert.equal(JSON.parse(content).organization_id, identity.organization_id);
});

test('serialized metadata byte bound is enforced before any publication even when individual opaque IDs fit', async t => {
  const { directory } = await location(t);
  await assert.rejects(enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(),
    readIdentity: async () => ({ ...restricted(), project_id: '\0'.repeat(2048), organization_id: '\0'.repeat(2048) }) }), errorCode('profile_invalid_metadata'));
  await assert.rejects(stat(directory), { code: 'ENOENT' });
});

test('POSIX metadata files and all writable nonsticky ancestors refuse unsafe routing ownership', { skip: process.platform === 'win32' }, async t => {
  const { directory, root } = await enrolled(t);
  const path = join(directory, filename('work'));
  try {
    await chmod(path, 0o666);
    await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_unavailable'));
    await chmod(path, 0o600);
    await chmod(directory, 0o777);
    await assert.rejects(listEnvironmentProfiles(directory), errorCode('profile_unavailable'));
    await chmod(directory, 0o700);
    await chmod(root, 0o777);
    await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_unavailable'));
    await assert.rejects(enrollEnvironmentProfile({ name: 'other', apiUrl: origin, directory, env: env(),
      readIdentity: async () => assert.fail('Unsafe ancestor must refuse before credential use') }), errorCode('profile_unavailable'));
  } finally { await chmod(root, 0o700); await chmod(directory, 0o700); await chmod(path, 0o600); }
});

test('invalid names fail before any directory creation or identity access', async t => {
  const { directory } = await location(t);
  for (const name of ['', 'UPPER', 'a/b', '..', 'a\\b', 'a.b', 'a b', 'é', 'x'.repeat(65)]) {
    await assert.rejects(enrollEnvironmentProfile({ name, apiUrl: origin, directory, env: env(), readIdentity: async () => assert.fail('Unexpected identity') }), errorCode('profile_invalid_name'));
    await assert.rejects(readEnvironmentProfile(name, directory), errorCode('profile_invalid_name'));
    await assert.rejects(removeEnvironmentProfile(name, directory), errorCode('profile_invalid_name'));
  }
  await assert.rejects(stat(directory), { code: 'ENOENT' });
});

test('directory links/junctions and final profile links refuse without following their targets', async t => {
  const { root, directory, profile } = await enrolled(t);
  const alias = join(root, 'alias');
  await symlink(directory, alias, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(listEnvironmentProfiles(alias), errorCode('profile_unavailable'));
  await assert.rejects(readEnvironmentProfile('work', alias), errorCode('profile_unavailable'));
  await assert.rejects(removeEnvironmentProfile('work', alias), errorCode('profile_unavailable'));
  const linkedFile = join(directory, filename('linked'));
  // A directory junction at a final file path can be created without Windows
  // symlink privilege, and must never be treated as profile metadata.
  await symlink(directory, linkedFile, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(readEnvironmentProfile('linked', directory), errorCode('profile_unavailable'));
  await assert.rejects(removeEnvironmentProfile('linked', directory), errorCode('profile_unavailable'));
  assert.deepEqual(await readEnvironmentProfile('work', directory), profile);
  await rm(linkedFile);
  await mkdir(linkedFile);
  await assert.rejects(readEnvironmentProfile('linked', directory), errorCode('profile_unavailable'));
});

test('orphan temporary files are ignored and uncertain per-profile mutation locks are not stolen', async t => {
  const { directory, profile } = await enrolled(t);
  await writeFile(join(directory, '.profile-orphan.tmp'), '{"interrupted":');
  await mkdir(join(directory, `.${Buffer.from('work').toString('hex')}.lock`));
  await assert.rejects(removeEnvironmentProfile('work', directory), errorCode('profile_busy'));
  assert.deepEqual(await readEnvironmentProfile('work', directory), profile);
  assert.deepEqual(await listEnvironmentProfiles(directory), [profile]);
  await mkdir(join(directory, `.${Buffer.from('new').toString('hex')}.lock`));
  await assert.rejects(enrollEnvironmentProfile({ name: 'new', apiUrl: origin, directory, env: env(), readIdentity: async () => restricted() }), errorCode('profile_busy'));
  assert.equal(await readFile(join(directory, '.profile-orphan.tmp'), 'utf8'), '{"interrupted":');
  assert.ok((await stat(join(directory, `.${Buffer.from('new').toString('hex')}.lock`))).isDirectory());
});

test('concurrent enrollment has one complete winner and no implicit replacement or temporary selection', async t => {
  const { directory } = await location(t);
  let arrived = 0;
  let release;
  const barrier = new Promise(resolveBarrier => { release = resolveBarrier; });
  const attempts = Array.from({ length: 8 }, (_, index) => enrollEnvironmentProfile({ name: 'race', apiUrl: origin, directory, env: env(),
    readIdentity: async () => { if (++arrived === 8) release(); await barrier; return { ...restricted(), project_id: `project_${index}` }; } }));
  const results = await Promise.allSettled(attempts);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  for (const result of results.filter(result => result.status === 'rejected')) {
    assert.ok(result.reason instanceof ProfileError);
    assert.ok(['profile_busy', 'profile_exists'].includes(result.reason.code));
  }
  const winner = results.find(result => result.status === 'fulfilled').value;
  assert.deepEqual(await readEnvironmentProfile('race', directory), winner);
  assert.deepEqual(await listEnvironmentProfiles(directory), [winner]);
  assert.deepEqual(await readdir(directory), [filename('race')]);
});

test('concurrent remove then enrollment never deletes a subsequently committed profile revision', async t => {
  const { directory } = await enrolled(t);
  for (let index = 0; index < 8; index++) {
    const removed = removeEnvironmentProfile('work', directory);
    const added = enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(),
      readIdentity: async () => ({ ...restricted(), project_id: `replacement_${index}` }) });
    const results = await Promise.allSettled([removed, added]);
    assert.equal(results[0].status, 'fulfilled');
    if (results[1].status === 'fulfilled') assert.deepEqual(await readEnvironmentProfile('work', directory), results[1].value);
    else {
      assert.ok(['profile_exists', 'profile_busy'].includes(results[1].reason.code));
      await assert.rejects(readEnvironmentProfile('work', directory), errorCode('profile_not_found'));
      await enrollEnvironmentProfile({ name: 'work', apiUrl: origin, directory, env: env(), readIdentity: async () => restricted() });
    }
  }
});

test('actual process interruption before and after exclusive publication leaves no partially active metadata', async t => {
  const { root } = await location(t);
  const childEnv = {};
  for (const name of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'PATHEXT', 'COMSPEC', 'LANG']) {
    if (process.env[name] !== undefined) childEnv[name] = process.env[name];
  }
  const script = `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    const original = fs.link;
    fs.link = async (...args) => {
      if (process.argv[2] === 'before') process.exit(23);
      await original(...args);
      process.exit(24);
    };
    syncBuiltinESMExports();
    const { enrollEnvironmentProfile } = await import('./src/profiles.ts');
    await enrollEnvironmentProfile({ name:'work', apiUrl:'https://api.example.invalid',
      directory:process.argv[1], env:{ BOTA_API_KEY:'rk_PROFILE_CREDENTIAL_CANARY' },
      readIdentity:async()=>(${JSON.stringify(restricted())}) });
    process.exit(99);
  `;
  for (const phase of ['before', 'after']) {
    const directory = join(root, phase);
    const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script, directory, phase], {
      cwd: new URL('..', import.meta.url), env: childEnv, encoding: 'utf8', timeout: 10000, windowsHide: true,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, phase === 'before' ? 23 : 24, child.stderr);
    assert.equal(child.stdout, '');
    assert.equal(child.stderr, '');
    const entries = await readdir(directory);
    assert.equal(entries.filter(name => name.endsWith('.tmp')).length, 1);
    assert.equal(entries.filter(name => name.endsWith('.lock')).length, 1);
    const temporary = await readFile(join(directory, entries.find(name => name.endsWith('.tmp'))), 'utf8');
    assert.doesNotMatch(temporary, /CANARY|key_id|scopes/);
    assert.equal(JSON.parse(temporary).credential_source, 'environment');
    if (phase === 'before') assert.deepEqual(await listEnvironmentProfiles(directory), []);
    else {
      const active = await readEnvironmentProfile('work', directory);
      assert.equal(active.project_id, ids.project_id);
      assert.equal((await listEnvironmentProfiles(directory)).length, 1);
      await assert.rejects(removeEnvironmentProfile('work', directory), errorCode('profile_busy'));
    }
    assert.equal((await readdir(directory)).filter(name => name.endsWith('.tmp')).length, 1, 'Interrupted owned temporary metadata is not auto-deleted');
  }
});
