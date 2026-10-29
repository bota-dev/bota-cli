import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertInstalledPackage, assertRegistryManifest } from './registry-release.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run this check through npm run verify:package.');
const execute = promisify(execFile);
const artifact = join(root, '.release');
await mkdir(join(artifact, 'consumer'), { recursive: true });
const temporary = await mkdtemp(join(tmpdir(), 'bota-cli-release-'));
const consumer = join(temporary, 'consumer');
const home = join(temporary, 'home');
await mkdir(consumer); await mkdir(home);
for (const name of ['user.npmrc', 'global.npmrc']) await writeFile(join(temporary, name), '');
// Allow OS/runtime essentials only. This also excludes credential-bearing proxy,
// database/session variables and differently cased Node options on Windows.
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  /^(PATHEXT|SYSTEMROOT|WINDIR|COMSPEC|SYSTEMDRIVE|LANG|LC_ALL|TZ)$/i.test(key)));
Object.assign(env, { HOME: home, USERPROFILE: home, PATH: `${dirname(process.execPath)}${process.platform === 'win32' ? ';' : ':'}${process.env.PATH ?? ''}`,
  TEMP: temporary, TMP: temporary,
  npm_config_userconfig: join(temporary, 'user.npmrc'), npm_config_globalconfig: join(temporary, 'global.npmrc'),
  npm_config_cache: join(artifact, 'npm-cache'), npm_config_registry: 'https://registry.npmjs.org', NO_COLOR: '1', FORCE_COLOR: '0' });
const run = (command, args, cwd = consumer, extraEnv = {}) => execute(command, args, { cwd, env: { ...env, ...extraEnv }, timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
const npm = (args, cwd = consumer, extraEnv) => run(process.execPath, [npmCli, ...args], cwd, extraEnv);
let server;
try {
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const provenanceBytes = await readFile(join(root, 'dist/release.json'));
  const provenance = JSON.parse(provenanceBytes);
  const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
  assert.equal(sha256(await readFile(join(root, 'dist/index.js'))), provenance.bundle_sha256, 'prepared bundle must match provenance');
  for (const [path, hash] of Object.entries(provenance.inputs)) assert.equal(sha256(await readFile(join(root, path))), hash, 'prepared source inputs must remain unchanged');
  console.log('Packing the prepared candidate with lifecycle scripts disabled.');
  const packed = JSON.parse((await npm(['pack', '--ignore-scripts', '--json', '--pack-destination', artifact], root)).stdout)[0];
  assert.equal(packed.name, pkg.name); assert.equal(packed.version, pkg.version);
  const expected = ['README.md', 'dist/index.js', 'dist/release.json', 'dist/THIRD_PARTY_NOTICES.txt', 'package.json'];
  if (provenance.source_license) expected.push('LICENSE');
  assert.deepEqual(packed.files.map(file => file.path).sort(), expected.sort(), 'only approved package files may ship');
  const tarball = join(artifact, packed.filename);
  const bytes = await readFile(tarball);
  assert.equal(`sha512-${createHash('sha512').update(bytes).digest('base64')}`, packed.integrity);
  // Exercise npm's actual tarball-manifest normalization. The registry fields
  // below are a synthetic projection only, not published provenance evidence.
  const normalized = await createRequire(npmCli)('pacote').manifest(tarball, {
    cache: join(temporary, 'manifest-cache'), fullMetadata: true, fullReadJson: true,
  });
  assertRegistryManifest({ ...normalized, dist: { tarball: `https://registry.npmjs.org/@bota.dev/cli/-/cli-${pkg.version}.tgz`, integrity: packed.integrity,
    attestations: { url: `https://registry.npmjs.org/-/npm/v1/attestations/@bota.dev%2fcli@${pkg.version}`, provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } },
  pkg, { name: pkg.name, version: pkg.version, integrity: packed.integrity, sha256: sha256(bytes) }, bytes);
  await copyFile(tarball, join(temporary, packed.filename));
  const manifest = { name: 'bota-cli-packed-consumer', version: '0.0.0', private: true, dependencies: { [pkg.name]: `file:../${packed.filename}` } };
  await writeFile(join(consumer, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log('Resolving a temporary consumer lock, then installing with npm ci --ignore-scripts.');
  await npm(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
  const frozenLock = await readFile(join(consumer, 'package-lock.json'));
  await npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund']);
  assert.deepEqual(await readFile(join(consumer, 'package-lock.json')), frozenLock, 'frozen consumer installation cannot rewrite its lock');
  const installed = JSON.parse(await readFile(join(consumer, 'node_modules/@bota.dev/cli/package.json'), 'utf8'));
  await assertInstalledPackage(consumer, root, pkg);
  // This genuine consumer installs the CLI from a file, so npm excludes that
  // local package from registry verification. Its public dependency graph must
  // nevertheless pass the same no-missing/no-invalid signature gate used later.
  const publicSignatureBytes = (await npm(['audit', 'signatures', '--json', '--include-attestations'])).stdout;
  const publicSignatures = JSON.parse(publicSignatureBytes);
  assert.deepEqual(publicSignatures.invalid, []); assert.deepEqual(publicSignatures.missing, []);
  assert.ok(Array.isArray(publicSignatures.verified));
  assert.equal(installed.version, pkg.version); assert.deepEqual(installed.dependencies, pkg.dependencies);
  assert.equal(installed.license, pkg.license, 'installed source-license identifier must match the package manifest');
  if (provenance.source_license) {
    const license = await readFile(join(root, 'LICENSE'));
    assert.equal(provenance.source_license.identifier, pkg.license);
    assert.equal(sha256(license), provenance.source_license.sha256, 'source license must match its provenance digest');
    assert.deepEqual(await readFile(join(consumer, 'node_modules/@bota.dev/cli/LICENSE')), license,
      'the installed package must retain the exact source license grant');
  }
  const installedProvenanceBytes = await readFile(join(consumer, 'node_modules/@bota.dev/cli/dist/release.json'));
  assert.deepEqual(installedProvenanceBytes, provenanceBytes);
  const installedProvenance = JSON.parse(installedProvenanceBytes);
  assert.deepEqual(installedProvenance, provenance);
  assert.equal(sha256(await readFile(join(consumer, 'node_modules/@bota.dev/cli/dist/index.js'))), provenance.bundle_sha256);
  assert.equal(sha256(await readFile(join(consumer, 'node_modules/@bota.dev/cli/dist/THIRD_PARTY_NOTICES.txt'))), provenance.notices_sha256);
  const cli = (args, extraEnv) => npm(['exec', '--offline', '--', 'bota', ...args], consumer, extraEnv);
  assert.equal((await cli(['--version'])).stdout.trim(), pkg.version);
  assert.equal((await run(process.execPath, ['--import', 'tsx', 'src/index.ts', '--version'], root)).stdout.trim(), pkg.version);
  assert.match((await cli(['--help'])).stdout, /Bota developer CLI/);
  assert.match((await cli(['mcp', '--mode', 'hosted', '--help'])).stdout, /--mode/);
  const loginHelp = await cli(['auth', 'login', '--help']);
  assert.match(loginHelp.stdout, /--no-browser/); assert.equal(loginHelp.stderr, '');
  const secureHelp = await cli(['auth', 'secure-profiles', '--help']);
  assert.match(secureHelp.stdout, /add.*name/); assert.match(secureHelp.stdout, /recover.*name/);
  assert.match(secureHelp.stdout, /migrate.*name/); assert.match(secureHelp.stdout, /list/);
  assert.equal(secureHelp.stderr, '', 'help must not bootstrap optional native storage');
  const migrationHelp = await cli(['auth', 'secure-profiles', 'migrate', '--help']);
  assert.match(migrationHelp.stdout, /--from-env/); assert.equal(migrationHelp.stderr, '');
  // Run the actual installed executable, with tripwires installed BEFORE its
  // entrypoint. HOME above remains legacy-config isolation only: it does not
  // relocate the new OS-selected native root or Credential Manager namespace.
  const guard = join(root, 'scripts/packed-developer-guard.mjs');
  const guardDirectory = join(temporary, 'developer-guards'); await mkdir(guardDirectory);
  assert.deepEqual(installed.bin, pkg.bin);
  const installedEntry = resolve(consumer, 'node_modules/@bota.dev/cli', installed.bin.bota);
  assert.equal(installedEntry, resolve(consumer, 'node_modules/@bota.dev/cli/dist/index.js'));
  const developerName = 'packed-dev-' + randomUUID(), developerProbes = [];
  const effectKeys = ['process_spawn', 'process_control', 'worker_spawn', 'network_request', 'network_listen',
    'native_module', 'filesystem_read', 'filesystem_write'].sort();
  const developerCommands = [
    ['auth', 'login', '--identity-only'],
    ['auth', 'login', '--identity-only', '--no-browser'],
    ['--developer-profile', developerName, 'auth', 'status'],
    ['--developer-profile', developerName, 'devices', 'list'],
    ['--developer-profile', developerName, 'mcp', '--mode', 'hosted'],
    ['auth', 'developer-profiles', 'list'],
    ['auth', 'developer-profiles', 'show', developerName],
    ['auth', 'developer-profiles', 'recover', developerName],
    ['auth', 'developer-profiles', 'logout', developerName],
    ['--developer-profile', developerName, 'auth', 'logout'],
  ];
  console.log('Checking installed Platform configuration refusal under pre-entrypoint effect tripwires.');
  for (const args of developerCommands) {
    const report = join(guardDirectory, 'probe-' + randomUUID() + '.json');
    let refusal;
    try { await run(process.execPath, ['--import', pathToFileURL(guard).href, installedEntry, '--json', ...args], consumer, {
      BOTA_PACKED_GUARD_DIRECTORY: guardDirectory, BOTA_PACKED_GUARD_REPORT: report,
      BOTA_PACKED_GUARD_MODULES: join(consumer, 'node_modules'),
      BOTA_API_KEY: 'sk_test_SYNTHETIC_PACKED_DEVELOPER_CANARY',
    }); } catch (error) { refusal = error; }
    assert.ok(refusal, 'configuration-off command must refuse');
    assert.equal(refusal.code, 1); assert.equal(refusal.signal, null); assert.equal(refusal.killed, false);
    assert.equal(refusal.stdout, '', 'configuration refusal must publish no stdout');
    assert.doesNotMatch(refusal.stderr, /SYNTHETIC_PACKED_DEVELOPER_CANARY|ExperimentalWarning|SQLite|WinCred|koffi|native bootstrap/i);
    assert.deepEqual(JSON.parse(refusal.stderr), { error: {
      code: 'developer_configuration_unavailable', message: 'Platform developer login is not configured for this build.',
      recovery_required: false, operation_may_have_executed: false,
    } });
    const reportBytes = await readFile(report), observed = JSON.parse(reportBytes);
    assert.equal(observed.schema_version, 1); assert.equal(observed.instrument, 'packed-developer-default-off-v1');
    assert.equal(observed.installed_before_entrypoint, true); assert.equal(observed.exit_code, 1);
    assert.deepEqual(Object.keys(observed.effects).sort(), effectKeys);
    assert.ok(Object.values(observed.effects).every(count => count === 0), 'configuration refusal must precede every guarded effect attempt');
    assert.ok(Number.isSafeInteger(observed.permitted_linux_startup_metadata_reads) && observed.permitted_linux_startup_metadata_reads >= 0);
    developerProbes.push({ args, code: 'developer_configuration_unavailable', stdout_empty: true,
      effects: observed.effects, permitted_linux_startup_metadata_reads: observed.permitted_linux_startup_metadata_reads,
      report_sha256: sha256(reportBytes) });
  }
  const calls = [];
  const identity = { project_id: 'proj_release_fixture', organization_id: 'org_release_fixture', key_id: 'sk_release_identifier',
    key_type: 'restricted', is_test_mode: false, scope_mode: 'restricted', scopes: [] };
  server = createServer((request, response) => {
    calls.push(request.url); assert.equal(request.method, 'GET'); assert.equal(request.url, '/v1/auth/identity');
    assert.equal(request.headers.authorization, 'Bearer rk_SYNTHETIC_RELEASE_FIXTURE');
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(identity));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const result = await cli(['--api-url', `http://127.0.0.1:${server.address().port}`, 'auth', 'status', '--json'], { BOTA_API_KEY: 'rk_SYNTHETIC_RELEASE_FIXTURE' });
  assert.deepEqual(JSON.parse(result.stdout), identity); assert.equal(result.stderr, ''); assert.deepEqual(calls, ['/v1/auth/identity']);
  const profileOrigin = `http://127.0.0.1:${server.address().port}`;
  const keyEnvironment = { BOTA_API_KEY: 'rk_SYNTHETIC_RELEASE_FIXTURE' };
  const beforeSecureRefusals = calls.length;
  await assert.rejects(cli(['--json', '--profile', 'installed', '--secure-profile', 'installed', 'auth', 'status'], keyEnvironment), error => {
    assert.equal(JSON.parse(error.stderr).error.code, 'profile_selection_not_applicable'); return true;
  });
  await assert.rejects(cli(['--json', '--api-url', profileOrigin, 'auth', 'secure-profiles', 'migrate', 'installed'], keyEnvironment), error => {
    assert.equal(JSON.parse(error.stderr).error.code, 'invalid_secure_profile_command');
    assert.doesNotMatch(error.stdout + error.stderr, /rk_SYNTHETIC_RELEASE_FIXTURE/); return true;
  });
  await assert.rejects(cli(['--json', '--api-url', profileOrigin, 'auth', 'secure-profiles', 'add', 'installed-secure',
    '--from-env', '--allow-http-loopback'], { ...keyEnvironment, BOTA_API_URL: 'https://different.example.invalid' }), error => {
    const detail = JSON.parse(error.stderr).error;
    assert.equal(detail.code, 'profile_origin_mismatch'); assert.equal(detail.operation_may_have_executed, false);
    assert.doesNotMatch(error.stdout + error.stderr, /rk_SYNTHETIC_RELEASE_FIXTURE/); return true;
  });
  assert.equal(calls.length, beforeSecureRefusals, 'secure selector/origin refusals must precede identity and storage');
  const enrollment = await cli(['--api-url', profileOrigin, 'auth', 'profiles', 'add', 'installed', '--from-env', '--allow-http-loopback'], keyEnvironment);
  const metadata = JSON.parse(enrollment.stdout);
  assert.deepEqual(metadata, { name: 'installed', format_version: 1, api_origin: profileOrigin,
    project_id: identity.project_id, organization_id: identity.organization_id,
    credential_source: 'environment', allow_http_loopback: true });
  assert.equal(enrollment.stderr, '');
  const profileStatus = await cli(['--profile', 'installed', 'auth', 'status', '--json'], keyEnvironment);
  assert.deepEqual(JSON.parse(profileStatus.stdout), identity); assert.equal(profileStatus.stderr, '');
  assert.equal(calls.length, 3, 'one legacy status, enrollment, and selected profile status identity request');
  assert.deepEqual(JSON.parse((await cli(['auth', 'profiles', 'list', '--json'])).stdout), [metadata]);
  const beforeRemoval = calls.length;
  assert.deepEqual(JSON.parse((await cli(['auth', 'profiles', 'remove', 'installed'])).stdout), { removed: true });
  assert.equal(calls.length, beforeRemoval, 'metadata list/removal must not contact the API');
  assert.deepEqual(JSON.parse((await cli(['auth', 'profiles', 'list', '--json'])).stdout), []);
  const consumerLock = JSON.parse(frozenLock);
  assert.equal(consumerLock.packages['node_modules/@bota.dev/cli'].license, pkg.license,
    'the installed consumer lock must retain the source-license identifier');
  for (const [name, version] of Object.entries(pkg.dependencies)) assert.equal(consumerLock.packages[`node_modules/${name}`]?.version, version);
  await run(process.execPath, [join(root, 'scripts/check-licenses.mjs'), join(consumer, 'node_modules')]);
  const resolved = Object.fromEntries(Object.entries(consumerLock.packages).filter(([name]) => name).map(([name, data]) => [name, { version: data.version, integrity: data.integrity, license: data.license }]));
  await writeFile(join(artifact, 'consumer/package-lock.json'), frozenLock);
  await writeFile(join(artifact, 'consumer/package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const receipt = { schema_version: 1, name: pkg.name, version: pkg.version, filename: packed.filename, integrity: packed.integrity,
    sha256: createHash('sha256').update(bytes).digest('hex'), files: packed.files.map(file => file.path), source: provenance.source,
    prepared_provenance_sha256: sha256(installedProvenanceBytes),
    source_license: provenance.source_license, publication_blockers: provenance.publication_blockers,
    node: process.version, npm: (await npm(['--version'])).stdout.trim(),
    consumer_environment_keys: Object.keys(env).sort(),
    consumer_lock_sha256: createHash('sha256').update(frozenLock).digest('hex'), resolved_dependencies: resolved,
    public_dependency_signatures: { npm: (await npm(['--version'])).stdout.trim(), audit_sha256: sha256(publicSignatureBytes),
      invalid: 0, missing: 0, verified_attestations: publicSignatures.verified.length,
      scope: 'Public dependencies of the genuine file-installed CLI; the local CLI itself is not registry/provenance qualified.' },
    developer_configuration_off: { guard_sha256: sha256(await readFile(guard)), probes: developerProbes,
      scope: 'Installed production entrypoint and unchanged trusted resolver; guarded effect-attempt evidence, not actual native qualification.',
      limits: ['Node module-loader reads, six exact public Linux is-wsl/container metadata paths, parent installation/temporary cleanup and the captured guard-report writer are permitted.',
        'No adversarial-sandbox claim for direct internal bindings, previously captured runtime internals, process.exit or OS/runtime startup effects.',
        'Existing temporary HOME isolates legacy config only; no new native root, credential-store or endpoint redirection.'] },
    checks: ['packed-npm-manifest-policy-synthetic-registry-fields', 'installed-exact-file-bytes', 'public-dependency-registry-signatures', 'installed-version', 'source-version', 'installed-source-license', 'installed-help', 'installed-hosted-mode-help', 'installed-manual-browser-help-no-native-bootstrap', 'installed-secure-profile-help-no-native-bootstrap',
      'installed-secure-selector-refusal', 'installed-secure-origin-refusal-before-storage', 'synthetic-empty-scope-identity',
      'installed-secure-migration-explicit-input',
      'installed-environment-profile-enrollment', 'installed-profile-status-one-preflight', 'installed-profile-local-list-removal',
      'frozen-consumer-lock', 'installed-provenance', 'bundle-and-input-hashes', 'direct-runtime-versions', 'consumer-dependency-licenses',
      'installed-developer-configuration-off-pre-entrypoint-tripwires'] };
  await writeFile(join(artifact, 'package-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Packed consumer passed: ${pkg.name}@${pkg.version}; ${packed.files.length} package files. Publication remains ${provenance.publication_blockers.length ? 'BLOCKED (see receipt)' : 'subject to separate exact-source approval'}.`);
} finally {
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  if (dirname(resolve(temporary)) !== resolve(tmpdir()) || !basename(temporary).startsWith('bota-cli-release-')) throw new Error('Unexpected temporary consumer directory.');
  await rm(temporary, { recursive: true, force: true });
}
