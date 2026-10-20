import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

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
  await copyFile(tarball, join(temporary, packed.filename));
  const manifest = { name: 'bota-cli-packed-consumer', version: '0.0.0', private: true, dependencies: { [pkg.name]: `file:../${packed.filename}` } };
  await writeFile(join(consumer, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log('Resolving a temporary consumer lock, then installing with npm ci --ignore-scripts.');
  await npm(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
  const frozenLock = await readFile(join(consumer, 'package-lock.json'));
  await npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund']);
  assert.deepEqual(await readFile(join(consumer, 'package-lock.json')), frozenLock, 'frozen consumer installation cannot rewrite its lock');
  const installed = JSON.parse(await readFile(join(consumer, 'node_modules/@bota.dev/cli/package.json'), 'utf8'));
  assert.equal(installed.version, pkg.version); assert.deepEqual(installed.dependencies, pkg.dependencies);
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
  const consumerLock = JSON.parse(frozenLock);
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
    checks: ['installed-version', 'source-version', 'installed-help', 'installed-hosted-mode-help', 'synthetic-empty-scope-identity', 'frozen-consumer-lock', 'installed-provenance', 'bundle-and-input-hashes', 'direct-runtime-versions', 'consumer-dependency-licenses'] };
  await writeFile(join(artifact, 'package-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Packed consumer passed: ${pkg.name}@${pkg.version}; ${packed.files.length} package files. Publication remains ${provenance.publication_blockers.length ? 'BLOCKED (see receipt)' : 'subject to separate exact-source approval'}.`);
} finally {
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  if (dirname(resolve(temporary)) !== resolve(tmpdir()) || !basename(temporary).startsWith('bota-cli-release-')) throw new Error('Unexpected temporary consumer directory.');
  await rm(temporary, { recursive: true, force: true });
}
