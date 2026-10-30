import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { releaseChannel, assertPublicationPrerequisites } from '../scripts/check-publication.mjs';
import { assertInstalledPackage, assertRegistryManifest, assertReleaseContext, assertReleaseTrust, assertTags, assertUnoccupiedVersion, assertVerifiedProvenance, readRegistryMetadata } from '../scripts/registry-release.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = '0.2.0-beta.0', commit = '1'.repeat(40);
const pkg = { name: '@bota.dev/cli', version, license: 'MIT', repository: { type: 'git', url: 'git+https://github.com/bota-dev/bota-cli.git' }, bin: { bota: 'dist/index.js' }, scripts: { test: 'synthetic-fixture' }, dependencies: { example: '1.2.3' }, publishConfig: { access: 'public' } };
const tarball = Buffer.from('Synthetic integrity bytes; not a published package.');
const receipt = { name: pkg.name, version, sha256: createHash('sha256').update(tarball).digest('hex'), integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}` };
const context = { tag: `v${version}`, commit, run: '123', attempt: '1' };
const clone = value => JSON.parse(JSON.stringify(value));
const packument = () => ({ name: pkg.name, versions: { '0.1.0': {} }, 'dist-tags': { latest: '0.1.0', historical: '0.1.0' } });
const manifest = () => ({ ...clone(pkg), dist: { tarball: `https://registry.npmjs.org/@bota.dev/cli/-/cli-${version}.tgz`, integrity: receipt.integrity,
  attestations: { url: `https://registry.npmjs.org/-/npm/v1/attestations/@bota.dev%2fcli@${version}`, provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } });
const statement = () => ({ _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
  subject: [{ name: `pkg:npm/%40bota.dev/cli@${version}`, digest: { sha512: Buffer.from(receipt.integrity.slice(7), 'base64').toString('hex') } }],
  predicate: { buildDefinition: { buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
    externalParameters: { workflow: { ref: `refs/tags/${context.tag}`, repository: 'https://github.com/bota-dev/bota-cli', path: '.github/workflows/publish.yml' } },
    internalParameters: { github: { event_name: 'push', repository_id: '1245303387', repository_owner_id: '252373912' } },
    resolvedDependencies: [{ uri: `git+https://github.com/bota-dev/bota-cli@refs/tags/${context.tag}`, digest: { gitCommit: commit } }] },
  runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' }, metadata: { invocationId: 'https://github.com/bota-dev/bota-cli/actions/runs/123/attempts/1' } } } });
const audit = (payload = statement()) => ({ invalid: [], missing: [], verified: [{ name: pkg.name, version, location: 'node_modules/@bota.dev/cli', registry: 'https://registry.npmjs.org/',
  attestationBundles: [{ predicateType: 'https://slsa.dev/provenance/v1', bundle: { dsseEnvelope: { payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(payload)).toString('base64') } } }] }] });

test('stable releases require plain forward semver and their own exact-source approval', () => {
  assert.equal(releaseChannel(version), 'beta'); assert.equal(releaseChannel('0.2.0'), 'stable');
  for (const value of ['0.2.0-rc.1', 'v0.2.0', '0.2.00', '0.2.0+extra', '0.2.0-beta.01', '999999999999999999999.0.0']) assert.throws(() => releaseChannel(value), /blocked/);
  const stable = { ...pkg, version: '0.2.0' };
  const input = { pkg: stable, commit, dirty: false, tag: 'v0.2.0', githubSha: commit, releaseApproval: `0.2.0@${commit}`, licenseApproval: `MIT@${commit}`, licenseText: 'Synthetic test grant only.',
    channel: 'stable', provenance: { source: { commit, dirty: false }, package: { name: pkg.name, version: '0.2.0' }, source_license: { identifier: 'MIT' } } };
  assert.doesNotThrow(() => assertPublicationPrerequisites(input));
  for (const change of [{ channel: 'beta' }, { tag: 'v0.2.0-beta.0' }, { releaseApproval: `${version}@${commit}` }, { licenseApproval: '' }, { dirty: true }]) assert.throws(() => assertPublicationPrerequisites({ ...input, ...change }), /blocked/);
  assert.doesNotThrow(() => assertUnoccupiedVersion(packument(), '0.2.0'));
  for (const value of ['0.0.9', '0.1.0']) assert.throws(() => assertUnoccupiedVersion(packument(), value), /blocked/);
});

test('occupied versions, malformed metadata and unrelated tag changes refuse without adoption', () => {
  assert.deepEqual(assertUnoccupiedVersion(packument(), version), packument()['dist-tags']);
  const occupied = packument(); occupied.versions[version] = manifest();
  assert.throws(() => assertUnoccupiedVersion(occupied, version), /occupied/);
  for (const change of [{ name: 'other' }, { versions: [] }, { 'dist-tags': null }, { 'dist-tags': { latest: 'https://example.invalid' } }]) assert.throws(() => assertUnoccupiedVersion({ ...packument(), ...change }, version), /blocked/);
  const after = packument(); after['dist-tags'].beta = version;
  assert.doesNotThrow(() => assertTags(after, { ...packument()['dist-tags'], beta: version }));
  for (const mutate of [value => { value['dist-tags'].latest = version; }, value => { delete value['dist-tags'].historical; }, value => { value['dist-tags'].new = version; }]) {
    const changed = clone(after); mutate(changed); assert.throws(() => assertTags(changed, after['dist-tags']), /tags changed/);
  }
});

test('registry manifest must retain inspected fields, fixed URLs and exact tarball integrity', () => {
  assert.doesNotThrow(() => assertRegistryManifest(manifest(), pkg, receipt, tarball));
  assert.doesNotThrow(() => assertRegistryManifest({ ...manifest(), directories: {} }, pkg, receipt, tarball));
  for (const mutate of [value => { value.optionalDependencies = { unexpected: 'https://example.invalid/payload.tgz' }; }, value => { value.bin.bota = 'other.js'; },
    value => { value.directories = { bin: 'other' }; },
    value => { value.scripts.install = 'unapproved'; }, value => { value.dependencies.example = '*'; }, value => { value.repository.url = 'git+https://github.com/other/repo.git'; },
    value => { value.dist.tarball = 'https://example.invalid/payload.tgz'; }, value => { value.dist.integrity += 'x'; }, value => { value.dist.attestations.url = 'https://example.invalid/attestation'; },
    value => { value.dist.attestations.url += '?redirect=1'; }, value => { delete value.dist.attestations; }, value => { value.dist.shasum = '0'.repeat(40); }]) {
    const changed = manifest(); mutate(changed); assert.throws(() => assertRegistryManifest(changed, pkg, receipt, tarball), /blocked/);
  }
  assert.throws(() => assertRegistryManifest(manifest(), pkg, receipt, Buffer.from('changed')), /blocked/);
});

test('public metadata may omit only the packing files directive; artifact and runtime fields remain exact', () => {
  const packed = { ...pkg, files: ['dist/index.js', 'README.md', 'LICENSE'] };
  const publicManifest = manifest();
  assert.doesNotThrow(() => assertRegistryManifest(publicManifest, packed, receipt, tarball));
  assert.doesNotThrow(() => assertRegistryManifest({ ...publicManifest, files: packed.files }, packed, receipt, tarball));
  for (const files of [null, [], ['unexpected.js']]) assert.throws(() => assertRegistryManifest({ ...publicManifest, files }, packed, receipt, tarball), /blocked/);
  for (const key of ['bin', 'scripts', 'dependencies', 'repository', 'license']) {
    const changed = clone(publicManifest); delete changed[key];
    assert.throws(() => assertRegistryManifest(changed, packed, receipt, tarball), /blocked/);
  }
  assert.throws(() => assertRegistryManifest(publicManifest, packed, receipt, Buffer.from('changed')), /blocked/);
});

test('registry reads avoid the preflight cache key and keep bounded fixed-origin response checks', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const cached = packument(), fresh = packument(); fresh['dist-tags'].beta = version;
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify(url.endsWith('-0') ? cached : fresh));
    };
    const signal = new AbortController().signal;
    assert.deepEqual(await readRegistryMetadata(context, 0, signal), cached);
    assert.deepEqual(await readRegistryMetadata(context, 1, signal), fresh);
    assert.notEqual(calls[0].url, calls[1].url);
    for (const [ordinal, call] of calls.entries()) {
      assert.equal(call.url, `https://registry.npmjs.org/@bota.dev%2fcli?verification=123-1-${ordinal}`);
      assert.equal(call.options.cache, 'no-store'); assert.equal(call.options.headers['cache-control'], 'no-cache');
      assert.equal(call.options.redirect, 'error'); assert.equal(call.options.credentials, 'omit');
    }
    for (const [input, ordinal] of [[{ ...context, run: '123&other=1' }, 2], [{ ...context, attempt: '2' }, 2], [context, -1], [context, 0.5]]) {
      await assert.rejects(readRegistryMetadata(input, ordinal, signal), /blocked/);
    }
    assert.equal(calls.length, 2);
    globalThis.fetch = async () => new Response('{}', { status: 503 });
    await assert.rejects(readRegistryMetadata(context, 2, signal), /blocked/);
    globalThis.fetch = async () => new Response('x'.repeat(12 * 1024 * 1024 + 1));
    await assert.rejects(readRegistryMetadata(context, 3, signal), /response size/);
    globalThis.fetch = async () => new Response('not JSON');
    await assert.rejects(readRegistryMetadata(context, 4, signal), SyntaxError);
  } finally { globalThis.fetch = originalFetch; }
});

test('verified-npm-output policy pins subject, source, run and workflow; synthetic DTOs are not cryptographic evidence', () => {
  assert.ok(assertVerifiedProvenance(audit(), pkg, receipt, context));
  for (const mutate of [value => { value.subject[0].digest.sha512 = '0'.repeat(128); }, value => { value.subject.push(value.subject[0]); }, value => { value.subject[0].name = 'pkg:npm/other@1.0.0'; },
    value => { value.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = '2'.repeat(40); }, value => { value.predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/other.yml'; },
    value => { value.predicate.buildDefinition.externalParameters.workflow.ref = 'refs/heads/main'; }, value => { value.predicate.buildDefinition.internalParameters.github.repository_id = '9'; },
    value => { value.predicate.runDetails.builder.id = 'https://example.invalid/builder'; }, value => { value.predicate.runDetails.metadata.invocationId += '0'; }]) {
    const changed = statement(); mutate(changed); assert.throws(() => assertVerifiedProvenance(audit(changed), pkg, receipt, context), /blocked/);
  }
  for (const mutate of [value => { value.invalid.push({}); }, value => { value.missing.push({}); }, value => { value.verified = []; }, value => { value.verified.push(value.verified[0]); },
    value => { value.verified[0].registry = 'https://example.invalid/'; }, value => { value.verified[0].attestationBundles = []; }]) {
    const changed = audit(); mutate(changed); assert.throws(() => assertVerifiedProvenance(changed, pkg, receipt, context), /blocked/);
  }
});

test('release context refuses forks, foreign workflows, run mismatches and TLS/preload overrides', () => {
  const env = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_REPOSITORY: 'bota-dev/bota-cli', GITHUB_REPOSITORY_ID: '1245303387', GITHUB_REPOSITORY_OWNER_ID: '252373912',
    GITHUB_EVENT_NAME: 'push', GITHUB_REF: `refs/tags/${context.tag}`, GITHUB_REF_NAME: context.tag, GITHUB_SHA: commit, GITHUB_WORKFLOW_SHA: commit,
    GITHUB_WORKFLOW_REF: `bota-dev/bota-cli/.github/workflows/publish.yml@refs/tags/${context.tag}`, GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_SERVER_URL: 'https://github.com' };
  assert.deepEqual(assertReleaseContext(env, pkg, { source: { commit } }), context);
  assert.throws(() => assertReleaseContext({ ...env, GITHUB_RUN_ATTEMPT: '2' }, pkg, { source: { commit } }), /first-attempt/);
  assert.throws(() => assertReleaseContext(env, { ...pkg, publishConfig: { access: 'public', registry: 'https://example.invalid' } }, { source: { commit } }), /blocked/);
  for (const key of Object.keys(env)) assert.throws(() => assertReleaseContext({ ...env, [key]: 'unexpected' }, pkg, { source: { commit } }), /blocked/);
  for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'NODE_USE_SYSTEM_CA', 'NODE_USE_ENV_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'npm_config_strict_ssl', 'npm_config_cafile']) assert.throws(() => assertReleaseTrust({ [key]: 'CANARY' }, []), /blocked/);
  assert.throws(() => assertReleaseTrust({}, ['--import=canary']), /blocked/);
  assert.doesNotThrow(() => assertReleaseTrust({ PATH: 'runtime' }, []));
});

test('installed byte checker rejects changed files and manifests; actual packed consumers exercise its positive path', async t => {
  const temporary = await mkdtemp(join(tmpdir(), 'bota-release-files-'));
  t.after(async () => { assert.equal(dirname(resolve(temporary)), resolve(tmpdir())); assert.ok(basename(temporary).startsWith('bota-release-files-')); await rm(temporary, { recursive: true, force: true }); });
  const source = join(temporary, 'source'), consumer = join(temporary, 'consumer'), installed = join(consumer, 'node_modules/@bota.dev/cli');
  for (const directory of [join(source, 'dist'), join(installed, 'dist')]) await mkdir(directory, { recursive: true });
  const files = ['dist/index.js', 'dist/release.json', 'dist/THIRD_PARTY_NOTICES.txt', 'README.md', 'LICENSE'];
  await writeFile(join(installed, 'package.json'), JSON.stringify(pkg));
  for (const path of files) { await writeFile(join(source, path), `fixture:${path}`); await writeFile(join(installed, path), `fixture:${path}`); }
  await assertInstalledPackage(consumer, source, pkg);
  for (const path of files) { await writeFile(join(installed, path), 'changed'); await assert.rejects(assertInstalledPackage(consumer, source, pkg), /blocked/); await writeFile(join(installed, path), `fixture:${path}`); }
  await writeFile(join(installed, 'package.json'), JSON.stringify({ ...pkg, version: 'other' }));
  await assert.rejects(assertInstalledPackage(consumer, source, pkg), /blocked/);
});

test('actual release entrypoint refuses untrusted startup with fixed output and no raw canary', async () => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|COMSPEC|SYSTEMDRIVE)$/i.test(key)));
  const execute = promisify(execFile);
  await assert.rejects(execute(process.execPath, [join(root, 'scripts/registry-release.mjs')], { env: { ...env, HTTPS_PROXY: 'DO_NOT_EXPOSE_RELEASE_CANARY' }, timeout: 15_000, maxBuffer: 65_536 }), error => {
    assert.equal(error.code, 1); assert.equal(error.stdout, ''); assert.equal(error.stderr, 'CLI registry release refused; inspect the retained phase receipt.\n');
    assert.doesNotMatch(error.stderr, /DO_NOT_EXPOSE/); return true;
  });
});

test('workflow keeps qualification unprivileged, consumes its exact artifact and protects the OIDC writer', async () => {
  const workflow = await readFile(join(root, '.github/workflows/publish.yml'), 'utf8');
  const qualification = workflow.slice(workflow.indexOf('  qualify:'), workflow.indexOf('  publish:'));
  const publication = workflow.slice(workflow.indexOf('  publish:'));
  assert.match(qualification, /node: \['22\.23\.2', '24\.19\.0'\]/);
  for (const command of ['npm run type-check', 'npm test', 'npm run license-check', 'npm run verify:package']) assert.ok(qualification.includes(command));
  assert.doesNotMatch(qualification, /id-token: write|environment:/);
  assert.match(publication, /needs: qualify/); assert.match(publication, /environment: npm-cli-release/); assert.match(publication, /id-token: write/);
  assert.match(publication, /name: cli-candidate-\$\{\{ github.sha \}\}-node24\.19\.0/);
  assert.ok(publication.indexOf('npm run check:publication') < publication.indexOf('npm run release:registry'));
  assert.doesNotMatch(workflow, /NODE_AUTH_TOKEN|NPM_TOKEN|workflow_dispatch|--tag latest/);
  assert.match(workflow, /CLI_STABLE_PUBLICATION_APPROVAL/); assert.match(workflow, /cancel-in-progress: false/);
  const script = await readFile(join(root, 'scripts/registry-release.mjs'), 'utf8');
  assert.ok(script.indexOf("const auditBytes = await npm(['audit'") < script.indexOf("const executable = join(consumer"));
  assert.ok(script.indexOf('await verify(bundle') < script.indexOf("const executable = join(consumer"));
});
