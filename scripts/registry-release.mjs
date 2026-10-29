import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertPreparedArtifact, assertPublicationPrerequisites, releaseChannel } from './check-publication.mjs';

const repository = 'bota-dev/bota-cli';
const registry = 'https://registry.npmjs.org';
const packageName = '@bota.dev/cli';
const npmVersion = '11.21.0';
const predicateType = 'https://slsa.dev/provenance/v1';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fixedError = () => new Error('CLI registry release refused; inspect the retained phase receipt.');
const check = (condition, message) => { if (!condition) throw new Error(`Release blocked: ${message}.`); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const equal = (left, right) => { try { assert.deepEqual(left, right); return true; } catch { return false; } };

export function assertReleaseTrust(env, execArgv = process.execArgv) {
  check(execArgv.length === 0, 'runtime preloads are unsupported');
  for (const key of Object.keys(env)) check(!/^(NODE_OPTIONS|NODE_PATH|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|NODE_USE_SYSTEM_CA|NODE_USE_ENV_PROXY|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|NPM_CONFIG_(PROXY|HTTPS_PROXY|STRICT_SSL|CA|CAFILE))$/i.test(key), 'TLS, proxy or preload override');
}

export function assertReleaseContext(env, pkg, provenance) {
  const tag = `v${pkg.version}`;
  check(pkg.name === packageName && env.GITHUB_ACTIONS === 'true' && env.RUNNER_ENVIRONMENT === 'github-hosted', 'hosted release context');
  check(equal(pkg.publishConfig, { access: 'public' }), 'fixed public publishing configuration');
  check(env.GITHUB_REPOSITORY === repository && env.GITHUB_REPOSITORY_ID === '1245303387' && env.GITHUB_REPOSITORY_OWNER_ID === '252373912', 'repository identity');
  check(env.GITHUB_EVENT_NAME === 'push' && env.GITHUB_REF === `refs/tags/${tag}` && env.GITHUB_REF_NAME === tag, 'tag event identity');
  check(env.GITHUB_SHA === provenance.source.commit && env.GITHUB_WORKFLOW_SHA === env.GITHUB_SHA && env.GITHUB_WORKFLOW_REF === `${repository}/.github/workflows/publish.yml@refs/tags/${tag}`, 'workflow source identity');
  check(/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID ?? '') && env.GITHUB_RUN_ATTEMPT === '1', 'first-attempt release identity');
  check(env.GITHUB_SERVER_URL === 'https://github.com', 'GitHub origin');
  return { tag, commit: env.GITHUB_SHA, run: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT };
}

export function registryTags(packument) {
  check(record(packument) && packument.name === packageName && record(packument.versions) && record(packument['dist-tags']), 'registry package identity');
  const tags = packument['dist-tags'];
  check(Object.keys(tags).length <= 100 && Object.entries(tags).every(([key, value]) => /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(key) && typeof value === 'string' && /^[0-9A-Za-z.+-]{1,100}$/.test(value)), 'registry tags');
  return { ...tags };
}

export function assertUnoccupiedVersion(packument, version) {
  const tags = registryTags(packument);
  check(!Object.hasOwn(packument.versions, version), 'version is already occupied; no automatic retry or adoption');
  if (releaseChannel(version) === 'stable' && tags.latest !== undefined) {
    const parts = input => {
      check(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(input), 'stable version ordering');
      const result = input.split('.').map(Number);
      check(result.every(Number.isSafeInteger), 'stable version ordering'); return result;
    };
    const current = parts(tags.latest), next = parts(version);
    const index = next.findIndex((value, i) => value !== current[i]);
    check(index >= 0 && next[index] > current[index], 'stable promotion must move forward');
  }
  return tags;
}

export function assertTags(packument, expected) {
  check(equal(registryTags(packument), expected), 'registry tags changed outside the intended transition');
}

export function assertRegistryManifest(manifest, pkg, receipt, tarball) {
  check(record(manifest) && record(manifest.dist), 'registry manifest');
  // Registry metadata can add publication records, but cannot override package
  // fields consumed by npm. In particular this refuses injected scripts, URLs,
  // aliases, optional dependencies, bins, overrides or alternate entrypoints.
  const additions = new Set(['_id', '_rev', '_npmVersion', '_nodeVersion', '_npmUser', '_npmOperationalInternal', '_hasShrinkwrap', '_integrity', '_resolved', '_from', 'gitHead', 'dist', 'maintainers', 'readme', 'readmeFilename', 'time', 'directories']);
  for (const key of Object.keys(manifest)) check(Object.hasOwn(pkg, key) || additions.has(key), 'unexpected registry manifest field');
  // npm omits the packing-only files directive from public metadata. The exact
  // tarball and installed manifest still have to match the inspected artifact.
  for (const [key, value] of Object.entries(pkg)) {
    if (key === 'files' && !Object.hasOwn(manifest, key)) continue;
    check(equal(manifest[key], value), 'registry package fields differ from the inspected source');
  }
  if (!Object.hasOwn(pkg, 'directories') && Object.hasOwn(manifest, 'directories')) check(equal(manifest.directories, {}), 'unexpected registry directories');
  check(manifest.name === receipt.name && manifest.version === receipt.version, 'registry version identity');
  check(manifest.dist.tarball === `${registry}/${packageName}/-/cli-${pkg.version}.tgz`, 'tarball origin or path');
  check(manifest.dist.integrity === receipt.integrity && sha256(tarball) === receipt.sha256, 'tarball integrity');
  check(`sha512-${createHash('sha512').update(tarball).digest('base64')}` === receipt.integrity, 'tarball integrity');
  if (manifest.dist.shasum !== undefined) check(manifest.dist.shasum === createHash('sha1').update(tarball).digest('hex'), 'registry SHA-1 readback');
  const attestations = manifest.dist.attestations;
  check(record(attestations) && attestations.provenance?.predicateType === predicateType && typeof attestations.url === 'string', 'required provenance metadata');
  const url = new URL(attestations.url);
  check(url.origin === registry && !url.username && !url.password && !url.search && !url.hash && decodeURIComponent(url.pathname) === `/-/npm/v1/attestations/${packageName}@${pkg.version}`, 'attestation origin or path');
}

// The input must be the successful, captured output of the pinned npm command,
// never a downloaded assertion that describes itself as verified. The native
// path additionally verifies the returned bundle with the exact Fulcio identity.
export function assertVerifiedProvenance(audit, pkg, receipt, context) {
  check(record(audit) && Array.isArray(audit.invalid) && audit.invalid.length === 0 && Array.isArray(audit.missing) && audit.missing.length === 0 && Array.isArray(audit.verified), 'npm signature verification');
  const matches = audit.verified.filter(value => value.name === packageName && value.version === pkg.version && value.location === `node_modules/${packageName}` && value.registry === `${registry}/`);
  check(matches.length === 1, 'one verified installed CLI');
  const bundles = matches[0].attestationBundles;
  check(Array.isArray(bundles), 'verified attestation bundles');
  const provenance = bundles.filter(value => value.predicateType === predicateType);
  check(provenance.length === 1, 'one verified provenance statement');
  const bundle = provenance[0].bundle;
  check(bundle?.dsseEnvelope?.payloadType === 'application/vnd.in-toto+json' && typeof bundle.dsseEnvelope.payload === 'string' && bundle.dsseEnvelope.payload.length < 1_000_000, 'provenance payload');
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
  check(statement._type === 'https://in-toto.io/Statement/v1' && statement.predicateType === predicateType, 'provenance statement type');
  check(equal(statement.subject, [{ name: `pkg:npm/%40bota.dev/cli@${pkg.version}`, digest: { sha512: Buffer.from(receipt.integrity.slice(7), 'base64').toString('hex') } }]), 'provenance subject');
  const build = statement.predicate?.buildDefinition;
  check(build?.buildType === 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1', 'provenance build type');
  check(equal(build.externalParameters?.workflow, { ref: `refs/tags/${context.tag}`, repository: `https://github.com/${repository}`, path: '.github/workflows/publish.yml' }), 'provenance workflow');
  check(equal(build.internalParameters?.github, { event_name: 'push', repository_id: '1245303387', repository_owner_id: '252373912' }), 'provenance repository identity');
  check(equal(build.resolvedDependencies, [{ uri: `git+https://github.com/${repository}@refs/tags/${context.tag}`, digest: { gitCommit: context.commit } }]), 'provenance source commit');
  check(statement.predicate.runDetails?.builder?.id === 'https://github.com/actions/runner/github-hosted' && statement.predicate.runDetails.metadata?.invocationId === `https://github.com/${repository}/actions/runs/${context.run}/attempts/${context.attempt}`, 'provenance run identity');
  return bundle;
}

export async function assertInstalledPackage(consumer, root, pkg) {
  const installed = join(consumer, 'node_modules', packageName);
  check(equal(JSON.parse(await readFile(join(installed, 'package.json'), 'utf8')), pkg), 'installed package manifest');
  for (const path of ['dist/index.js', 'dist/release.json', 'dist/THIRD_PARTY_NOTICES.txt', 'README.md', 'LICENSE']) check((await readFile(join(installed, path))).equals(await readFile(join(root, path))), 'installed package bytes');
}

async function boundedRead(url, maxBytes, signal) {
  const response = await fetch(url, { redirect: 'error', credentials: 'omit', cache: 'no-store', signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]), headers: { accept: 'application/json', 'cache-control': 'no-cache' } });
  check(response.status === 200, 'public registry or source read');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; check(size <= maxBytes, 'public response size'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}

export async function readRegistryMetadata(context, ordinal, signal) {
  check(/^[1-9][0-9]{0,19}$/.test(context.run ?? '') && context.attempt === '1' && Number.isSafeInteger(ordinal) && ordinal >= 0, 'registry read identity');
  // Reusing the preflight URL can return its cached, pre-publication packument
  // after an acknowledged publish. Each bounded read has its own cache key.
  const url = `${registry}/@bota.dev%2fcli?verification=${context.run}-${context.attempt}-${ordinal}`;
  return JSON.parse(await boundedRead(url, 12 * 1024 * 1024, signal));
}

function run(command, args, cwd, env, signal) {
  return new Promise((accept, refuse) => {
    if (signal.aborted) { refuse(fixedError()); return; }
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let failed = false, killed = false, total = 0, escalation;
    const stdout = [];
    const stop = () => { failed = true; if (!killed) { killed = true; child.kill('SIGTERM'); escalation = setTimeout(() => child.kill('SIGKILL'), 2_000); } };
    const timer = setTimeout(stop, 180_000);
    signal.addEventListener('abort', stop, { once: true });
    child.on('error', () => { failed = true; });
    for (const [stream, capture] of [[child.stdout, true], [child.stderr, false]]) {
      stream.on('error', stop);
      stream.on('data', bytes => { total += bytes.length; if (total > 32 * 1024 * 1024) stop(); else if (capture) stdout.push(bytes); });
    }
    child.once('close', code => {
      clearTimeout(timer); clearTimeout(escalation); signal.removeEventListener('abort', stop);
      if (failed || code !== 0) refuse(fixedError()); else accept(Buffer.concat(stdout));
    });
  });
}

const systemEnvironment = source => Object.fromEntries(Object.entries(source).filter(([key]) => /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|COMSPEC|SYSTEMDRIVE|LANG|LC_ALL|TZ)$/i.test(key)));
const oidcKeys = ['CI', 'GITHUB_ACTIONS', 'GITHUB_ACTOR', 'GITHUB_ACTOR_ID', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_REF_NAME', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SERVER_URL', 'GITHUB_SHA', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'RUNNER_ENVIRONMENT', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'];

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const controller = new AbortController(), abort = () => controller.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  const result = { schema_version: 1, status: 'refused', phase: 'source', publication: 'not-attempted', stable_promotion: 'not-attempted', operation_may_have_executed: false, scope: 'Registry publication and installed package only; live Platform login, hosted MCP and physical device acceptance are separate.' };
  let temporary, mayRetainReceipt = false;
  try {
    check(process.argv.length === 2, 'release command arguments');
    assertReleaseTrust(process.env);
    check(process.version === 'v24.19.0', 'pinned publication runtime');
    const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
    const provenance = JSON.parse(await readFile(join(root, 'dist/release.json'), 'utf8'));
    const receiptBytes = await readFile(join(root, '.release/package-receipt.json'));
    const receipt = JSON.parse(receiptBytes), channel = releaseChannel(pkg.version);
    check(receipt.node === 'v24.19.0' && receipt.npm === npmVersion && provenance.build?.node === 'v24.19.0' && provenance.build.npm === npmVersion, 'qualified artifact tooling');
    const context = assertReleaseContext(process.env, pkg, provenance);
    const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    assertPublicationPrerequisites({ pkg, commit: git(['rev-parse', 'HEAD']), dirty: Boolean(git(['status', '--porcelain', '--untracked-files=all'])), tag: context.tag, githubSha: context.commit,
      releaseApproval: channel === 'beta' ? process.env.CLI_PREVIEW_PUBLICATION_APPROVAL : process.env.CLI_STABLE_PUBLICATION_APPROVAL,
      licenseApproval: process.env.CLI_SOURCE_LICENSE_APPROVAL, licenseText: await readFile(join(root, 'LICENSE'), 'utf8'), provenance, channel });
    check(git(['rev-parse', `refs/tags/${context.tag}^{commit}`]) === context.commit, 'tag source');
    git(['merge-base', '--is-ancestor', context.commit, 'origin/main']);
    await assertPreparedArtifact(root, provenance, receipt);
    mayRetainReceipt = true;
    const npmCli = process.env.npm_execpath;
    check(typeof npmCli === 'string' && JSON.parse(await readFile(resolve(dirname(npmCli), '../package.json'), 'utf8')).version === npmVersion, 'pinned npm release tooling');
    check(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN && /^https:\/\/[a-zA-Z0-9.-]+\.actions\.githubusercontent\.com\//.test(process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? ''), 'OIDC availability');
    const source = JSON.parse(await boundedRead(`https://api.github.com/repos/${repository}`, 128 * 1024, controller.signal));
    check(source.private === false && source.id === 1245303387 && source.full_name === repository && source.owner?.id === 252373912, 'public source identity');
    let registryReadOrdinal = 0;
    const readRegistry = () => readRegistryMetadata(context, registryReadOrdinal++, controller.signal);
    result.phase = 'registry-preflight';
    const before = assertUnoccupiedVersion(await readRegistry(), pkg.version);
    Object.assign(result, { package: { name: pkg.name, version: pkg.version }, channel, source: context, candidate_receipt_sha256: sha256(receiptBytes), tarball_sha256: receipt.sha256, tags_before: before, npm: npmVersion });
    temporary = await mkdtemp(join(tmpdir(), 'bota-cli-public-'));
    const home = join(temporary, 'home'), consumer = join(temporary, 'consumer');
    await mkdir(home); await mkdir(consumer);
    const userConfig = join(temporary, 'user.npmrc'), globalConfig = join(temporary, 'global.npmrc');
    await writeFile(userConfig, ''); await writeFile(globalConfig, '');
    const env = { ...systemEnvironment(process.env), HOME: home, USERPROFILE: home, TEMP: temporary, TMP: temporary,
      npm_config_userconfig: userConfig, npm_config_globalconfig: globalConfig, npm_config_cache: join(temporary, 'cache'),
      npm_config_registry: `${registry}/`, npm_config_fetch_retries: '0', NO_COLOR: '1', FORCE_COLOR: '0' };
    const npm = (args, cwd = consumer, extra = {}) => run(process.execPath, [npmCli, ...args, `--registry=${registry}/`], cwd, { ...env, ...extra }, controller.signal);
    const oidc = Object.fromEntries(oidcKeys.filter(key => Object.hasOwn(process.env, key)).map(key => [key, process.env[key]]));
    const publicationTag = channel === 'beta' ? 'beta' : 'next';
    // There is exactly one write attempt. An error/lost acknowledgement is an
    // unknown outcome, never permission to republish or adopt an occupied version.
    result.phase = 'publish'; result.publication = 'unknown'; result.operation_may_have_executed = true;
    await npm(['publish', join(root, '.release', receipt.filename), '--access=public', `--tag=${publicationTag}`, '--provenance', '--ignore-scripts'], consumer, oidc);
    result.publication = 'acknowledged';
    result.phase = 'public-readback';
    const published = await readRegistry(), expectedTags = { ...before, [publicationTag]: pkg.version };
    assertTags(published, expectedTags);
    const publicTarball = await boundedRead(`${registry}/${packageName}/-/cli-${pkg.version}.tgz`, 16 * 1024 * 1024, controller.signal);
    assertRegistryManifest(published.versions[pkg.version], pkg, receipt, publicTarball);
    await writeFile(join(consumer, 'package.json'), `${JSON.stringify({ name: 'bota-cli-public-consumer', version: '0.0.0', private: true, dependencies: { [packageName]: pkg.version } }, null, 2)}\n`);
    await npm(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
    const lockBytes = await readFile(join(consumer, 'package-lock.json')), lock = JSON.parse(lockBytes);
    const locked = lock.packages?.[`node_modules/${packageName}`];
    check(locked?.version === pkg.version && locked.integrity === receipt.integrity && locked.resolved === `${registry}/${packageName}/-/cli-${pkg.version}.tgz`, 'public consumer lock');
    await npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund']);
    check((await readFile(join(consumer, 'package-lock.json'))).equals(lockBytes), 'frozen public consumer lock');
    await assertInstalledPackage(consumer, root, pkg);
    result.phase = 'provenance';
    const auditBytes = await npm(['audit', 'signatures', '--json', '--include-attestations']);
    const bundle = assertVerifiedProvenance(JSON.parse(auditBytes), pkg, receipt, context);
    // Reuse the cryptographic verifier shipped in the exact pinned npm release.
    // Its identity policy pins the Fulcio issuer AND workflow/tag, beyond npm's
    // ordinary subject/integrity checks. No custom CA/endpoint is accepted.
    const { verify } = createRequire(npmCli)('sigstore');
    await verify(bundle, { certificateIdentityURI: `https://github.com/${repository}/.github/workflows/publish.yml@refs/tags/${context.tag}`,
      certificateIssuer: 'https://token.actions.githubusercontent.com', tufCachePath: join(temporary, 'cache', '_tuf'), tufForceCache: true, retry: 0, timeout: 10_000 });
    const publicEvidence = join(root, '.release/public-consumer');
    const provenanceBytes = Buffer.from(`${JSON.stringify(bundle, null, 2)}\n`);
    await mkdir(publicEvidence, { recursive: true });
    await writeFile(join(publicEvidence, 'package.json'), await readFile(join(consumer, 'package.json')));
    await writeFile(join(publicEvidence, 'package-lock.json'), lockBytes);
    await writeFile(join(publicEvidence, 'provenance.json'), provenanceBytes);
    Object.assign(result, { provenance_verified: true, provenance_bundle_sha256: sha256(provenanceBytes), signature_audit_sha256: sha256(auditBytes), consumer_lock_sha256: sha256(lockBytes), installed_bytes_verified: true });
    result.phase = 'installed-smoke';
    const executable = join(consumer, 'node_modules', packageName, 'dist/index.js');
    check((await run(process.execPath, [executable, '--version'], consumer, env, controller.signal)).toString().trim() === pkg.version, 'installed CLI version');
    check((await run(process.execPath, [executable, '--help'], consumer, env, controller.signal)).toString().includes('Bota developer CLI'), 'installed CLI help');
    check((await run(process.execPath, [executable, 'mcp', '--mode', 'hosted', '--help'], consumer, env, controller.signal)).toString().includes('--mode'), 'installed MCP help');
    await run(process.execPath, [join(root, 'scripts/check-licenses.mjs'), join(consumer, 'node_modules')], root, env, controller.signal);
    result.phase = 'tag-check';
    assertTags(await readRegistry(), expectedTags);
    if (channel === 'stable') {
      result.phase = 'stable-promotion';
      result.stable_promotion = 'unknown';
      await npm(['dist-tag', 'add', `${packageName}@${pkg.version}`, 'latest'], consumer, oidc);
      result.stable_promotion = 'acknowledged';
      expectedTags.latest = pkg.version;
    }
    const final = await readRegistry(); assertTags(final, expectedTags);
    assertRegistryManifest(final.versions[pkg.version], pkg, receipt, publicTarball);
    result.tags_after = registryTags(final); result.status = 'verified'; result.phase = 'complete';
  } catch { throw fixedError(); }
  finally {
    try {
      if (temporary) {
        check(dirname(resolve(temporary)) === resolve(tmpdir()) && basename(temporary).startsWith('bota-cli-public-'), 'owned consumer cleanup');
        await rm(temporary, { recursive: true, force: true });
      }
    } catch { result.status = 'refused'; result.phase = 'cleanup'; }
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
    if (controller.signal.aborted) { result.status = 'refused'; result.phase = 'cancelled'; }
    if (mayRetainReceipt) await writeFile(join(root, '.release/registry-release-receipt.json'), `${JSON.stringify(result, null, 2)}\n`);
    if (result.status !== 'verified') throw fixedError();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().then(() => console.log('CLI registry artifact, provenance and clean public installation verified.')).catch(() => { console.error(fixedError().message); process.exitCode = 1; });
