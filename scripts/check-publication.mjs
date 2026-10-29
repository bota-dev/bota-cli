import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function releaseChannel(version) {
  if (typeof version !== 'string' || version.length > 100 || version.split(/[.-]/).filter(value => /^[0-9]+$/.test(value)).some(value => !Number.isSafeInteger(Number(value)))) throw new Error('Publication blocked: unsupported release version.');
  if (/^0\.2\.0-beta\.(0|[1-9][0-9]*)$/.test(version)) return 'beta';
  if (/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) return 'stable';
  throw new Error('Publication blocked: unsupported release version.');
}

export function assertPublicationPrerequisites({ pkg, commit, dirty, tag, githubSha, releaseApproval, licenseApproval, licenseText, provenance, channel = 'beta' }) {
  if (!pkg.license || pkg.license === 'UNLICENSED' || !licenseText?.trim()) throw new Error('Publication blocked: CLI source license decision and LICENSE are required.');
  if (releaseChannel(pkg.version) !== channel || tag !== `v${pkg.version}`) throw new Error('Publication blocked: release tag, channel and package version must match.');
  if (dirty || !/^[0-9a-f]{40}$/.test(commit) || commit !== githubSha) throw new Error('Publication blocked: clean checkout HEAD must equal GITHUB_SHA.');
  if (releaseApproval !== `${pkg.version}@${commit}` || licenseApproval !== `${pkg.license}@${commit}`) throw new Error('Publication blocked: exact-source release and source-license approvals are required.');
  if (provenance?.source?.commit !== commit || provenance.source.dirty || provenance.package?.name !== pkg.name || provenance.package?.version !== pkg.version || provenance.source_license?.identifier !== pkg.license) throw new Error('Publication blocked: package provenance must match the approved clean source.');
}

export async function assertPreparedArtifact(root, provenance, receipt) {
  const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
  if (sha256(await readFile(resolve(root, 'LICENSE'))) !== provenance.source_license.sha256) throw new Error('Publication blocked: source-license digest changed.');
  if (sha256(JSON.stringify(provenance.inputs)) !== provenance.inputs_sha256) throw new Error('Publication blocked: input manifest digest changed.');
  for (const [path, hash] of Object.entries(provenance.inputs)) {
    const local = relative(root, resolve(root, path));
    if (!local || local.startsWith('..') || isAbsolute(local)) throw new Error('Publication blocked: invalid provenance input path.');
    if (sha256(await readFile(resolve(root, path))) !== hash) throw new Error('Publication blocked: prepared source inputs changed.');
  }
  if (sha256(await readFile(resolve(root, 'dist/index.js'))) !== provenance.bundle_sha256) throw new Error('Publication blocked: prepared bundle changed.');
  if (sha256(await readFile(resolve(root, 'dist/THIRD_PARTY_NOTICES.txt'))) !== provenance.notices_sha256) throw new Error('Publication blocked: prepared notices changed.');
  if (!/^[a-zA-Z0-9._-]+\.tgz$/.test(receipt.filename) || receipt.name !== provenance.package.name || receipt.version !== provenance.package.version
    || receipt.source?.commit !== provenance.source.commit || receipt.source.dirty !== false) throw new Error('Publication blocked: candidate receipt does not match clean source.');
  if (sha256(await readFile(resolve(root, 'dist/release.json'))) !== receipt.prepared_provenance_sha256) throw new Error('Publication blocked: inspected tarball provenance is stale.');
  const tarball = await readFile(resolve(root, '.release', receipt.filename));
  if (sha256(tarball) !== receipt.sha256 || `sha512-${createHash('sha512').update(tarball).digest('base64')}` !== receipt.integrity) throw new Error('Publication blocked: inspected tarball changed.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  let licenseText;
  try { licenseText = await readFile(resolve(root, 'LICENSE'), 'utf8'); } catch { /* A missing grant is a hard publication blocker. */ }
  let provenance;
  try { provenance = JSON.parse(await readFile(resolve(root, 'dist/release.json'), 'utf8')); } catch { /* Checked below. */ }
  const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  try {
    const channel = releaseChannel(pkg.version);
    assertPublicationPrerequisites({ pkg, commit: git(['rev-parse', 'HEAD']), dirty: Boolean(git(['status', '--porcelain', '--untracked-files=all'])),
      tag: process.env.GITHUB_REF_NAME, githubSha: process.env.GITHUB_SHA,
      releaseApproval: channel === 'beta' ? process.env.CLI_PREVIEW_PUBLICATION_APPROVAL : process.env.CLI_STABLE_PUBLICATION_APPROVAL,
      licenseApproval: process.env.CLI_SOURCE_LICENSE_APPROVAL, channel, licenseText, provenance });
    const receipt = JSON.parse(await readFile(resolve(root, '.release/package-receipt.json'), 'utf8'));
    await assertPreparedArtifact(root, provenance, receipt);
    console.log('Exact-source publication prerequisites passed. Registry/OIDC acceptance remains separate.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
