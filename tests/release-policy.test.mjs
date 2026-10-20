import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { assertPreparedArtifact, assertPublicationPrerequisites } from '../scripts/check-publication.mjs';

// Synthetic policy inputs test the guard, and grant no license to Bota source.
const commit = '1'.repeat(40);
const fixture = () => ({ pkg: { name: '@bota.dev/cli', version: '0.2.0-beta.0', license: 'TEST-ONLY' }, commit, dirty: false,
  tag: 'v0.2.0-beta.0', githubSha: commit, releaseApproval: `0.2.0-beta.0@${commit}`, licenseApproval: `TEST-ONLY@${commit}`, licenseText: 'Synthetic policy fixture only.',
  provenance: { source: { commit, dirty: false }, package: { name: '@bota.dev/cli', version: '0.2.0-beta.0' }, source_license: { identifier: 'TEST-ONLY' } } });

test('preview publication policy refuses missing source license even when release approval is supplied', () => {
  assert.throws(() => assertPublicationPrerequisites({ ...fixture(), pkg: { version: '0.2.0-beta.0' }, licenseText: undefined }), /source license decision/);
});

test('preview publication policy refuses tag, source, approval and provenance mismatches', () => {
  for (const change of [{ tag: 'v0.1.0' }, { githubSha: '2'.repeat(40) }, { dirty: true }, { releaseApproval: '' }, { licenseApproval: '' }, { provenance: undefined },
    { provenance: { ...fixture().provenance, source: { commit, dirty: true } } }, { pkg: { ...fixture().pkg, version: '0.2.0' } }]) {
    assert.throws(() => assertPublicationPrerequisites({ ...fixture(), ...change }), /Publication blocked/);
  }
  assert.doesNotThrow(() => assertPublicationPrerequisites(fixture()));
});

test('prepared artifact guards reject changed bytes, escaping paths and stale dirty-tarball receipts', async t => {
  const root = await mkdtemp(join(tmpdir(), 'bota-cli-pub-fixture-'));
  t.after(async () => {
    assert.equal(dirname(resolve(root)), resolve(tmpdir())); assert.ok(basename(root).startsWith('bota-cli-pub-fixture-'));
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(join(root, 'dist')); await mkdir(join(root, '.release'));
  const sha = value => createHash('sha256').update(value).digest('hex');
  const files = { LICENSE: 'Synthetic policy fixture only; not a Bota source grant.', 'source.txt': 'source', 'dist/index.js': 'bundle',
    'dist/THIRD_PARTY_NOTICES.txt': 'third-party fixture', '.release/fixture.tgz': 'synthetic digest fixture, not a package' };
  const reset = async () => {
    for (const [path, value] of Object.entries(files)) await writeFile(join(root, path), value);
    const inputs = { 'source.txt': sha(files['source.txt']) };
    const provenance = { ...fixture().provenance, source_license: { identifier: 'TEST-ONLY', sha256: sha(files.LICENSE) }, inputs,
      inputs_sha256: sha(JSON.stringify(inputs)), bundle_sha256: sha(files['dist/index.js']), notices_sha256: sha(files['dist/THIRD_PARTY_NOTICES.txt']) };
    const serialized = `${JSON.stringify(provenance)}\n`; await writeFile(join(root, 'dist/release.json'), serialized);
    const receipt = { name: '@bota.dev/cli', version: '0.2.0-beta.0', source: { commit, dirty: false }, filename: 'fixture.tgz',
      sha256: sha(files['.release/fixture.tgz']), integrity: `sha512-${createHash('sha512').update(files['.release/fixture.tgz']).digest('base64')}`,
      prepared_provenance_sha256: sha(serialized) };
    return { provenance, receipt };
  };
  let current = await reset(); await assertPreparedArtifact(root, current.provenance, current.receipt);
  for (const path of Object.keys(files)) {
    current = await reset(); await writeFile(join(root, path), 'changed');
    await assert.rejects(assertPreparedArtifact(root, current.provenance, current.receipt), /Publication blocked/);
  }
  for (const change of [{ source: { commit, dirty: true } }, { prepared_provenance_sha256: 'stale' }, { filename: '../escape.tgz' }, { name: 'different-package' }]) {
    current = await reset(); await assert.rejects(assertPreparedArtifact(root, current.provenance, { ...current.receipt, ...change }), /Publication blocked/);
  }
  current = await reset(); current.provenance.inputs = { '../escape.txt': 'unused' };
  current.provenance.inputs_sha256 = sha(JSON.stringify(current.provenance.inputs));
  await assert.rejects(assertPreparedArtifact(root, current.provenance, current.receipt), /invalid provenance input path/);
});
