# CLI preview candidate: publication gated

Date: October 19, 2026. Scope: T01 packaging qualification for
`@bota.dev/cli@0.2.0-beta.0`, starting from functional source `25dca4e`.
The owner-approved [implementation initiative](https://github.com/bota-dev/bota/issues/401)
owns cross-repository/backend/docs delivery. Root owns source commit/push.

**This is a prepared candidate, not a published release.** The owner explicitly
approved MIT licensing for the public CLI on October 21, 2026. The package and
root lock now declare MIT, and `LICENSE` contains the approved grant with the
same Bota attribution as the API SDK. This resolves the source-license decision;
exact-source publication approval, trusted publishing and registry acceptance
remain independent gates. Third-party notices retain their own role.

## Read-only publication baseline

- The [public registry metadata](https://registry.npmjs.org/@bota.dev%2fcli)
  returned only version `0.1.0` and `latest: 0.1.0`, published May 25, 2026,
  at source `5ab9df4d7365e02127b1e3b56cbab1586890fbb9`.
- `0.2.0-beta.0` was unoccupied; the repository's remote tag listing was empty.
  No tag, release, dispatch, npm publication or production action was performed.
- Before this change, a dry pack included 38 files, including tests, source,
  workflow configuration and internal reviews. Publication had duplicate broad
  tag/release triggers and implicit `latest`, without installed-package tests.

## Candidate contract

| Requirement | Evidence and status |
| --- | --- |
| Explicit preview/version boundary | Package version is `0.2.0-beta.0`; CLI `--version` reads its own installed manifest. The existing MCP compatibility identities remain `0.1.0`. README distinguishes historical npm latest from unpublished source preview. Matched. |
| Restricted package contents | Six files: `package.json`, `README.md`, `LICENSE`, `dist/index.js`, `dist/release.json`, and `dist/THIRD_PARTY_NOTICES.txt`. Source/tests/workflows/internal reviews are excluded. The installed license bytes and digest must match the approved source. |
| Declared runtime support | Node minimum is `22.23.2`; Node 22/24 remain the tested cohorts. Eight runtime dependencies are exact qualified versions. The MIT metadata update changes no dependency package entry, version, integrity or resolution. |
| Dependency/notices evidence | Build metadata detects bundled dependencies from the actual esbuild metafile and copies their license notices if needed. The current bundle has no third-party JavaScript; external dependencies ship their own notices. Both source and installed consumer graphs run the dependency-license gate. This is not source-license approval. Matched. |
| Installed consumer | The actual tarball is installed into a temporary consumer through a generated lock followed by `npm ci --ignore-scripts`; lock bytes must remain unchanged. Installed version/help, hosted-mode help and one synthetic empty-scope identity read are checked, without login or a live API. Matched. |
| Consumer isolation | Child environment uses an OS/runtime allowlist plus explicit temporary HOME/USERPROFILE, npm user/global config, cache and temporary directories. Proxy, provider, database/session, Node-option and inherited credential variables are excluded. Temporary cleanup verifies its resolved owned path. Matched. |
| Exact prepared artifact | Source inputs, bundle, notices, package version and installed provenance are hashed. The receipt binds tarball SHA-256/SHA-512 to exact installed provenance bytes and the consumer lock/graph. The publication guard refuses changed files, paths escaping the source root and stale dirty-source receipts. Matched in synthetic tamper fixtures. |
| Channel-specific publication | One tag-triggered workflow; the source guard accepts `v0.2.0-beta.N` or a matching plain-semver stable version. Both Node cohorts qualify; the protected writer receives the exact inspected Node 24 archive. Beta preserves `latest`; a stable version publishes to `next`, then promotes the same version to `latest` only after authenticated registry/artifact/provenance/public-install readback. Source implementation is separate from activated publishing authority. |

## Release contract

CLI and local MCP share `@bota.dev/cli`; hosted MCP releases with the backend.
The source remains MIT licensed. Public source visibility must match
`https://github.com/bota-dev/bota-cli` for npm provenance. Source review,
publication, docs-site delivery, backend activation and real login/MCP acceptance
remain distinct cohorts. The current package candidate is not a released login
feature merely because these workflows exist.

The `Publish CLI` workflow qualifies the matching tagged source on Node 22.23.2
and 24.19.0 with pinned npm 11.21.0. Qualification has no OIDC permission. Its
Node 24 candidate, build metadata and installed-consumer receipt are transferred
within the same workflow run; the protected writer verifies their hashes and
uses that exact archive rather than rebuilding or repacking it.

Before activation, maintainers must configure:

- Public repository visibility, reviewed `main`, protected release tags and
  required human reviewers for the `npm-cli-release` GitHub environment. The owner
  may review a release they triggered after independent PR review; agent approval
  is never a substitute.
- npm trusted publisher: organization `bota-dev`, repository `bota-cli`, workflow
  filename `publish.yml`, environment `npm-cli-release`, with **npm publish** and
  **npm dist-tag** allowed. No persistent npm token fallback is used. npm 11.21.0
  is required for OIDC dist-tag operations.
- `CLI_PREVIEW_PUBLICATION_APPROVAL=<beta-version>@<commit>` for previews, or
  `CLI_STABLE_PUBLICATION_APPROVAL=<stable-version>@<commit>` for stable releases,
  plus `CLI_SOURCE_LICENSE_APPROVAL=MIT@<commit>` for that exact clean source.

The writer requires the tagged commit to belong to `main`, current public
repository identity and an unoccupied package version. `0.2.0-beta.N` publishes
to `beta` without changing `latest`. A plain-semver stable release must move
forward from `latest`; it first publishes to `next`. Stable is a distinct source
version and archive, not a prerelease relabeled as stable.

Public readback pins the source fields, fixed registry/tarball/attestation URLs,
archive SHA-256/SHA-512, and installed bytes. A clean public consumer resolves a
lock, installs with lifecycle scripts disabled, preserves lock bytes, checks
CLI/local-MCP help and dependency licenses, and verifies npm registry signatures
and attestations. The returned provenance bundle also undergoes Sigstore
verification with the exact GitHub workflow/tag certificate identity and OIDC
issuer. Its payload must identify the expected tarball, source commit and
current run. Only then may a stable version move to `latest`.

One workflow concurrency group serializes both channels. Each transition checks
all observed dist-tags; unexpected changes refuse instead of overwriting or
rolling them back. This is cooperative serialization, not a registry CAS or a
claim against malicious maintainers. A publication or promotion is attempted
once. Unknown acknowledgement, failed verification and cleanup remain nonzero;
the retained receipt distinguishes attempted, acknowledged and verified state.
Only the first workflow attempt can publish; GitHub reruns refuse even when an
earlier attempt failed before a write. Configure all prerequisites before tagging.
An occupied version is never silently adopted on rerun. Review its public state
and receipt before deciding recovery; do not repeat a write on the assumption
that failure meant no effect.

Credential-free tests cover boundary predicates, malicious registry fields,
occupied versions, source/tag/run mismatches, unexpected tag changes and fixed
startup refusal. Both installed-candidate cohorts exercise exact shipped bytes.
These checks do not emulate a successful npm publication or certify production
Platform login. Trusted publisher/environment configuration, actual publication,
public cryptographic readback and live deployment acceptance remain unverified
until their respective real executions succeed.

## Verification and receipts

`npm run verify:package` builds, prepares metadata, packs and installs the
candidate. `npm run smoke:package` repeats the installed smoke against an
already prepared build; it does not rebuild it. Artifacts are under ignored
`.release/`: the tarball, package receipt, and temporary consumer manifest/lock.
The receipt records Node/npm versions, exact integrity, allowed environment
keys, resolved dependency graph and which checks ran.

The three `tests/release-policy.test.mjs` cases cover missing license; source,
tag, approval and provenance mismatches; and artifact/path/stale-receipt tampering.
Their temporary fake license text tests policy only and grants nothing to Bota.
Independent review passes those guards and the consumer isolation/dependency
boundaries. The original October 19 publication check failed because the source
license was absent; that failure remains historical evidence. The October 21
owner approval resolves that prerequisite, while source/tag/release approval
checks continue to refuse unapproved publication. No npm publish command is
executed during qualification.

The owning delivery receipt records final test counts, type/build checks,
packed readbacks, source identity and hosted CI. The original review did not
run a dedicated workflow-validator skill or actionlint; local YAML parsing,
structural checks and independent review covered that source. Current release
workflows additionally pass actionlint and executable release-boundary
regressions; hosted publication remains a separate check.

Exact source `89c5e3c` passed hosted types, 80 regressions, dependency licenses
and the installed candidate check in run `39361611935`. Its final artifact
upload failed because the default uploader excludes the hidden `.release`
directory. The successor explicitly includes hidden files only under the
existing tarball/receipt/consumer JSON globs in both workflows. It does not
upload the npm cache or broaden them to arbitrary hidden files. The successor
requires its own exact-source CI and clean-source candidate receipt.

## Approved source-license qualification

The October 21 owner decision is implemented as the MIT grant in `LICENSE` and
the `MIT` identifier in both package metadata and the root lock entry. The text
and Bota attribution match the approved API SDK license. Structural comparison
confirms that no dependency package entry, integrity, resolution or version
changed. Third-party notices and the exact-source publication guard remain.

Actual packed consumers pass all 18 installed checks on Node 22.23.2 and
24.19.0 with npm 11.17.0. Both archives contain exactly six approved files,
including `LICENSE`. The installed manifest and consumer lock retain `MIT`;
the installed grant bytes and provenance digest equal the source. Strict types
pass on both runtimes, all three publication/tamper cases pass on both, and
the dependency gate passes 182 packages. These working-tree receipts correctly
record `dirty: true` and require clean-source requalification after delivery.

A read-only public registry check on October 21 still finds only `0.1.0`,
`latest: 0.1.0`, and an unoccupied `0.2.0-beta.0`. It establishes no authenticated
write authority or trusted-publisher configuration. No approval variable, tag,
workflow dispatch or registry write is changed by licensing the source.

## Remaining gates

1. Merge the reviewed source, then qualify its exact clean tagged commit on both
   declared Node versions. Any artifact reporting `dirty: true` refuses
   publication and cannot serve as clean-source evidence.
2. Configure and verify the public source, npm package ownership, protected
   environment/tags, human review and exact OIDC publisher/action permissions
   described in the release contract. Exact-source preview or stable publication
   approval and MIT approval remain mandatory. Source changes configure none of
   these external controls.
3. Recheck registry version occupancy and dist-tags, then run the matching tag's
   approved workflow. Registry tarball/integrity/provenance readback, clean public
   installation, channel-specific tag transitions and their retained receipt
   require a real execution; synthetic fixtures do not qualify publication.
4. Backend identity/integration/hosted-tool availability, docs-site promotion,
   and authorized live-principal smoke retain separate deployment/release gates.
   Help/import and synthetic identity evidence do not qualify live MCP operations.

Transitive dependency ranges are not globally frozen for future installations.
The consumer lock records the graph actually tested. This slice changes neither
authentication/storage/login/logout nor existing MCP tool behavior, and does
not implement or publish the separate Bota API SDK.
