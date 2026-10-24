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
| Preview-only publication | One tag trigger, `v0.2.0-beta.*`; no release/dispatch trigger. Guard requires clean HEAD equal to `GITHUB_SHA`, exact tag/version agreement, source-license approval and exact-source release approval. The workflow publishes the tested `.tgz` with `--tag beta --provenance --ignore-scripts`; it cannot promote `latest`. Prepared; publication remains blocked. |

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
packed readbacks, source identity and hosted CI. The unavailable dedicated
workflow-validator skill/actionlint is not claimed as run; local YAML parsing
and structural checks plus independent workflow review cover the saved files.

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

1. Root must commit/push the licensed candidate, then rebuild and re-smoke the exact
   clean source. Local working-tree artifacts honestly report `dirty: true`
   and cannot be promoted as clean-source evidence.
2. Configure/verify npm package ownership and the trusted publisher for this
   repository/workflow.
   Only after review, repository variables must approve the exact source:
   `CLI_PREVIEW_PUBLICATION_APPROVAL=<version>@<commit>` and
   `CLI_SOURCE_LICENSE_APPROVAL=<license>@<commit>`. No values were set here.
3. Recheck registry version occupancy and dist-tags, then use the matching tag
   and approved workflow execution,
   registry tarball/integrity/provenance readback, normal public installation,
   unchanged `latest`, and its own release receipt. Those remain unverified.
4. Backend identity/integration/hosted-tool availability, docs-site promotion,
   and authorized live-principal smoke retain separate deployment/release gates.
   Help/import and synthetic identity evidence do not qualify live MCP operations.

Transitive dependency ranges are not globally frozen for future installations.
The consumer lock records the graph actually tested. This slice changes neither
authentication/storage/login/logout nor existing MCP tool behavior, and does
not implement or publish the separate Bota API SDK.
