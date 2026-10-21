# Environment-backed developer profiles

This increment implements the first bounded slice of Developer Toolchain
Design section 6 and implementation task T06: explicit environment-backed
project profiles shared by terminal commands and local MCP. Native credential
storage, legacy migration and delegated Platform login remain separate work.
At this increment's October 20 baseline, the owner's MIT decision covered the
API SDK only. Separate owner approval on October 21 now licenses the CLI under
MIT; the [preview release review](2026-10-19-cli-preview-release.md) records the
remaining exact-source publication gates.

## Frozen cohort

`auth profiles add NAME --from-env` requires an explicit trusted `--api-url`,
verifies `BOTA_API_KEY` through the existing seven-field identity endpoint, and
exclusively creates one metadata record. There is no default selection,
replacement, native store access or automatic legacy migration. Literal
loopback HTTP requires explicit development opt-in; other origins use HTTPS.

Metadata contains only name/version, canonical origin, exact project and
organization, environment source and the development flag. It contains no key,
hint, hash, credential ID, scopes or human identity. Project IDs remain bounded
opaque strings; safe JSON rendering preserves their values while escaping
terminal controls. The selected environment credential cannot be reflected
inside returned identity or saved metadata.

`--profile NAME` resolves only the current environment key. All explicit or
environment API-origin overrides must match before key access or a request.
One bounded identity request verifies exact project/organization before cloud
REST commands, trigger or either local MCP mode. Status reuses that verified
identity. Missing, empty, rejected, quarantined or mismatched credentials never
fall back to legacy configuration or browser consent. Backend admission still
governs every operation; a local identity check grants no business permission.

Without `--profile`, legacy saved-key precedence, login/storage and end-user
MCP compatibility stay unchanged. Profile selection refuses legacy login/logout
and ambiguous profile-management combinations. Local help, metadata list/remove,
unavailable webhook management and manual webhook forwarding need no identity
or credential. Removing metadata never revokes a backend key.

MCP captures one verified startup context. Changed environment/profile metadata
requires restart; metadata removal does not stop existing processes or claim
cross-process revocation. This cohort does not refresh credentials per tool call.

## Implementation and review evidence

| Requirement | Source and verification | Conformance boundary |
|---|---|---|
| One explicit origin/project provider | `profiles.ts`, config context and Commander pre-action hook; real command and both stdio MCP fixtures | Shared startup selection; no-profile compatibility remains tested separately. |
| Identity before cloud effects | Bounded native identity reader, exact seven-field decoder and project/org comparison; no-fallback/foreign-origin negatives | One attempt, 30-second total budget, 64 KiB advertised/streamed body limit, strict UTF-8 and redirect refusal; no live API acceptance. |
| No persisted credential | Exact flat versioned schema and metadata inspection; fixed errors and reflected-bearer negatives | Only explicit environment injection; no native store or enrollment journal for secrets. |
| Atomic metadata and safe routing | Exclusive hard-link publication, fsynced temporary file, immutable records and per-name mutation locks; collision/interruption/concurrency/path tests | Complete visible record or refusal; no replacement. Unknown stale locks are not stolen; orphan non-secret temporary files are not selected. |
| Filesystem trust | Directory/link/file bounds and ownership/permission refusal; platform fixtures | POSIX current-user/root ownership and non-writable ancestry, with trusted root-owned sticky ancestors; Windows relies on the account's trusted home ACLs. No hostile-same-user sandbox or independent Windows ACL certification. |
| Opaque result safety | Source status/profile rendering and Unicode/control fixtures | Exact parsed IDs/scopes retained; control characters escaped. This adds no redaction promise for arbitrary business tool results. |
| Installed delivery | Packed external consumer now enrolls, verifies selected status once, lists and removes without credentials/network | Candidate-only source/package receipt; no CLI license grant or npm release. |

Review caught and corrected raw-URL normalization accepting dot-segment paths,
empty query/fragment and empty userinfo; metadata origins now require a raw
origin form. It also corrected missing POSIX parent/ownership checks and an
unnecessary ASCII grammar for opaque IDs. Enrollment and selection both reject
conflicting environment origins before resolving the key. Native error causes,
response bodies, URLs and bearer values do not enter profile diagnostics.

The shared decoder extraction preserves the existing no-profile seven-field
identity behavior. Tests use synthetic keys/identity, loopback endpoints and
isolated homes; a test-only filesystem spy verifies selected commands never
read or write the legacy credential file. Native stores, owner profiles and
live project/provider/device services are not used for qualification.

Exact aggregate, packed-consumer, hosted-source and downloaded-artifact receipts
are recorded in the owning internal developer-toolchain implementation track.
Local source tests, hosted Linux results, publication and deployed acceptance
remain distinct evidence. T06 remains partial until native store/migration
cohorts pass; T07–T09 separately own delegated human authentication.
