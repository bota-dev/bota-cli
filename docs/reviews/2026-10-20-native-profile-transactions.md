# Native profile transaction source foundation

This is the adapter-neutral part of T06, reviewed against Developer Toolchain
Design v0.12 section 6.3.2 and implementation track section 17.1. It defines
enrollment, selection, removal and explicit recovery over injected ports. It
does not enable native enrollment or Platform login. T06–T09 and the overall
toolchain milestones remain partial.

The current `src/index.ts` does not import this engine; the `tsup` entry remains
that index. This source is not mounted in the CLI or either local MCP mode and
is not part of their current executable bundle. Existing environment-v1
profiles and no-profile credential precedence retain their own behavior. No
owner profile, real credential store or live identity service is exercised.

## Frozen port contract

`NativeProfileTransactions` accepts an exact-reference native store, durable
snapshot compare-and-publish, current project-identity reader and exclusive
lease. Each operation passes the same abort signal and opaque budget to every
port. The engine never extends or serializes the budget. Ports must cooperate
with cancellation, finish or terminate their work within that budget, and join
cleanup before resolving; the source engine cannot interrupt a port that never
settles.

The lease must own the fixed store namespace and then the selected profile for
the entire callback, including credential lookup, identity and the caller's
action. This deliberately serializes distinct profiles within one store.
Process-lifetime kernel ownership is required; a directory, PID or elapsed age
cannot establish it. The engine rejects an absent or repeated callback and a
forged callback result, but an injected port remains trusted to hold actual
ownership until callback settlement and to release/join in `finally`.

`snapshots.load()` returns proven absence or one complete strict snapshot and
must refuse a colliding v1/foreign profile. `publish()` atomically and durably
compares the previous revision and publishes the next complete snapshot. Its
only outcomes are `committed`, `not_committed` and `unknown`; an exception or
malformed result is unknown. The future filesystem adapter must enforce bounded
input bytes, private ownership/ACLs, safe path/handle resolution and durability.
Those properties are port obligations, not evidence supplied by these tests.

Native reads return exactly absent or present plus a private key. Native write
and delete acknowledgments have fixed allowlists; malformed objects and raw
errors never count as success. References have independent random profile and
credential UUIDs in one fixed store namespace. Before persisting enrollment
intent, the engine verifies that the generated exact native reference is absent.
It never enumerates or adopts an existing entry. The namespace lease prevents
cooperating writers from racing that check. Protection from outside writers
requires a qualified adapter namespace and trust model; absence alone does not
prove ownership against arbitrary external store access.

## State and recovery decisions

Native records are format v2; journals and enclosing snapshots are format v1.
Unknown fields, accessors, proxies, foreign stores/references, identifier aliasing
and inconsistent state combinations are refused. Snapshot revisions and
transaction IDs are independent UUIDs. Records contain only safe binding data:
name, origin, project, organization, store/reference, backend key ID and the
explicit loopback-development flag. They contain no bearer, key hint/hash,
scopes or cached grant. Known objects are copied and frozen; record and snapshot
serialized bounds are 8 KiB and 24 KiB. Current identity has bounded opaque IDs,
at most 256 bounded scopes and a 64 KiB safe projection.

| Persisted state | Selection | Explicit recovery/removal |
|---|---|---|
| Absent | Refuse | Enrollment verifies identity and reference absence, durably publishes intent, then writes once. |
| No record + enrollment intent | Refuse, including environment override | Read and clean only the intent's exact reference; verify absence and publish a removed tombstone. Never resend the write. |
| Ready + committed enrollment journal | Refuse until recovery | Verify private readback and current pinned identity, then clear the journal. Recovery never deletes a committed credential. |
| Ready + no journal | Verify current identity under the lease | Stored selection requires pinned key ID. An explicit environment key may have a different key ID within the same project/organization. |
| Disabled + removal intent | Refuse, including environment override | Exact-reference delete, confirm absence, then publish a removed tombstone. Unknown cleanup retains the journal for explicit recovery. |
| Removed + no journal | Refuse | Repeated remove/recover returns the same terminal state without native calls. |

An unknown native write is never automatically retried or followed by an
implicit cleanup. A known or ambiguous publication failure prevents the next
native mutation. Removal durably disables the profile before deletion; a delete
acknowledgment alone is insufficient without verified absence. Explicit recovery
first reads the journal's reference and only deletes if it is present. A lost
terminal-publication response therefore does not force another deletion after
proven absence. A retained committed journal keeps `recovery_required=true` on
every failed recovery, including unavailable readback, rejected identity or a
known failed journal-clear publication.

Tombstones retain the non-secret ownership/binding record and reserve the
profile name. Name reuse, rotation, garbage collection and legacy migration need
their own contract. No backend key revocation is implied by local removal.

## Selection and business-operation boundary

Selection validates the profile state, explicit origin and any expected startup
binding before reading a credential. Missing/empty explicit environment values,
missing or unavailable native entries and foreign identity never fall back to
legacy configuration or another credential source. Stored selection pins the
exact safe `key_id`; a ready same-project/organization environment override is
intentional. Pending/disabled/removed state blocks that override. Every selection
rechecks current identity; a stored local binding is not permission to execute a
backend operation.

The action receives a frozen credential context with a non-enumerable key and
must return an already-sanitized success or business-failure envelope. The engine
does not sanitize arbitrary returned values. Thrown failures are opaque and map
to fixed diagnostics. `operation_may_have_executed` is immutable and becomes true
when the action was entered and then threw, exceeded its budget, was cancelled,
or could not confirm lease cleanup. It is independent of the immutable
`recovery_required` flag for local profile state. An operation may have completed
remotely even though its result is refused. Neither flag authorizes automatic
operation retry. The future business adapter must preserve its safe status and
submission-uncertainty contract in returned envelopes; that integration is not
wired or qualified here.

## Requirement comparison and verification

| Requirement | Implementation and evidence | Status |
|---|---|---|
| Strict versioned immutable metadata without credentials or cached authority | Exact record/journal/snapshot decoders; unsafe-shape, reflected-key, identity/scopes and immutability fixtures | matched within source cohort |
| Intent before native mutation; no unknown-write retry | Enrollment sequence, exact readback, CAS outcomes; unknown-created/absent, throw-created, malformed and bad-readback fixtures | matched within source cohort |
| Exact cleanup ownership and collision refusal | Fresh-reference absence check; owned-journal reference only; unrelated synthetic entry retained | matched for cooperating synthetic ports; external namespace trust unverified |
| Committed enrollment survives recovery | Readback/current key-ID verification and journal-clear fixtures; failed-recovery classification regression tests | matched within source cohort |
| Durable disable and verified absence before terminal removal | Disable-before-delete, unknown/failed/delete-without-absence and lost terminal-publication fixtures; terminal idempotence | matched for synthetic durability; real crash/power-loss behavior unverified |
| Shared no-fallback selection and identity | Origin/startup binding, stored key-ID swap, same-project environment override and pending-state override refusal | matched within source cohort; CLI/MCP provider integration not implemented |
| Lease held through action; bounded cancellation | Same exact context across ports; action/removal and cross-profile serialization; callback/result/cleanup fault fixtures | matched for synthetic ports; kernel lease and process lifecycle unverified |
| Preserve possible business effects independently of local recovery | Late action, opaque throw and release-failure execution-marker fixtures | matched for declared action contract; real business adapter not implemented |
| Existing environment and no-profile behavior | No changes to the current provider, index or executable entry; existing regressions remain owning coordinator gates | unchanged source wiring; native installed behavior not implemented |

The focused suite passes 52/52 on Node 24.19.0. Independent review reruns pass
52/52 on both the supported minimum Node 22.23.2 and Node 24.19.0; a separate
16-case injected-port probe passes on the final reviewed source. TypeScript
`--noEmit` passes. The synthetic fixtures use only in-memory snapshots, fake
keys, native entries and exclusive callback gates. They do not invoke a native
store, filesystem adapter, identity network endpoint, CLI registration or MCP
provider. Aggregate CLI, packed artifact and exact-source delivery receipts are
recorded by the owning coordinator in the internal implementation track.

Independent review corrected three source gaps before this assessment: the
original action path accepted a result after budget expiry; the lease wrapper
did not verify callback entry/result; and failed committed-journal recovery
could lose its recovery-required classification. The final tests exercise all
three corrections. No remaining source blocker was found for this bounded
cohort.

## Snapshot bytes and Windows lease continuation

The next bounded source slice follows design v0.13 section 6.3.2 and implementation
track section 18. `native-profile-codec.ts` supplies fixed whitelisted JSON order,
UTF-8 and exactly one trailing LF, with a 24-KiB inclusive limit. Strict core
state validation and exact canonical-byte equality refuse duplicate names,
alternate spelling/order/whitespace, BOM and invalid UTF-8. Owned copies reject
shared/proxied storage without calling input hooks. Opaque identifier code units
retain the core contract; this is Bota encoding, not a general JSON standard.
Twenty-nine focused cases pass on both Node22.23.2 and24.19.0.

`windows-native-api.ts` and `windows-native-lease.ts` add an explicit factory for
Windows x64/local NTFS. Koffi 3.3.3 is exact in manifest/lock, with unchanged prior
locked entries and exact optional platform versions. Bootstrap uses the loaded
Windows kernel and checks the actual inbox before loading the fixed security DLL;
hosts outside `C:\Windows\System32` refuse. DLL path/owner/DACL and filesystem
attestation follow. Native diagnostic/loader overrides and Electron packaging
refuse before Koffi evaluation. Trusted Node/installed dependencies, OS and admin
code remain premises; this is not a hostile-same-user sandbox.

The root is a runtime-immutable callsite capability. Hold non-reparse ancestry
and root handles without delete sharing through the session. Ancestors may allow
creating unrelated children, but untrusted path replacement/retag/authority
changes refuse. A new private leaf gets an exact protected current-user/SYSTEM/
Administrators full-control DACL; an existing differing leaf refuses without
repair. Existing empty, single-link private lease files persist. Share-zero store
then hex-encoded profile handles establish ownership through callback settlement;
file existence, timestamps and PIDs never do. Reverse cleanup retires handles
before one close attempt; ambiguity poisons further process admission.

Tests use injected ports and only fresh synthetic directories. Actual Windows
cases verify private/inherited/Everyone DACL handling, junctions, nonempty/link/
directory collisions, two-process exclusion across profiles, cancellation,
normal closure and forced-owner death/reacquisition without stale-file deletion.
Isolated FFI faults verify fixed private diagnostics, process poisoning and
release of a just-acquired share-zero handle before its child exits. An opaque
startup exception after an allocating call can retain an unknown resource until
restart; the factory fails closed rather than guessing a numeric handle or
retrying. That case is tested in an isolated child, whose exit owns release.
The final lease suite passes on Node22.23.2 and24.19.0: 24 cases, 23 passed and
one expected Linux-refusal skip on Windows. Types pass on both runtimes. No
hosted Windows or other operating-system acceptance is inferred.

Native calls are synchronous and nonpreemptible. Budget/signal checks surround
high-level native operations and callback settlement, not every constituent FFI
call. Normal cancellation joins known cleanup, but stalled OS calls and unknown
startup resources do not satisfy a universal hard deadline/all-resource-join
claim. The engine's complete bounded-port target remains partial at that edge.

| Requirement | Implementation/evidence | Current status |
|---|---|---|
| One bounded strict snapshot wire | Canonical byte codec, golden/alias/malformed/ownership/state cases | matched in pure source; persistence absent |
| Kernel ownership held through callback | Actual share-zero child exclusion and process-death/reuse; reverse-close fault cases | matched for the declared local Windows cohort |
| Trusted fixed filesystem namespace | Immutable root, handle ancestry/final-path/NTFS/DACL/reparse checks and actual refusal fixtures | matched within trusted installed runtime/OS/admin premises |
| Private native failures and unknown cleanup | Fixed wrappers, one-attempt retirement, still-live-child reacquisition and startup poison fixture | partial: unknown startup resources require process restart; no universal OS preemption |
| Secure durable credentials used by CLI/MCP | No Credential Manager signatures, snapshot CAS, provider or command registration | not implemented; no real credentials or owner profiles exercised |

The selected in-process binding replaces the earlier PowerShell/C# helper
proposal for this cohort, avoiding helper/compiler descendants. Independent
fresh consumers on both Node versions execute Koffi's normal installation hook,
select the same prebuilt, preserve the frozen lock and pass fixed-DLL call/exit
probes. The native payload SHA-256 is
`f7af4982457657d2e7ad46acb076614ed7122d6efbdbfbc75f21ec12681fa121`.
Main and platform manifests declare MIT; full MIT notices were inspected in the
parent Koffi distribution. The platform archive has no separate license file.
No compiler output/fallback occurs in these selected installations. This does
not certify other platforms, source builds or installed credential enrollment.

Durable filesystem CAS and an exact-reference Windows Credential Manager adapter,
real-store interruption recovery and installed native behavior remain gates.
Only then may enrollment, per-invocation CLI/MCP resolution and explicit migration
be wired. The current MCP startup credential snapshot cannot establish the new
lease contract. Delegated Platform login, public CLI licensing/publication and
live-auth acceptance remain separate. Aggregate source/package/hosted receipts
are recorded with the existing implementation track, not inferred here.
