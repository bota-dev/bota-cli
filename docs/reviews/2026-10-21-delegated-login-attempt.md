# Inactive delegated login and family foundations

The callback section records the cohort accepted at
`f19f738dbe9bc00550c27a77a46c412f7d9d2cfc`. Its 29-test and package evidence is
historical and bound to that source. The adapter-neutral family follow-on is
reviewed separately below; neither cohort enables Platform login.

This is the first client boundary for [design section 6.2](../../../internal-docs/Developer%20Toolchain%20Design.md#62-platform-login-flow)
and implementation task T09. `src/delegated-login.ts` has no command importer.
It captures an authorization code through an owned local callback; it does not
complete Platform login, exchange a code, establish identity, create a delegated
grant, store credentials, refresh or revoke a family. Existing login and API-key
profile behavior are unchanged. Developer-session lifecycle remains separate
from browser logout under the owner's selected policy.

The explicit deployment includes the HTTPS-origin issuer, exact authorization,
token and revocation URLs, distinct REST/MCP resources and preregistered native
CLI client. This cohort uses the backend's inactive `/oauth/authorize`,
`/oauth/token` and `/oauth/revoke` manifest paths. There is no discovery or
production fallback. The request explicitly selects its grant resources,
initial exchange resource and read scopes. A shared CLI/MCP request includes
both resource indicators; the eventual exchange binding names one resource.
These arrays describe requested authority, not granted or issued authority.
Platform still owns project selection, consent and authoritative scope output.

Each attempt independently generates 256-bit state and a 256-bit S256 verifier.
Only the challenge and state appear in the authorization URL. The listener binds
an ephemeral port on the registered literal `127.0.0.1` or `::1` interface and
uses the exact `/oauth/callback` path. Its frozen handle exposes the URL and a
code-only result. A private WeakMap permits an immutable exchange-input snapshot
only for the original successfully closed, unexpired, uncancelled handle.
Explicit cancellation is sticky through closure; cancellation after code capture
also retires subsequent access to the exchange binding. A result already
delivered to the caller cannot be withdrawn and is still not a completed login.

The engineering limits for this inactive cohort are a 120-second default and
300-second maximum total attempt budget; 2 KiB request target; 8 KiB headers;
32 requests; eight concurrent connections; and 64 total connections. These are
selected client limits, not OAuth requirements or an authorization-code lifetime.
They do not implement the server's separate 120-second code expiry.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Explicit issuer/client/endpoints/resources and narrow requested authority | Frozen copied policy/selection, malformed/reflective input tests, repeated authorization resources and one exchange resource | Matched for inactive policy-v1 client input. No server registration or grant is created. |
| Code plus S256 and independent state/verifier | Actual authorization URL, private successful binding and recomputed S256 in IPv4/IPv6 fixtures | Matched locally. No browser, token endpoint or real identity is exercised. |
| Exact callback binding | Raw target and required exact Host, GET/body/header checks, canonical code/state, duplicate/extra credential rejection | Matched locally. Independent review found missing-Host admission; required-Host check and actual HTTP/1.0 refusal regression close that finding. |
| Browser cookie compatibility | Actual valid callback with unrelated local-app cookie canary | Matched locally. Cookies are bounded unused headers; they are never parsed, logged, reflected or treated as callback authority. |
| Callback race/error privacy | One synchronous claim, concurrent valid callbacks, wrong-state OAuth error followed by valid success, fixed static no-store/no-referrer responses | Matched locally. Remote descriptions and URIs never become diagnostics or result fields. |
| Bounded lifetime and complete owned closure | Slowloris/idle/aborted sockets, request/connection limits, bind deadline, late callback, joined cancellation/deadline and natural child exit | Matched in actual owned-loopback tests on Node 22.23.2 and 24.19.0. A final signal/deadline check follows normal server/socket join. |
| Compatible inactive packaging | Both offline cached package preparations pass all 18 installed checks and ship the existing six files | Matched for dirty source preparation. Command bundle stays byte-identical; only source provenance adds this inactive module. Clean committed/hosted qualification remains a delivery step. |
| Complete T09 shared login | No command wire, browser launcher, exchange, delegated identity, refresh persistence or revocation adapter | Not implemented by this slice. API-key profile storage is not a delegated refresh-store format. |

All 29 focused tests and strict TypeScript checks pass on both pinned runtimes.
Fixtures use owned literal-loopback sockets and synthetic authorization codes.
Package preparation uses an explicit offline npm wrapper and cached dependencies;
no external API, native profile database or credential store is accessed.
Historical package preparations and the first helper's pre-pack PATH failure
remain separate from the final source-bound preparation receipts.

The native redirect and PKCE choices follow [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)
and [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636). This narrow client does not
claim a complete OAuth client or a deployed authentication flow.

## Adapter-neutral refresh-family follow-on

`src/delegated-family-state.ts` and `src/delegated-family-engine.ts` add an
inactive data format and state machine for design sections 6.2–6.3 and T09.
No command imports them. API-key environment-v1 and secure API-key profiles,
their Windows credential adapter, and the callback implementation remain
unchanged. `bota-delegated-family-v1` and `bota/delegated/refresh/v1` are explicit
separate delegated namespaces, with no reinterpretation or migration of keys.

The trusted assembly seam receives one definitively returned token pair through
an opaque one-use handoff; consuming it must not perform or retry a code
exchange. The engine independently requires authoritative access verification
before deriving the server-family lease, and repeats verification inside that
lease before enrollment. Requested deployment resources never establish granted
authority. Issuer, client, user, organization, project, grant, family, granted
resources and grant scopes are pinned independently from the access token's one
resource, scope subset and expiry. Canonical server UUIDs have no version gate;
independently generated local IDs retain the local v4 requirement.

Every operation uses one pinned parent cancellation/deadline authority through
a retiring child signal and frozen assertion facade. The facade cannot extend
the original budget; after settlement or defective early lease release it is
unusable, and the child signal is aborted. Started callback work is joined before
return. Errors are fresh fixed projections of known diagnostic fields. Mutated
error messages, causes, accessors, forged objects and proxy hooks cannot escape
through an injected port error. A lease rejection is recorded separately from
its payload, including `throw undefined` and `throw null`.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Separate delegated schema, no API-key adoption | Exact format/namespace, dense bounded own-data fields, canonical copied UTF-8 bytes, API-key and reflective input refusals | Matched for inactive schema/codec only. No native persistence format is activated. |
| Authoritative enrollment and binding | One-use opaque handoff, current credential verification before and within lease, scope/resource narrowing and identity-retarget negatives | Matched through trusted injected authority ports. No backend identity endpoint or HTTP token response is consumed. |
| One family across CLI/MCP resources and aliases | Canonical store + issuer + client + server-family key; fresh snapshot and identity before caller action; concurrent resource rotations and initial enrollment collision tests | Matched for source ordering under a portable mock mutex. Native cross-process locking remains unqualified. |
| Durable intent before one refresh | `ready` → `refreshing` CAS before exchange; lost response leaves `refreshing`/`suspended`; three engine instances refuse all cached access without identity/business calls | Matched in injected crash/race tests. Unknown remote exchanges are never replayed or adopted. |
| Atomic rotation and retained consumed proof | Verified successor write/readback; one whole-family CAS changes current, prior consumed proof and `localGeneration`; only the older superseded proof is then deleted and proven absent | Matched through injected atomic CAS/store ports. `localGeneration` makes no server-generation claim. |
| Unknown local acknowledgment differs from unknown remote response | Lost ready-CAS acknowledgment permits a later exact durable ready read; pre-rotation uncertainty remains blocking; no old refresh is resubmitted | Matched in fault fixtures. Adapters must preserve the same durable acknowledgment and exact readback contracts. |
| Revocation despite ordinary authority loss | Current or last definitively consumed refresh proof identifies its family; unknown revocation blocks use and only explicit recovery repeats that exact proof | Matched against a synthetic backend contract retaining consumed proofs. No real revocation request is made. |
| Exact removal and recoverable uncertainty | Durable `removing` inventory before deletes; exact absence proof and CAS progress; unknown delete is not blindly repeated; removed tombstone retained | Matched in source fixtures. Accepted revoking/revoked cleanup is bounded to one extra ref, keeping the complete removal inventory within three refs. Missing proof cannot falsely establish revocation. |
| Cancellation after effects requires recovery | Pre-effect cancellation/deadline reports no recovery; metadata/store/exchange/revocation/caller-effect boundaries preserve fixed errors with `recoveryRequired: true` | Matched in bounded synthetic effect-boundary tests. No pending intent or credential reference is discarded. |
| Complete secure delegated login | No HTTP transport, native snapshot/store/lease adapter, browser launcher, profile command or CLI/MCP credential selection integration | Not implemented by this cohort. Platform login remains inactive; existing API-key behavior remains the enabled path. |

All **37 focused family tests** and strict types pass on **Node 22.23.2 and
24.19.0**. The immutable ignored source/log receipt is
`delegated-family-source-receipt.json`, SHA-256
`a196a6066198fe21ab8e86f6bfb9c835ec6c8998b231902339b5b937fdec73bb`,
recorded at `2026-10-22T00:34:42.877Z`. It binds the exact three new source/test
files and both focused/type logs. Fixtures use synthetic opaque credentials and
in-memory metadata/store/authority ports; they open no native credential store,
database, HTTP listener or external API. Independent review closed the issued
context-lifetime, recovery-flag, cleanup-closure, mutable-error privacy and
undefined-rejection findings with regression coverage.

The earlier callback's subsequent clean qualification is retained separately in
`delegated-login-attempt-clean-delivery-receipt.json`, SHA-256
`b0525de1bbac9b10b83e9407f20496a1f7010b834a7c2e50c26957593ee96ff4`.
That receipt records callback source `f19f738d`, its 29 tests, both pinned clean
offline installed-package checks and exact hosted CI `39696736013`. It is not
native delegated enrollment or qualification of this follow-on engine. This
cohort's clean committed package and hosted checks are separate delivery receipts.

The owner upstream removal of internal engineering harness files at `fb9661ff`
is preserved. Current package provenance must derive its source inputs from the
current clean commit rather than inherit the old callback input count. Native
cross-process leases, durable credential/metadata adapters, HTTP grant/identity
admission, installed enrollment and recovery, and deployed Platform authorization
remain explicit gates before command activation. Browser logout remains separate
from developer-session family revocation under the owner's selected policy.

## Bound revocation confirmation follow-on

The preceding family cohort is accepted source
`369e5d286ececa074010491cc1469e57084b2672`. Its immutable clean delivery receipt,
`delegated-family-clean-delivery-receipt.json`, has SHA-256
`e03834665e33cc832ea351d312ad3839ea64fd0edd7a1c16b898ca619e552fd5`.
That historical receipt binds its 37-test source, both pinned clean packages,
and hosted CI `39700744295`; it also records the missing bound revocation gate.
It is preserved unchanged rather than reinterpreted as this newer contract.

An ordinary RFC7009 empty HTTP 200 intentionally does not prove that a named
grant/family was revoked. This narrow follow-on replaces the trusted port's old
`'revoked'` string with a definitive normalized `{ grantId, familyId }` result,
or `'unknown'` / `'not_submitted'`. The engine supplies an independent frozen
expected pair from the validated snapshot while holding the canonical family
lease. It uses the same current or retained consumed proof as before.

Only an exact two-field own-data object, with canonical server UUIDs equal to
both expected IDs, permits the transition to `revoked`. Empty bodies, 200-like
objects, old strings, raw wire envelopes, missing/mismatched IDs, extra credential
fields, inherited/reflective/proxy shapes and unknown outcomes remain fixed
`revocation_unknown` with `recoveryRequired: true`. The durable state stays
`revoking`, every exact credential reference remains retained, all cached access
and removal remain blocked, and no automatic retry occurs. Only explicit
recovery resubmits the same proof and expected IDs.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Expected authority comes from the leased family | Frozen pair captured for both current and consumed proofs, including canonical non-v4 server IDs | Matched in source fixtures. No caller-supplied replacement family ID is accepted. |
| Definitive matching confirmation before removal | Exact two-field canonical binding validation, successful explicit recovery, then exact removal | Matched through the trusted normalized port; shape alone is not remote commit authority. |
| Fail closed for empty or contradictory receipt | Nineteen malformed/empty/200/raw-wire/wrong-ID/extra-field cases, retained references and blocked cached access/removal | Matched in synthetic crash/recovery fixtures. No proof is discarded on an absent confirmation. |
| Private receipt hooks cannot become authority or diagnostics | Accessor/proxy/inherited/array/symbol shapes refused, zero private hook evaluations | Matched at the normalized result validation boundary. |
| Real HTTP revocation confirmation | Future adapter must use the configured trusted issuer/client endpoint and validate `bota_revoked: true`, `bota_grant_id` and `bota_family_id` against both expected IDs before producing the normalized pair | Unimplemented. Plain HTTP 200/empty body must map to unknown; standard empty-200 semantics remain separate. No HTTP adapter or request is introduced. |

All **41 focused family tests** and strict types pass on **Node 22.23.2 and
24.19.0**. The new immutable ignored source/log receipt is
`delegated-bound-revocation-source-receipt.json`, SHA-256
`5315dfc310b3c4e47a82c2f5e104111614c553c9147d0a0a438e6dca2edb61e4`.
Independent scoped review reports no remaining actionable finding. The existing
schema/codec and callback files are unchanged; only the inactive engine port and
its tests change. There is still no HTTP/native adapter, delegated credential
installation, command activation, browser launch or enabled Platform login.

## Inactive one-attempt HTTP component

The preceding bound-port source is accepted at
`eb402d5c0108a269602401feda2bd8a98d6fb991`. Its historical clean receipt,
`delegated-bound-revocation-clean-delivery-receipt.json`, has SHA-256
`f553a0ec00699a11db0efa4ffa6dbd9a39e86e8c11a4fac69da11197cfaec937`.
It binds the previous 41-test family contract and hosted CI `39701858726`.

`src/delegated-http.ts` adds a standalone inactive HTTP component. Production
construction captures native fetch and requires a frozen explicit HTTPS
deployment plus a mandatory resource-aware identity verifier. The separate
`ForTrustedPorts` factory is a trusted assembly seam, with no CLI, environment,
root override or production fallback. No identity route, URL or wire schema is
selected or discovered: the mandatory verifier remains an explicit read-only
authority port and may not mutate SQL, credentials or other native state.

An original completed callback handle permits one code exchange across factory
instances. Code, verifier and redirect come from that owned handle; the code is
never retried after submission or an unknown result. The definitive result may
later enter the existing one-use enrollment handoff; consuming a handoff must
never hide a code exchange. Refresh and exact-bound revocation each send one
form POST to the configured endpoint, with no bearer/cookie forwarding, redirect
following or automatic retry. Existing refresh and consumed revocation proofs
remain usable after process restart; they do not require the access-token ledger.

Access verification accepts only currently issued transient tokens from this
factory, for their exact configured REST or MCP resource. Unknown, wrong-resource
or another-factory access tokens fail before verifier egress. This bounded
128-entry ledger contains no refresh token and is not durable access caching.
Every admitted use still calls the authoritative verifier and compares its
current identity. Token wire resource, scopes, grant and family must match that
authority; a code result cannot expand requested grant resources or scopes.

`expires_in` is explicitly a **range-only relative hint**: an integer from one
through 300 seconds. It is not reconciled across server/client clocks or treated
as proof of exact absolute expiry. A fixture deliberately uses a one-second hint
with a separately authoritative absolute expiry, making this limitation visible.
The normalized pair uses only that exact identity expiry; the family engine
continues to compare it exactly. No `now() + expires_in` expiry is manufactured.
Selecting a cross-clock plausibility rule or an absolute wire expiry extension
remains future contract work.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| One configured attempt, no credential redirect/retry | Exact form/header assertions, owned callback, consumed attempt after lost response, foreign owned redirect sink receives zero requests | Matched in component fixtures. No browser or external issuer is contacted. |
| Wire and identity admission | Strict flat token body, canonical opaque credentials/IDs, exact resource/scopes/grant/family comparison, requested-authority expansion refusals | Matched through a mandatory trusted identity port. A production identity route and codec remain unselected. |
| Bounded owned token/revoke body | Explicit 16 KiB advertised and decoded bound; gzip overflow, duplicates, BOM, invalid UTF-8, truncated body and fixed diagnostics | Matched using actual owned HTTP and native fetch response streams. The external identity port needs its own qualified HTTP body/cleanup contract. |
| Original operation authority and total deadline | Pinned parent signal/budget/assertion, own-data retarget refusal, retiring child, 30-second maximum whole-call budget with a monotonic deadline | Matched in cancellation, retarget, delayed-timer and late-publication fixtures. The timer alone is never expiry proof. |
| Read-only verifier withdrawal | Never-settling and late verifier fixtures return fixed failure, retire authority, observe/discard late completion and publish no ledger entry | Matched for bounded public settlement. An uncooperative underlying verifier may outlive the returned method; universal join is not claimed. |
| Native response/body cancellation join | Unfinished actual response cancellation and delayed/rejected reader cancellation prevent credential publication until owned cleanup settles | Matched for these qualified native-fetch fixtures. An arbitrary uncooperative injected fetch/body cannot establish universal cleanup bounds. |
| Bound revocation before proof removal | HTTP 200 plus exact positive `bota_revoked` and both expected IDs; empty/malformed responses stay unknown | Matched in actual HTTP plus portable engine composition: proofs remain in `revoking`, cached access/removal block, then explicit matching recovery permits exact cleanup. The mock lease is not native cross-process qualification. |
| Unknown mutation status | `mutationSubmitted: true` after POST entry, including body, identity, cancellation and cleanup failures | Matched in fixture assertions. A failed code exchange is never described as safe to replay. |
| Complete initial enrollment and Platform login | No native attempt journal, durable initial proof retention, command imports or browser launcher | Not implemented. An abandoned initial grant after a definitive token response and failed identity verification may remain remotely active; future enrollment must own durable attempt/cleanup recovery before activation. Unknown grants require explicit Platform revoke-developer-access or expiry recovery. No automatic revocation is added. |

All **21 HTTP component tests** and strict types pass on **Node 22.23.2 and
24.19.0**. The immutable ignored source/log receipt is
`delegated-http-source-r2-receipt.json`, SHA-256
`36f97523434649e8046b10840f7ef10dccd0f5d55cf436672173cff6f35d116c`,
recorded at `2026-10-22T01:11:01.239Z`. These include actual loopback token,
revocation and fixture-identity reads through an explicit trusted mapping from
configured HTTPS URLs to owned loopback HTTP. They qualify HTTP component
behavior, not production TLS, a deployed identity endpoint, native credential
storage or real Platform enrollment. Independent review closes the concrete
deadline/authority findings; root review closes the monotonic and context fixes.

Initial fixture work incorrectly canceled a stream still locked by
`Response.json()` and expected a read-only verifier to have mutation status.
Those fixture errors were corrected without relaxing production checks. The
first receipt helper then selected the old family test filename; its total-count
guard refused the run. Its logs are retained separately; only the explicit r2
receipt above qualifies this source. Earlier callback/family receipts remain
historical. No API-key path, callback, family schema/engine or command importer
changes in this cohort; no native store, external account, registry or deployment
operation is performed. Platform login remains inactive.
