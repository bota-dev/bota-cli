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

## Inactive delegated identity response codec

The preceding HTTP component is accepted source
`59024c30837c27d1f74b37f47efd585bb190d306`. Its immutable clean delivery receipt,
`delegated-http-clean-delivery-receipt.json`, has SHA-256
`57d40e36a5050b3ed02f7692d83ac8c07fad4b9963721ffad5ec176c43f80723`.
It binds the previous 21-test HTTP contract and hosted CI `39704353495`; the
historical statement that the identity codec was unselected applies to that
source. Those HTTP source/test bytes remain unchanged in this cohort.

`src/delegated-identity.ts` adds a standalone parsed-value normalizer for the
backend's committed `api/src/auth/developer-auth-identity.ts` schema, last owned
at `2a0825c3ff7b180b6c516e7a61bf587ecc9566d3`. It accepts exactly the **14**
snake-case server fields with `format_version: 1` and
`credential_type: developer_delegation`, then returns exactly the engine's **12**
normalized fields. The result and all authority arrays are copied and frozen.
Canonical lowercase server UUIDs do not have an invented UUID-version gate.

The caller must supply an explicit validated deployment, the actual configured
REST or MCP resource and safe current seconds. The response issuer/client must
match that deployment; grant resources must be registered, contain the actual
resource and remain distinct from the client's full registration. Grant/access
scopes come only from the response, are unique known read scopes, and access
scopes must be a subset of grant scopes. Exact authoritative expiry must be
after the supplied current time and within 300 seconds. The optional already
trusted expected grant/family pair checks known-family consistency; the engine
still owns comparison of the complete pinned user/org/project/resource/scope
binding. Request scope sets and profile labels supply no authority.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Backend wire and engine DTO alignment | Backend integration-fixture-shaped REST/MCP bodies, exact 14-to-12 projection and generic canonical server UUIDs | Matched in portable source fixtures; no cross-repository runtime import. |
| Explicit resource, deployment and family consistency | Wrong issuer/client/resource/registration, missing grant resource and wrong optional expected IDs refused | Matched at the parsed-data boundary. A matching object is not proof of authentication. |
| Authoritative permissions and exact expiry | Empty/subset scopes accepted; duplicate/unknown/escalated scopes, duplicate resources, expired/over-300-second/unsafe times refused | Matched without manufacturing expiry or expanding consent. |
| Credential-free strict own-data boundary | Missing/unknown/private fields, accessors/proxies, inherited/non-enumerable/symbol fields and sparse/reflective arrays refused; private hook count remains zero | Matched with fixed fresh diagnostics and no cause or private input reflection. |
| Copied immutable output | Top object and all three arrays frozen; source mutation cannot retarget the result | Matched. No token, profile, database or network operation occurs. |
| Duplicate JSON members and HTTP authentication | Text/bytes are refused; a fixture explicitly demonstrates that a prior JSON parser loses duplicate-member evidence | Deferred to a future bounded resource-aware transport. This codec accepts parsed values and does not authenticate, select an endpoint or admit an HTTP/MCP request. |

All **13 focused codec tests** and strict types pass on **Node 22.23.2 and
24.19.0**. The immutable ignored source/log receipt is
`delegated-identity-source-receipt.json`, SHA-256
`f0a722c9fce3cbea0804d68c30478eb67ad5748aa1c53752868efe76ad6756ca`.
Independent scoped review reports no remaining concrete finding. The existing
21 HTTP tests, callback and API-key/native paths are unchanged.
This closes the strict parsed-DTO conversion prerequisite only. A future owner
must supply a fresh successful response from its explicitly trusted resource
endpoint, reject duplicate JSON members and qualify response bounds/cleanup.
No endpoint URL is guessed and no token egress, native store, command/browser
activation, registry or deployment action occurs. Initial enrollment durability,
abandoned-grant cleanup, real TLS/admission and native cross-process acceptance
remain open; Platform login remains inactive.

## Inactive REST delegated-identity transport

The parsed codec above is delivered at `0a5f259c1ed0ce7e3217c088114463ee54965db5`.
This increment adds a separate REST-only verifier. Its required identity URL
must exactly equal the configured REST origin and path prefix followed by
`/auth/delegated-identity`; root resources use an empty prefix. There is no
endpoint discovery, redirect alias, inferred production deployment or command
importer. Existing token/callback/family/codec source is unchanged.

The verifier requires the selected REST resource before egress and sends one
GET with the access bearer in its header. MCP resource requests are refused
without a REST fallback. An opaque token's actual audience cannot be inferred
from its bytes: the backend must enforce it, while the existing token adapter
and family engine retain their resource/binding checks. The request uses
captured native fetch, HTTPS configuration, no redirects, cookies or retries.

A 16KiB decoded-body bound, exact successful JSON response and raw duplicate
member rejection precede the existing fourteen-to-twelve-field codec. The
bounded wire-shape walk detects escaped duplicate keys and accepts key-like
string content without mistaking it for a member. Nested extensions, BOM,
invalid UTF-8, private fields and stale/wrong authority are refused. Relative
token expiry never substitutes for the authoritative identity expiry.

The original native parent signal, budget object and assertion are pinned
before and after their use. One monotonic maximum thirty-second child budget
cannot extend the parent. The child is retired, response/body cancellation is
awaited, the reader is released and parent listeners are removed before any
result is returned. Captured native response/body slots ignore shadow getters.
Failures expose a fresh fixed diagnostic, without raw response/error/cause.
Trusted replacement transports must honor cancellation and own their I/O;
arbitrary uncooperative transports have no universal bounded-join guarantee.

All **15 focused checks and strict types pass on Node 24.19.0 and 22.23.2**.
They exercise actual loopback GET/redirect/status/body behavior, resource
refusal, raw duplicates, schema/expiry boundaries, cancellation before headers
and during a stalled body, the finite deadline, context retargeting and native
slot/body cleanup. Explicit trusted mapping supplies owned HTTP for configured
HTTPS URLs. This proves neither production TLS nor a mounted backend endpoint.
Source/log/dependency/runtime receipt `rest-identity-http-source-receipt.json`
has SHA-256
`56a6cd6c4138a7b6523172798a35b906ed918eeb1c85357b938804c6ae8cf7cc`.
Independent scoped review found no remaining concrete issue.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Explicit resource-aware identity read | Exact configured REST endpoint, one actual GET and pre-egress wrong-resource negatives | Matched for this private REST transport. Opaque token audience remains server-enforced; MCP needs its own transport. |
| Strict authenticated response boundary | Success/status/header/body bounds, escaped raw duplicate rejection and committed identity codec | Matched in owned HTTP fixtures. Live backend, certificate trust and ingress remain unqualified. |
| Retiring authority and owned response cleanup | Parent retargeting/expiry, pre-header and stalled-body cancellation, deadline, captured native slots and fixed failures | Matched with cooperative actual native fetch/body work. No arbitrary-port universal-join claim. |
| Shared login activation | No command/browser/native store or initial enrollment producer | Partial. Durable initial proof retention, native family coordination, configured consent and live acceptance remain open. |

## October 22 retirement of browser API-key export

No-argument `auth login` now fails locally with `platform_login_unavailable`
and fixed environment/secure-profile guidance. It no longer opens a browser,
binds a callback listener, receives a project key through a URL or writes that
key to configuration. The unused dashboard override remains accepted for
compatibility but cannot reactivate the flow. Help, README and missing-credential
guidance describe the available API-key workflows.

This deliberately retires the older browser-key compatibility behavior: it
cannot satisfy the design's code-only URLs or separate developer-session
requirements. Explicit legacy `auth login <key>` and logout retain their
existing behavior; explicit environment and secure profiles are unchanged.
Legacy key arguments still use plaintext config and command-line input and are
not presented as secure enrollment.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| No browser export of project secrets | Actual CLI subprocesses fail without a callback, make zero fixture requests and preserve saved config bytes; fixed JSON/human diagnostics contain no credential/URL | Matched in source and controlled subprocess execution. Backend/Portal retirement has its own evidence. |
| Preserve explicit API-key compatibility | Key-argument enrollment, logout, identity/profile and complete CLI regression suites | Matched for tested source. No owner credential or canonical store is accessed by the new retirement tests. |
| Source/package qualification | Both Node 24.19.0 and 22.23.2: 652 total, 649 pass, three expected platform skips; strict types; installed candidate verification and 182-package license check | Matched locally. Exact-source hosted checks and public package availability remain separate. |
| Secure delegated enrollment/shared auth | No native initial-attempt journal, abandoned-grant recovery, native family provider or configured browser consent is enabled | Partial overall. Retirement closes an unsafe old path; it does not complete Platform login. |

## Protected enrollment ordering and shared delegated consumers

This private source increment adds an opt-in recoverable producer, first-response
custody checkpoint, enrollment-attempt revocation client, MCP identity verifier
and shared REST/MCP invocation assembly. It supplies no default deployment,
native delegated journal/store, public login switch or migration from API keys.
No-argument `auth login` remains unavailable. The existing canonical-host ACL
refusal is retained; no permissions were repaired or alternate storage selected.

The recoverable producer generates an independent attempt UUID and cleanup
verifier in addition to PKCE/state. It retains the exact original deployment,
selection, redirect and both proof secrets through an explicit trusted port
before returning any authorization URL or accepting a callback. The URL carries
only the attempt ID and independent S256 challenge. An exact matching positive
acknowledgement is required; unknown or negative retention joins the listener
and cooperative port and returns no attempt. This establishes source ordering,
not actual protected OS persistence or crash durability.

For a genuine recoverable attempt, code exchange requires a separate initial-
refresh custody port before any token request. A well-formed first refresh is
retained in the attempt namespace before resource identity verification, with
claimed grant/family IDs treated as untrusted until verification. Access tokens
stay transient. The custody child context retires immediately when that one
operation joins; it cannot remain usable while a later identity check waits.
Identity failure, cancellation or an uncertain receipt never adopts a family,
deletes recovery proof or silently repeats code exchange.

The existing configured revocation endpoint accepts an explicitly selected
private Bota extension: the independent verifier, original PKCE proof, attempt
ID and exact original client/redirect/resource bindings. Only a strict positive
receipt matching that attempt and consistent derived grant/family IDs confirms
cleanup. Empty RFC7009 success, lost response or malformed metadata stays
unknown. The adapter does not remove custody; explicit recovery can repeat the
same protective request. No current account call or issuance is required.

The MCP verifier uses the CLI's pinned SDK 1.29.0 at the exact configured MCP
resource and calls `get_delegated_identity`; it never falls back to REST or an
API key. It admits a bounded JSON-response cohort, joins clients and native
response work, rejects sessions/SSE/foreign resources/duplicate members, and
checks authoritative identity expiry after cleanup. HTTPS production factories
and explicitly mapped owned HTTP fixtures remain distinct.

Shared invocation consumes the actual family engine rather than reclassifying
a delegated bearer as a project key. Every action uses a freshly admitted exact
resource under the same family lease and pinned user/org/project/grant/family/
resource/scope binding. The actual BotaClient and existing resource commands
can consume this separate private scope; the existing hosted bridge can use it
through an explicitly supplied transport and request-auth function. API-key
commands preserve canonical equivalent URL overrides. Delegated scopes refuse
compatibility profile readers, explicit key/URL overrides, writes and unsupported
reads before egress. This cohort permits bounded ordinary read IDs and query
parameters, not every existing backend path. Ordinary responses are capped at
1 MiB and fail closed without truncation; the identity transport cap is 16 KiB.
The backend read-wire fixture separately admits a trusted 64 MiB cap. Large
transcript/read compatibility and the deployed cap must be aligned deliberately
before activation; this cohort does not establish unrestricted REST parity.

Action settlement retires descendants and cancels/joins all started REST and
MCP transport work before the actual lease releases. Pending REST work and
uncertain native body cancellation/release prevent success even when an SDK
background error is swallowed. The network child is separate from the engine's
parent context, so ordinary cleanup does not falsely cancel a completed action.
Expiry is checked after transport drain and again after the actual lease release.

| Requirement | Evidence | Current conformance |
| --- | --- | --- |
| Retain cleanup proof before URL/callback publication | Genuine recoverable producer; exact/negative/unknown acknowledgements, held cancellation and actual owned-listener close assertions | Source ordering matched through a disclosed trusted retention port; native persistence remains unqualified. |
| Retain first refresh before trusting identity | Exact acknowledgement/mismatch/privacy tests, held custody and identity failures, retired custody child while verifier waits | Source ordering matched; no native journal/adoption coordinator is activated. |
| Pre-callback protective cleanup over existing HTTP | Strict original proof binding, exact seven-field POST, matching/null receipt cases and uncertainty tests | Client and backend source components qualify separately; controlled combined protocol has its own receipt. |
| Separate exact REST/MCP audiences and current admission | Actual family engines, ordinary REST client/commands, SDK MCP verifier/bridge and wrong-scope/resource negatives | Private shared source cohort only; no default issuer, installed provider or deployed resource is enabled. |
| Join cleanup before releasing authority | Held background work, cancellation rejection, unawaited REST, retired descendants and lease-release expiry regressions | Matched under cooperative owned ports; arbitrary uncooperative ports have no universal join guarantee. |
| Preserve API-key compatibility | Complete CLI suite, canonical URL override regression and package candidate checks | Exact final results are recorded below; legacy flows are not converted into delegated sessions. |

The first complete CLI run retained 719 total / 715 pass / one failure / three
platform skips. Its negative-retention test reconnected a released numeric
ephemeral port and could not identify the server owner. The specific failure's
second owner was not recorded. The replacement observes the actual owned Node
Server's close event, stopped state, null address and zero connections, and
proves that a live owned listener fails that assertion. It uses neither a sleep
nor a retry and changes no production close path.

Independent review also found and fixed the API-key command canonicalization
regression, unjoined started REST work, an overlong initial-custody child lifetime,
missing post-drain expiry, swallowed MCP cleanup failures and missing expiry
after actual lease release. New regressions cover each corrected behavior.

Native delegated custody and cross-process/crash coordination, canonical-host
acceptance, configured production issuer/client/mounts, actual browser/SSO/MFA,
live TLS/ingress, installed CLI/MCP and independent hosted-client OAuth remain
separate gates. These source increments do not make Platform login complete.

Final full qualification passes on Node 24.19.0 and 22.23.2: **722 total,
719 pass, three existing platform skips, zero failures** on each runtime,
with strict types on both. The packed six-file candidate installs into a
temporary consumer with lifecycle scripts disabled and passes package checks;
the license gate checks 182 packages. All 5,133 declared source, test, dependency,
control and runtime inputs remain byte-identical before/after qualification.
Receipt `platform-login-cli-final-v3-receipt.json` SHA-256:
`37204c0b9617feffd12cd5c6392f1f1cea7e5a81d58470279eb75f3a830ede3f`.

The final run uses four file workers and unchanged per-test/request deadlines.
An earlier v2 Node24 run passed, while Node22's unconstrained 40-file runner on
this 16-processor host timed out in two tests that each launch five CLI/tsx
processes, and subsequently hit the outer 240-second ceiling. That run remains
failed; its exact cause is unproved. No Node22 descendants remained at the
subsequent process inventory. Bounded concurrency is consistent with the
observed startup load and does not relax the actual 30-second request deadline.
The successful final run independently establishes its stated results, not
retroactive success for that failed attempt. No production change was made for
the v2 timeout.

The focused producer cohort independently passes 45 checks on each runtime
(29 existing and 16 recovery); receipt SHA-256
`1fd2e9488b240ec7bce19b53ec892fe5b6562a76460fc93d7b2e7e8d3fc4b2de`.
The full final suite additionally covers the 17 MCP-identity, nine initial-
custody, eight enrollment-revocation and 20 shared-invocation cases against the
final source graph. The earlier MCP component receipt is
`5b68d5db55f5442bababb4b3b0623ff247cb4309fdacebd1ae35d11cb06179da`;
its original imported graph is historical, while the full final receipt binds
the combined current graph.

The controlled cross-repository test found a genuine backend enrollment HTTP
wrapper that still admitted only the legacy consent DTO and rejected the new
optional authorization-request correlation ID. This CLI qualification does not
resolve or establish that server composition; its narrow server correction and
fresh actual HTTP/PostgreSQL protocol qualification have their own evidence.


## October 22 native delegated format primitives

Design 6.2 now defines one new delegated-only location:
OS `FOLDERID_Profile` with an explicit current process token plus the fixed
`BotaDeveloperToolchainDelegated` leaf. This is a new format's canonical root,
not a runtime fallback or migration from LocalAppData. Existing API-key roots,
ancestor checks and permissions remain unchanged. AppData's applicable Codex
sandbox capability with full control still causes the expected API-key refusal.

The closed delegated Credential Manager API derives only exact kind/local UUID/
generation targets and markers. It shares the existing fixed verified Windows
bindings and create-only/no-enumeration implementation. Reads/deletes reject
malformed delegated payloads or foreign markers without adopting/removing the
entry; uncertain mutations suspend use. A separate fixed SQLite guard requires
`delegated-v1.sqlite3`, its journal and application ID `0x42544431`, with canonical
hashed ticket leases. API-key guard behavior remains unchanged. No arbitrary
root, target, DLL, filename or schema policy is exposed by production factories.

The four focused suites pass **154 of 155 tests on Node 24.19.0 and 22.23.2**, with
one expected non-Windows skip on this Windows host. The new root guard rejects
proxy/getter contexts and reads genuine cancellation through the native signal
accessor. Its capability/budget remains unchanged across OS lookup. Review also
checked malformed payload preservation, closed namespace separation, GUID byte
layout, exact headers and conservative unknown/super-journal admission.

Genuine native leaf admission passes on both pinned runtimes: complete ancestor
checks, exact final path/local NTFS, protected three-ACE leaf DACL, and joined
handle close. The first lookup found the leaf absent; only that new private leaf
was created. AppData SDDL is identical before/after, and the second runtime also
preserves the existing leaf SDDL. These runs read/write zero credentials and
open zero SQLite snapshots. Earlier read-only lookup alone did not prove this
admission. This checkpoint establishes canonical leaf trust, not durable native
attempt/family storage, restart recovery, installed commands or live login.

| Requirement | Evidence | Conformance |
| --- | --- | --- |
| Preserve host sandbox permissions | Genuine before/after AppData DACL comparison, unchanged trust algorithm | Matched within this Windows cohort |
| New canonical location without fallback | Closed Profile GUID/current token/fixed leaf; genuine two-pin lease open/close | Leaf trust matched; no credential persistence claim |
| Separate closed delegated formats | Marker/payload/collision and SQLite header/inventory preservation regressions | Source primitives matched; native coordinator qualification pending |
| Complete Platform login | Live dev authorization/token/discovery return 404 at deployed source 069e4919 | Unverified; configuration/ingress and server mounts remain gates |


The first broad development run retains 736 total / 732 pass / three expected
skips / one cancellation: hosted discovery exceeded its unchanged 15-second
case deadline while other source work ran. No assertion failed. Its isolated
12-case file then passes, including the real 30-second total-deadline check.
This does not retroactively pass the cancelled broad run. The foundation is
qualified by the focused primitive suites and strict module types; final combined
CLI/native/provider source, package and broader qualification remain separate.
