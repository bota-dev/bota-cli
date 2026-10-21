# Inactive delegated login attempt

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
