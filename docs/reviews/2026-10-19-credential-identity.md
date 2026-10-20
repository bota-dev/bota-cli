# Credential identity status review

Date: October 19, 2026. Scope: CLI status and its private client only.
Authority: [credential identity plan](../../../internal-docs/plans/2026-10-19-credential-identity.md)
and [Developer Toolchain Design section 6.3](../../../internal-docs/Developer%20Toolchain%20Design.md#63-api-keys-and-shared-profiles).
Backend, hosted MCP, public documentation, and final source delivery are owned
by the integration review.

| Requirement | Implementation and verification | Status |
| --- | --- | --- |
| Identity rather than a business-read proxy | `BotaClient.getProjectIdentity()` calls only `GET /v1/auth/identity`. Real CLI fixtures authenticate device-only, integration-only, and empty restricted grants without `/end-users` fallback. | Matched in loopback fixtures |
| Frozen safe identity | The private typed model projects only the seven agreed fields. It checks key-type/scope-mode/null-array consistency, preserves opaque ID strings and exact scope order/duplicates, and ignores unexpected metadata. Secret identity and its test flag come from the response rather than the supplied key's text. | Matched |
| Safe human and JSON output | Success goes to stdout. Status-local JSON quoting escapes C0, DEL/C1, Unicode line separators, and bidi controls; fixtures include ESC and U+009B CSI, and JSON parsing recovers exact stored grants. Key material, hints, and configured URLs are absent from output. | Matched |
| Explicit failure categories | Fixed messages distinguish missing credentials, HTTP 401/403/423/429/404/5xx, malformed replies, and connectivity/URL failures. Failures go to stderr and exit nonzero; backend bodies, codes, headers, parameters, and error text are not echoed. | Matched |
| Accurate diagnostic status | Non-JSON successful responses retain actual HTTP status. Schema failures omit status instead of inventing 200 after a 204 or malformed 201 response. | Matched by focused fixtures |
| Existing compatibility | Login/logout and `config.ts` are unchanged. A saved key still precedes the environment key; fixtures use isolated homes and prove the saved bytes are not rewritten. All existing legacy MCP, hosted bridge, integration, and webhook tests remain in the full suite. | Matched within CLI scope |
| Broader M1 authentication | No human identity, OAuth delegation, profiles, secure store, API-origin binding, key issuance/rotation, or expiry is inferred or implemented. Current server key flag is not test isolation proof. | Not implemented by this increment |
| Live/backend/package acceptance | Fixtures use synthetic credentials and loopback HTTP. They do not establish deployed authentication, publish a CLI package, or qualify a real project. | Unverified here |

`tests/auth-status.test.mjs` adds 13 tests with actual CLI subprocesses, isolated
configuration, and controlled HTTP responses. It includes both output modes,
configuration precedence, projection privacy, exact arbitrary scopes, control
escaping, malformed JSON/shape/status variants, and fixed transport errors.
No fixture reads the user's credential configuration or contacts a live API.

Final checks on the frozen source:

| Check | Result |
| --- | --- |
| Full suite, Node 24.19.0 | 77/77 pass; 48.1 seconds |
| Full suite, Node 22.23.2 | 77/77 pass; 71.7 seconds |
| Final scope-rendering and malformed-response focused cases | 2/2 pass |
| `npm run type-check`, `npm run build`, `git diff --check` | Pass |

These final runtime suites ran sequentially. An earlier concurrent dual-runtime
run under shared host load hit one bounded test cancellation; the final runs
have no failures or cancellations. All 64 previous cases are retained beside
the 13 new status cases.

The generic private client's malformed-JSON success message remains unchanged;
an `Error` subclass lets the status adapter classify it without parsing or
printing raw transport diagnostics. Other command JSON rendering is unchanged.

Final local suite/runtime results, source identity, pushed CI, backend admission,
and docs delivery are recorded separately by the owning integration receipt.
