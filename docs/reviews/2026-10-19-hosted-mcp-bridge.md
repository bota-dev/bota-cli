# Hosted MCP bridge source review

Date: October 19, 2026. Scope: an opt-in source preview in `bota-cli`.
Authority: the owner-approved [hosted bridge plan](../../../internal-docs/plans/2026-10-19-hosted-mcp-bridge.md)
and [Developer Toolchain Design section 5.2](../../../internal-docs/Developer%20Toolchain%20Design.md#52-opt-in-canonical-hosted-cohort).
This review distinguishes local protocol evidence from hosted deployment and
package publication.

## Requirement review

| Requirement | Implementation and evidence | Status |
| --- | --- | --- |
| Explicit cohort; unchanged legacy default | `src/commands/mcp.ts` selects `hosted` explicitly, defaults to `legacy`, and rejects unknown modes before credential access. Existing 16 tools and their compatibility fixtures remain intact. | Matched |
| Public SDK stdio handlers; no business-tool duplication | `src/commands/hosted-mcp.ts` uses low-level `Server`, `Client`, and `StreamableHTTPClientTransport`. Only `tools: {}` is advertised. Startup waits for downstream requests without contacting upstream. | Matched |
| Canonical discovery and results | Real stdio plus official SDK loopback fixtures preserve paginated tool schemas, descriptions, effect annotations, `_meta`, all result content blocks, `structuredContent`, and `isError`. | Matched |
| Fresh current authority | A separate client initializes for every list/call. Synthetic secret, restricted-read/write, and six-tool end-user inventories differ. A simulated revocation between list and call is enforced; a subsequent list refresh changes inventory. | Matched in controlled fixtures; deployed principal matrix unverified |
| One bounded invocation; no replay | One total 30-second abort scope covers initialize, initialized notification, execution, and response consumption. A real-clock lost-SSE fixture observes exactly one tool call, one initialize, no resumption, and an unknown-outcome deadline error. Accelerated fixtures separately test stalled initialized notification and a combined initialize/execution budget. | Matched |
| Cancellation and shutdown | Separate controllers use original string/number request IDs, including numeric zero. Duplicate active IDs are rejected before upstream work. Cancellation, EOF, SIGINT, and SIGTERM fixtures observe HTTP closure and normal process exit. Pending handler promises join before shutdown finishes. | Matched at observable local boundaries |
| Safe transport failures | Invalid modes/URLs, HTTP authentication errors, cross-origin redirects, malformed protocol content, and cleanup errors use fixed diagnostics. Canary response bodies, URLs, credentials, callbacks, and raw cleanup errors are excluded. Business tool results are forwarded under their hosted output contract. | Matched |
| No unsupported protocol claims | The bridge exposes listing and final call results only. Tests reject task-augmented calls before upstream initialization and do not forward elicitation callbacks. README excludes progress, list changes, resources, prompts, tasks, sampling, and elicitation. | Matched |
| Credential compatibility | Existing credential selection is captured once. No OAuth provider, browser login, refresh, credential persistence change, or callback authority is introduced. Restart after selecting different credentials or API context. | Matched |
| Publication and deployment | No external project/provider/device request or package publication is part of these fixtures. Source delivery and hosted CI are recorded by the owning integration review. | Unverified here |

## Verification

The dependency lock and package identity are unchanged. The installed official
MCP SDK is 1.29.0. Verification uses Node 24.19.0 and Node 22.23.2, synthetic
credentials, isolated configuration homes, real CLI subprocess stdio, and
loopback HTTP. Final local checks:

| Check | Result |
| --- | --- |
| `node --import tsx --test tests/*.test.mjs`, Node 24.19.0 | 64/64 pass; 49.9 seconds |
| Same full suite, Node 22.23.2 | 64/64 pass; 51.6 seconds |
| `npm run type-check` | Pass |
| `npm run build` | Pass; existing ESM/ES2022 package target |
| `git diff --check` | Pass |

The 64 cases comprise all 50 existing cases and 14 new bridge regressions.
The owning delivery receipt records final source identity and hosted CI.

`tests/hosted-mcp.test.mjs` covers discovery, schemas/results, invocation errors,
privacy, redirects, unsupported tasks/callbacks, request-ID cancellation,
shutdown, the real 30-second clock, and cleanup failure injection.
`tests/hosted-mcp-lifecycle.test.mjs` adds two accelerated deadline regressions.
Its test-only preload shortens matching timers; production has no environment
switch or alternate transport implementation. Existing legacy/integration
privacy regressions run unchanged with the new cases.

## Boundaries and retained lessons

- Cancellation or closing local HTTP cannot prove that a stateless hosted
  mutation stopped or rolled back. Read the owning resource before retrying an
  unknown outcome; the bridge never repeats it automatically.
- SDK `close()` aborts transport activity without exposing a separate promise
  that joins its internal stream reader. The bridge joins its own request
  promises. Fixtures establish observed remote socket closure and subprocess
  shutdown, not remote business cancellation.
- There is no cached inventory or reliable list-change notification. Clients
  follow continuation cursors and explicitly refresh discovery or restart.
  Registry release identity, default-mode migration, shared OAuth/profiles,
  broad protocol forwarding, and API SDK publication remain separate work.
- The SDK's default cancellation handling ignores numeric request ID zero.
  An explicit public notification handler preserves zero and distinguishes
  it from string `"0"`; map removal checks controller ownership.
- The total signal must also reach the SDK's initialized-notification fetch
  and response-body reader. Request timeout options alone cover too little.
  The custom fetch composes signals and refuses redirects for every method.
- On Windows, IPC fixture teardown can omit ChildProcess `close` after an
  exit and both pipe closures. Fixtures join those observable events directly,
  retaining the actual CLI signal handlers through a test-only IPC relay.

The parent integration review owns cross-repository docs, final source delivery,
and remaining release/deployment evidence. This preview does not complete the
broader M3 convergence or change established legacy contracts.
