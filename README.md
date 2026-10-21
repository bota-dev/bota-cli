# Bota CLI

Official CLI for the [Bota](https://bota.dev) developer platform. Manage supported end-user, device, and recording operations from your terminal, or use the existing local MCP tools. Webhook management remains in Bota Platform.

## Installation

The current public npm `latest` is **0.1.0**, published May 25, 2026. It does not
contain the source-preview workflows described below. The prepared candidate
is **0.2.0-beta.0**, requires Node **22.23.2 or newer**, and is **not published**.
The CLI source is [MIT licensed](LICENSE), approved by the owner on October 21,
2026. Registry publication still requires exact-source release approval and
the verified publishing workflow; packaging and synthetic tests do not publish it.

To install the historical public version:

```bash
npm install -g @bota.dev/cli@0.1.0
```

Candidate packaging and release requirements are recorded in the
[preview release review](https://github.com/bota-dev/bota-cli/blob/main/docs/reviews/2026-10-19-cli-preview-release.md).
Any future preview publication uses `beta`; it must not move `latest`.

## Authentication

```bash
# Browser login — opens the Bota dashboard to authorize
bota auth login

# Headless / CI — pass your key directly
bota auth login sk_live_...

# Resolve the selected project credential's identity
bota auth status
bota auth status --json

# Remove saved credentials
bota auth logout
```

`auth status` calls `GET /v1/auth/identity` once. It does not read end-user data or require `end_users:read`: a valid restricted key with only device or integration scopes, or no scopes, can resolve its own identity. JSON success contains `project_id`, `organization_id`, `key_id`, `key_type`, `is_test_mode`, `scope_mode`, and `scopes`. IDs are opaque database identifiers; `key_id` is not the credential. A secret key reports `scope_mode: "project_secret"` with `scopes: null`; a restricted key reports its exact stored scope array, including an empty array. The key's test flag does not establish an isolated environment or project.

Status output excludes key material, key hints, and API URLs. Status rendering escapes C0, DEL, C1, and direction/line controls in opaque identifiers and scope strings; JSON parsing preserves the exact stored values. `--json` writes success to stdout; failures use a fixed `error` object on stderr and exit nonzero. Invalid credentials (401), unsupported credential authority (403), organization quarantine (423), rate limiting (429), service failures, malformed responses, and connectivity failures are distinguished. A temporary service failure does not establish that a credential is invalid. The command never falls back to a business read or retries the check.

Without `--profile`, the existing selection order remains: a saved configuration key takes precedence over `BOTA_API_KEY`. With no saved key, inject a restricted key through `BOTA_API_KEY`; direct `auth login <key>` retains its existing secret-key format check and plaintext storage behavior. Status does not rewrite that configuration or introduce delegated OAuth. A matching backend identity endpoint is required; source delivery, backend deployment, and CLI publication remain separate.

### Secure API-key profiles in the source preview

Secure profiles currently support **Windows x64, local NTFS, and the qualified
Node 22.23.2 or 24.19.0 builds**. Unsupported or unavailable native storage fails
without a plaintext fallback. Other hosts can use injected environment profiles.
Existing ancestors of the OS-selected storage directory must also pass the
native ownership and permissions checks. The CLI refuses an untrusted ancestor
before creating its private root and never repairs existing permissions.
The CLI package remains an unpublished candidate.

```bash
# Hidden terminal input; the key never appears in the command line
bota --api-url https://api.bota.dev auth secure-profiles add work --key-prompt

# A secret manager can instead pipe one key into the same command with --key-stdin
# Explicit --from-env enrolls BOTA_API_KEY into the OS store
bota auth secure-profiles show work
bota --secure-profile work auth status --json
bota --secure-profile work devices list
bota --secure-profile work mcp --mode hosted

bota auth secure-profiles list --json

# Explicit local recovery or removal; neither revokes the project API key
bota auth secure-profiles recover work
bota auth secure-profiles remove work
```

Choose exactly one input mode. Piped input accepts one printable ASCII key of
1–2560 bytes, with an optional final LF or CRLF and a finite EOF deadline. Hidden
prompting requires interactive stdin and stderr; it restores terminal state and
joins output before returning the key. Standard-input MCP never prompts.

Windows selects one fixed per-user storage location independently of shell
HOME/USERPROFILE overrides. Key bytes live in Credential Manager; transactional
metadata contains only identity, state and exact store references. A conflicting
origin, changed stored-key identity, unavailable store or pending recovery stops
selection. No profile is silently replaced. Removal first disables selection,
then deletes only its exact owned credential and retains a removed reservation.

Every selected CLI action and every MCP discovery/call rereads the profile and
verifies current project/organization identity while holding its namespace lock
through the action and cleanup. MCP pins nonsecret profile metadata at startup;
it keeps no startup bearer. A removed/pending profile therefore stops subsequent
requests in an already running MCP server. Concurrent requests can fail busy;
the CLI never retries a submitted operation automatically.

An explicitly present `BOTA_API_KEY` overrides a ready secure profile's key for
that invocation only, and must match its project and organization. Invalid,
empty or rejected overrides never fall back to the stored key. Both `--api-url`
and `BOTA_API_URL` may only repeat the enrolled origin. HTTP requires explicit
`--allow-http-loopback` enrollment for literal loopback development.

`--secure-profile` is separate from environment-v1 `--profile`; combining them
or using either selector for profile management/legacy login/logout refuses.
Existing environment profiles and legacy configuration are not automatically
read, migrated, rewritten or deleted by secure selection. Secure errors keep
fixed private diagnostics and explicit recovery/unknown-outcome flags. Legacy
MCP tool errors in secure mode conservatively hide callback/validation text;
successful tool shapes remain compatible. Platform browser login is still a
separate delegated-auth workflow and is not enabled by API-key enrollment.

To copy a selected environment-v1 profile explicitly, keep its matching key in
`BOTA_API_KEY` and repeat the trusted origin:

```bash
bota --api-url https://api.bota.dev auth secure-profiles migrate work --from-env
```

Migration verifies current identity against the captured source project and
organization before native credential access or durable enrollment. It leaves
the source profile and selected authentication mode unchanged; select the new
copy explicitly with `--secure-profile`. Existing native names, including removed
reservations, refuse. A later source edit cannot retarget that captured copy.
`auth secure-profiles list` validates the complete bounded metadata inventory
without reading credentials or contacting the API. Pending and removed states
remain visible. Listing does not initialize an absent database; normal recovery
of an admitted SQLite journal can still write its physical metadata files.

### Environment-backed profiles in the source preview

Explicit profiles bind an injected key to an API origin, project and organization.
Supply `BOTA_API_KEY` through your shell or CI secret manager, then enroll the
trusted origin explicitly:

```bash
bota --api-url https://api.bota.dev auth profiles add work --from-env
bota auth profiles list --json
bota --profile work auth status --json
bota --profile work recordings list
bota --profile work mcp --mode hosted
bota auth profiles remove work
```

Profiles store metadata only in `~/.bota/profiles/`; they never save the key,
key hints, scopes or a credential hash. Creation verifies the current identity
and refuses an existing name. Each selected cloud command verifies the injected
key against the saved project and organization before proceeding. Both local
MCP modes use that same verified startup context. `BOTA_API_URL` or `--api-url`
may only repeat the saved origin; a conflicting origin refuses before key
resolution or a request. HTTP is restricted to literal loopback addresses and
requires `--allow-http-loopback` during enrollment for development.

With `--profile`, `BOTA_API_KEY` is required. Missing, empty, invalid or rejected
keys never fall back to legacy saved credentials, browser login or another
profile. The legacy login/logout commands refuse `--profile`; list/remove need
no key or network access, and removal does not revoke an API key. A running MCP
process keeps its verified startup key and profile: restart it to use changed
environment or metadata. Removing metadata does not stop that process or
revoke backend access. Backend admission still applies to every operation.

This first profile cohort provides no native credential storage, automatic
legacy migration, default profile selection or Platform OAuth. Existing
no-profile commands retain their compatibility behavior. Local help and the
manual webhook listener remain independent of credentials.

## Commands

### End users

```bash
bota end-users list
bota end-users get <id>
bota end-users create --name "Jane Smith" --email jane@example.com

# MCP tokens
bota end-users token <id>         # Issue a user token (shown once)
bota end-users token-revoke <id>  # Revoke the token
```

### Devices

```bash
bota devices list
bota devices get <id>
bota devices inspect <id>       # Alias for get
bota devices stats
```

Device tables use the API's `battery_percent` and `last_heartbeat_at` fields.

### Recordings

```bash
bota recordings list
bota recordings list --end-user-id eu_abc123
bota recordings list --cursor <next_cursor>
bota recordings list --start-date 2026-10-01T00:00:00Z --end-date 2026-10-18T00:00:00Z
bota recordings get <id>
bota recordings transcribe <id> --provider deepgram
bota recordings summarize <id> --template general_notes
bota recordings summarize <id> --prompt "Summarize the agreed next steps."
```

`--end-user` and `--end-user-id` both filter recordings. End-user, device, and recording lists accept `--limit` and `--cursor`. Tables report the next cursor on stderr; `--json` preserves the API page, including `has_more` and `next_cursor`.

Recording lists also expose `--device`, `--status`, `--start-date`, and `--end-date`. Date bounds filter `created_at`, with an inclusive start and exclusive end, and are passed to the public API as `start_date` and `end_date`. Dashboard-only search and transcription/summary status filters are not public API filters.

`recordings get` reads transcription and summary metadata after the recording. A successful empty list means that result is absent. A failed related read returns a nonzero exit and diagnostics instead of presenting partial metadata as a complete success; the credential needs the corresponding read scopes.

Summaries require exactly one of `--template` and `--prompt`. The four built-in aliases (`general_notes`, `sales_call`, `clinical_soap`, `legal_memo`) map to their `tmpl_` IDs; an exact template ID also works. Prompts must contain 10–10000 characters. A requested transcription/summary reports its actual job state; it does not mean processing has completed.

### Provider integrations

```bash
bota integrations list
bota integrations get asr deepgram

# provider-key is an existing protected file containing one provider key line
bota integrations set asr deepgram --key-stdin < provider-key
bota integrations rotate <integration-uuid> --key-stdin < provider-key

bota integrations enable <integration-uuid>
bota integrations disable <integration-uuid>
bota integrations delete <integration-uuid>
bota integrations delete-provider asr deepgram
bota integrations test asr deepgram --json
```

You can also pipe a key from your secret manager into `set` or `rotate`. Key input is stdin only: one nonempty UTF-8 line, optionally ending in LF/CRLF, no whitespace/control characters, at most 16 KiB, with EOF within 30 seconds. Interactive entry and key arguments are rejected. Provider keys are not saved in the CLI configuration or printed in tables, JSON, or error messages.

`set` creates or replaces the credential and enables the integration. `rotate` replaces the credential by UUID while retaining the existing enabled state. Supported provider pairs are ASR `whisper`, `deepgram`, `assemblyai`, `elevenlabs`, and LLM `gemini`, `openai`, `claude`. Read operations require `integrations:read`; changes and credential tests require `integrations:write` for restricted keys. End-user tokens do not gain integration-management authority.

Outputs contain validated metadata and `has_error`; raw `last_error`, credential hints, encrypted material, and provider errors are excluded. Integration errors use fixed safe messages and available HTTP status/code. A credential test uses only the stored key and may consume provider capacity. It checks basic provider acceptance, without qualifying transcription, summarization, or regulated-route approval. A failed check prints a safe result with `success: false` and exits nonzero. Tests and writes are attempted once, without automatic replay.

These commands use typed methods in the private CLI client. No standalone Bota API SDK is released by this change. Source changes, matching backend deployment, and CLI package publication remain separate.

### Webhooks

Create and inspect webhook endpoints in Bota Platform. The public API does not mount webhook registration, list, detail, or deletion routes. `bota webhooks list` and `bota webhooks get <id>` fail locally with that explanation instead of making a request to an unavailable route.

### Webhook forwarding

Run your webhook receiver locally, then start the manual listener:

```bash
bota listen --manual --forward-to http://127.0.0.1:3000/webhooks --port 4242

# Optional: record that you already have a public tunnel URL
bota listen --manual --forward-to http://127.0.0.1:3000/webhooks --tunnel-url https://your-existing-tunnel.example/webhooks
```

Point an existing tunnel at `http://127.0.0.1:4242`, then configure its public webhook destination and subscribed events in Bota Platform. Bring your own tunnel; `--tunnel-url` is informational. Manual mode needs no API key and creates no tunnel or webhook registration. `--event` is rejected because subscriptions are configured in Platform. Without `--manual`, `listen` fails before opening a port or making network requests.

The listener binds only to `127.0.0.1`. The destination must use HTTP(S) on `localhost`, `127.0.0.0/8`, or `[::1]`, with no embedded credentials. Only POST requests are accepted, with a 1 MiB body limit. Forwarding preserves the original bytes and the three Bota verification headers, so the receiver should verify the signature normally. It excludes incoming Authorization headers, refuses redirects, and makes one forwarding attempt with a 10-second deadline. Receiver rejection or forwarding failure returns HTTP 502. Logs do not print payloads, verification headers, or destination URLs. Ctrl+C or SIGTERM closes the listener and cancels in-flight forwarding.

### Trigger test events

```bash
bota trigger recording.uploaded --webhook wh_abc123
bota trigger transcription.completed --webhook wh_abc123 --json
```

Use an existing webhook ID from Bota Platform. The command calls the hosted MCP test tool under the supplied credential's permissions. Automatic webhook selection is unavailable. HTTP, JSON-RPC, tool, and delivery failures return a nonzero exit status; the command does not automatically repeat a failed test call.

### MCP server

Start the existing local MCP tools for AI assistants (the default `legacy` mode):

```bash
bota mcp
bota mcp --mode legacy

# Add to Claude Code
claude mcp add bota -- bota mcp
```

The local server has curated tools for end-user/device/recording reads, transcription and summary requests, and explicit webhook tests. It does not expose every CLI command. `list_webhooks` remains registered for compatibility but returns the Platform-only error locally. Device and recording list tools accept an optional cursor. Local `list_recordings` also accepts `start_date` and `end_date` with the creation-date semantics above.

Legacy mode retains all 16 local tools, their 0.1 output shapes, and transcription defaults: external-ID `get_end_user` still returns a page envelope, `get_recording` stays flattened with optional nested transcription/summary, and omitted transcription language remains omitted. A future versioned migration is required to change those contracts.

Failed related reads in local `get_recording` return `isError: true`; successful empty lists retain the existing flattened success shape. Local errors retain their first text message and add a second JSON text block when structured HTTP diagnostics are available.

Five new local tools (`list_integrations`, `get_integration`, `test_integration`, `update_integration`, `delete_integration`) forward to the corresponding hosted tools. `update_integration` accepts only an ID and `is_enabled`; no integration tool accepts a provider key. Local schemas reject extra fields and return fixed validation errors. Safe hosted credential-test results retain their `success` value and code, including failed basic checks. Hosted authorization still controls every operation; local tool visibility does not imply that the current credential can invoke it. Existing local tools retain their compatibility behavior.

Safe integration rate-limit errors retain `rate_limit_exceeded` and HTTP 429 with a fixed message. The local bridge makes no automatic retry and does not echo provider error text.

#### Hosted discovery preview

Select the explicit hosted mode to use the authenticated backend's current tool inventory and contracts:

```bash
bota mcp --mode hosted

# Add a separate connection to Claude Code
claude mcp add bota-hosted -- bota mcp --mode hosted
```

Run `bota auth login` separately first, supply `BOTA_API_KEY`, or explicitly select a profile. Startup is noninteractive. Without `--secure-profile`, hosted mode uses the selected API base URL's `/mcp` endpoint and captures the credential and API URL once; restart the process after changing credentials or environment. Secure mode uses the per-request behavior above. Unknown modes and invalid API URLs fail locally. Package publication and availability of a matching hosted deployment remain separate from this source preview.

Without `--profile`, bridge startup makes no network request. An explicit
environment profile first verifies developer identity before connecting stdio;
it supports project keys rather than end-user tokens.

`tools/list` forwards the hosted principal's inventory, tool schemas, descriptions, and effect annotations. Project API keys, restricted-key scopes, and end-user tokens can receive different inventories. Each requested page is fetched afresh; clients follow `nextCursor` to request the next page. There is no inventory cache or list-change notification. Refresh the tool list or restart the bridge to see inventory changes. Every invocation independently passes current hosted authorization, even if a previously listed tool is no longer allowed.

`tools/call` preserves the complete final hosted result, including every content block, `structuredContent`, `_meta`, and `isError`. Hosted mode has different contracts from legacy mode and never falls back to legacy tools. This preview supports tool listing and final call results only. Progress and list-change notifications, resources, prompts, tasks, sampling, and elicitation are outside its supported capabilities. It does not forward interactive callbacks or open browser login prompts. Hosted business results retain their owning output and secret-handling contracts; the bridge does not sanitize arbitrary tool content.

Each list or call uses a fresh official MCP client connection with one total 30-second deadline for initialization and execution. Redirects, reconnect/resumption, and automatic retries are disabled; an invocation sends at most one upstream tool call. Transport failures return fixed diagnostics without reflecting HTTP bodies, URLs, or credentials. Cancellation, stdin closure, Ctrl+C, and SIGTERM abort active HTTP requests and join request cleanup. The SDK closes and aborts its transport without exposing a separate reader-join promise. Local cancellation or a lost response cannot prove a remote operation stopped or rolled back. Its outcome may be unknown: inspect the owning resource before deciding whether to retry.

## Global flags

| Flag | Description |
| --- | --- |
| `--api-url <url>` | Override the API base URL |
| `--dashboard-url <url>` | Override the portal URL (for browser login) |
| `--json` | Output raw JSON |

```bash
# Point at a different environment
bota --api-url https://api.dev.bota.dev end-users list

# Raw JSON output for scripting
bota end-users list --json | jq '.data[].id'
```

For the resource commands and explicit webhook tests above, JSON failures are written to stderr as an `error` object; backend status, code, parameter, and request ID are retained when supplied. REST errors use `X-Request-Id` when the body omits its ID and retain `Retry-After` as `retry_after`. An optional `rate_limit` object contains the supplied `RateLimit-Limit/Remaining/Reset/Policy` and `X-RateLimit-Limit/Remaining/Reset/Tier` headers under their lowercase names. Values stay as supplied; the two reset header families can use different units. Human stderr includes the same available diagnostics. These values do not trigger automatic retries. Success payloads stay on stdout. HTTP requests have a deadline and reject redirects rather than forwarding credentials to another origin.

## Configuration

Credentials are stored in `~/.bota/config.json`. You can also use environment variables:

```bash
export BOTA_API_KEY=sk_live_...
export BOTA_API_URL=https://api.bota.dev
```

## Documentation

Full documentation at [docs.bota.dev/cli](https://docs.bota.dev/cli).

## Development checks

The shared loopback helpers and signal-relay fixture are versioned with the
regressions so these checks run from a fresh checkout.

```bash
npm ci
npm run type-check
npm test
npm run build
npm run license-check
npm run verify:package
```

`verify:package` creates a tarball and receipt under `.release/`, resolves an
isolated consumer lock, and installs it with `npm ci --ignore-scripts`. It runs
the installed command's version/help, hosted-mode help, legacy identity read,
profile enrollment/status and credential-free metadata list/removal against
synthetic loopback fixtures. It uses temporary homes and npm configuration with
inherited credentials removed. The root dependency lock remains unchanged.
The package includes the executable, manifest, README, MIT license, build/source
metadata, and third-party notices; source tests, CI configuration and internal reviews
are excluded. The candidate metadata records source dirtiness honestly.
Transitive dependency ranges are not globally frozen for future consumers;
the receipt records the exact graph used by this installed-consumer check.

Packed consumers verify the manifest's MIT identifier, exact `LICENSE` bytes
and provenance digest. The publication guard still requires a
clean source commit matching `GITHUB_SHA`, a matching `v0.2.0-beta.N` tag and
package version, and exact-source repository approval variables. It publishes
the already-tested tarball with provenance. No tag, release, dispatch, registry
publication or production action is part of preparing this candidate.

Contract regressions use loopback fixtures and synthetic credentials. They exercise real command parsing/exit codes, backend request fields, page cursors, MCP JSON/SSE errors and local-tool compatibility. Hosted-preview fixtures cover principal-dependent discovery, full result/schema preservation, fresh admission, redirects, cancellation, shutdown, a real 30-second deadline, and one attempted tool invocation after a lost response. Manual-listener subprocess tests verify HMAC signatures over the original body and `X-Bota-Signature`, `X-Bota-Timestamp`, and `X-Bota-Event-Id` forwarding, credential-free startup, fixed logs, rejection paths, and joined SIGINT/SIGTERM handlers. On Windows, a test-only IPC relay delivers those signals inside the subprocess. No test contacts Bota Platform or creates a public tunnel. These checks do not call a live project, establish webhook-management availability, publish a package, or qualify a physical device.
