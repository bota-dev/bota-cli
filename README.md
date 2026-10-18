# Bota CLI

Official CLI for the [Bota](https://bota.dev) developer platform. Manage supported end-user, device, and recording operations from your terminal, or use the existing local MCP tools. Webhook management remains in Bota Platform.

## Installation

```bash
npm install -g @bota.dev/cli
```

## Authentication

```bash
# Browser login — opens the Bota dashboard to authorize
bota auth login

# Headless / CI — pass your key directly
bota auth login sk_live_...

# Confirm the saved key is valid
bota auth status

# Remove saved credentials
bota auth logout
```

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
bota recordings get <id>
bota recordings transcribe <id> --provider deepgram
bota recordings summarize <id> --template general_notes
bota recordings summarize <id> --prompt "Summarize the agreed next steps."
```

`--end-user` and `--end-user-id` both filter recordings. End-user, device, and recording lists accept `--limit` and `--cursor`. Tables report the next cursor on stderr; `--json` preserves the API page, including `has_more` and `next_cursor`.

Summaries require exactly one of `--template` and `--prompt`. The four built-in aliases (`general_notes`, `sales_call`, `clinical_soap`, `legal_memo`) map to their `tmpl_` IDs; an exact template ID also works. Prompts must contain 10–10000 characters. A requested transcription/summary reports its actual job state; it does not mean processing has completed.

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

Start the existing local MCP tools for AI assistants:

```bash
bota mcp

# Add to Claude Code
claude mcp add bota -- bota mcp
```

The local server has curated tools for end-user/device/recording reads, transcription and summary requests, and explicit webhook tests. It does not expose every CLI command. `list_webhooks` remains registered for compatibility but returns the Platform-only error locally. Device and recording list tools now accept an optional cursor.

This repair retains the 0.1 local tool output shapes and transcription defaults. It does not replace the server with hosted forwarding: external-ID `get_end_user` still returns a page envelope, `get_recording` stays flattened with optional nested transcription/summary, and omitted transcription language remains omitted. A future versioned migration is required to change those contracts.

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

For the resource commands and explicit webhook tests above, JSON failures are written to stderr as an `error` object; backend status, code, parameter, and request ID are retained when supplied. Success payloads stay on stdout. HTTP requests have a deadline and reject redirects rather than forwarding credentials to another origin.

## Configuration

Credentials are stored in `~/.bota/config.json`. You can also use environment variables:

```bash
export BOTA_API_KEY=sk_live_...
export BOTA_API_URL=https://api.bota.dev
```

## Documentation

Full documentation at [docs.bota.dev/cli](https://docs.bota.dev/cli).

## Development checks

```bash
npm ci
npm run type-check
npm test
npm run build
```

Contract regressions use loopback fixtures and synthetic credentials. They exercise real command parsing/exit codes, backend request fields, page cursors, MCP JSON/SSE errors and local-tool compatibility. Manual-listener subprocess tests verify HMAC signatures over the original body and `X-Bota-Signature`, `X-Bota-Timestamp`, and `X-Bota-Event-Id` forwarding, credential-free startup, fixed logs, rejection paths, and joined SIGINT/SIGTERM handlers. On Windows, a test-only IPC relay delivers those signals inside the subprocess. No test contacts Bota Platform or creates a public tunnel. These checks do not call a live project, establish webhook-management availability, publish a package, or qualify a physical device.
