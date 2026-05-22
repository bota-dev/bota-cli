# Bota CLI

Official CLI for the [Bota](https://bota.dev) developer platform. Manage end users, devices, recordings, and webhooks from your terminal — and expose everything as an MCP server for AI assistants.

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
bota devices inspect <id>
```

### Recordings

```bash
bota recordings list
bota recordings list --end-user-id eu_abc123
bota recordings get <id>
```

### Webhooks

```bash
bota webhooks list
bota webhooks get <id>
```

### Webhook forwarding

```bash
# Forward live events to a local server
bota listen --forward-to http://localhost:3000/webhook
```

### Trigger test events

```bash
bota trigger recording.uploaded
bota trigger transcription.completed
```

### MCP server

Expose all commands as MCP tools for AI assistants:

```bash
bota mcp

# Add to Claude Code
claude mcp add bota -- bota mcp
```

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

## Configuration

Credentials are stored in `~/.bota/config.json`. You can also use environment variables:

```bash
export BOTA_API_KEY=sk_live_...
export BOTA_API_URL=https://api.bota.dev
```

## Documentation

Full documentation at [docs.bota.dev/cli](https://docs.bota.dev/cli).
