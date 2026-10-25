# Platform developer sessions

This is the source-preview command contract. Default production Platform login
remains **configuration off**: `getProductionDeveloperDeployment()` refuses with
`developer_configuration_unavailable` before opening native storage, a callback
listener, browser or network request. Explicit `--developer-deployment dev`
selects the fixed reviewed DEV configuration through the actual service and
protected native factory. No argument, environment variable or saved profile can
supply arbitrary deployment endpoints. The candidate CLI is unpublished;
historical public npm `0.1.0` does not provide this workflow.

The implementation separates a Platform user's delegated session from project
API keys and customer end-user tokens. Existing API-key login, environment
profiles and secure API-key profiles keep their own compatibility behavior.
The design and component evidence live in the
[delegated login review](reviews/2026-10-21-delegated-login-attempt.md).

## Enrollment and selection

The DEV selection is pinned to backend candidate
[`551927a1`](https://github.com/bota-dev/bota/blob/551927a19f751fa20a1b420aaa5a5bffa4f2128b/infra/config/developer-auth-dev.candidate.json):
issuer `https://api.dev.bota.dev`, native client `bota-cli-dev-v1`, authorization,
token and revocation paths `/oauth/authorize`, `/oauth/token` and `/oauth/revoke`,
REST audience `https://api.dev.bota.dev/v1`, and MCP audience
`https://api.dev.bota.dev/mcp`. The registered literal callback templates are
`http://127.0.0.1/oauth/callback` and `http://[::1]/oauth/callback`; the owned
listener binds an ephemeral port with S256 PKCE. Both resource audiences are
requested for the shared grant. The server sends consent to the configured
`https://platform.dev.bota.dev` Portal. DEV explicitly opts into
`negative-fence-v1` recovery.

This source selection does not prove active deployment, Portal configuration or
real account consent. The actual coordinator performs these steps:

1. Reserve a new explicit local name. Existing names and removed reservations
   refuse; enrollment never silently replaces them.
2. Generate independent state, S256 PKCE and enrollment recovery proof. Wait for
   protected proof custody acknowledgement before publishing the authorization
   URL or launching the browser.
3. Receive one code-only callback on an owned literal loopback listener. The
   callback validates the exact path, Host and state; it receives no token.
4. Submit code exchange once. Acknowledge protected custody of the first refresh
   credential before resource-aware identity verification or family adoption.
5. Verify authoritative identity, resource, grant and scopes; create the exact
   family and finish journaled local adoption. Join callback/native cleanup
   before reporting success.

These are the source-prepared DEV commands. Repeat the fixed DEV selector for
every invocation; omitting it still refuses production configuration at step zero:

```bash
bota --developer-deployment dev auth login --name dev-work --scope devices:read --scope recordings:read
bota --developer-deployment dev --developer-profile dev-work devices list
bota --developer-deployment dev --developer-profile dev-work recordings list
bota --developer-deployment dev --developer-profile dev-work auth status --json
bota --developer-deployment dev --developer-profile dev-work mcp --mode hosted
```

The available read scope names are `end_users:read`, `devices:read`,
`recordings:read`, `transcriptions:read` and `summaries:read`. Choose the minimum
needed scopes. `--identity-only` requests none; interactive login can show a
nonsecret scope picker, while noninteractive login requires an explicit choice.
Requested scopes do not prove granted operations. Consent and fresh backend
admission remain authoritative.

Omitting `--name` reserves `default`; it does not select that name for future
commands. Always pass `--developer-profile` when using a delegated session. Do
not combine it with `--profile`, `--secure-profile`, `--api-url` or
`--dashboard-url`; those options also conflict with `--developer-deployment dev`.
The DEV selector cannot be used for API-key login or unrelated commands.
API-key environment variables cannot substitute for a
selected delegated session. Endpoint authority comes only from reviewed source
configuration and must match saved metadata exactly. The selection is captured
once for the entire command lifetime, including a hosted-mode local MCP process;
it neither changes a saved default nor imports legacy credentials.

## Shared CLI and local MCP access

Local MCP is the stdio bridge to the hosted canonical MCP tools. Delegated
selection requires explicit `mcp --mode hosted`; its legacy tool inventory is
not an alternate authority path. Stdio MCP never prompts or starts enrollment.
Startup pins nonsecret profile identity. Each discovery or tool request then
opens the protected runtime and admits current MCP-resource authority again.
REST credentials are never sent to the MCP resource or vice versa.

One family lock covers current admission, refresh, business work, native network
and body cleanup, and metadata finality. Separate CLI/MCP processes must use the
same canonical family namespace. Unknown rotation suspends the whole family;
cached access cannot bypass it. Operations are not automatically replayed.

Ordinary selected CLI output is buffered until the action, family lease and
native runtime cleanup join. For asynchronous writers, each output acknowledgement
has a five-second ceiling. Buffered ordinary output also remains subject to the
original invocation cancellation, deadline and authoritative access expiry. A stalled acknowledgement refuses;
late completion cannot return command success or start another buffered chunk.
Metadata and login guidance use that ceiling and the command's cancellation;
status metadata also checks its authoritative expiry. Already queued
bytes cannot be recalled, and a nonzero exit never qualifies a preceding ready
record. Output uncertainty does not delete retained proofs or journals, revoke a
family or repeat enrollment; inspect the explicit profile before choosing recovery.

JavaScript timers cannot interrupt a synchronously blocked native write. Node
uses synchronous process pipes on Windows and synchronous regular-file output on
all platforms; those paths have no bounded-wait guarantee here. Pending native
writes keep their error observers until their callbacks and deferred errors are
observed. The CLI does not destroy global stdout/stderr or force-close their file
descriptors, and this boundary does not promise bounded process exit while native
output remains blocked. MCP protocol traffic has
its own request/transport owner and is not globally buffered. Ordinary delegated
CLI reads currently refuse responses above 1MiB; identity bodies are bounded at
16KiB. This cohort does not promise unrestricted large-transcript parity.

## Recovery, logout and retained state

```bash
bota --developer-deployment dev auth developer-profiles list --json
bota --developer-deployment dev auth developer-profiles show dev-work
bota --developer-deployment dev auth developer-profiles recover dev-work
bota --developer-deployment dev auth developer-profiles logout dev-work
# The explicitly selected equivalent:
bota --developer-deployment dev --developer-profile dev-work auth logout
```

Metadata output contains safe name, state and deployment information; it never
contains bearer credentials, recovery proofs or native store references. Native
listing is bounded by the complete 2048-record format limit. No command silently
chooses another profile when the selected one is unavailable.

`recover` resumes the exact durable state, with distinct outcomes:

| Observed state | Explicit recovery behavior |
| --- | --- |
| Empty reserved name | Retire it to an empty tombstone; do not reuse the name. |
| Protected enrollment proof / uncertain first exchange | Prove and revoke the exact enrollment attempt. Preserve unknown outcomes and never repeat code exchange. |
| Verified generation-zero family awaiting adoption | Resume exact local adoption and cleanup, without another exchange. |
| Confirmed remote cleanup with partial local deletion | Resume the stored cleanup receipt and exact local deletion; do not reread an already deleted proof. |
| Ready profile with unknown family refresh/revocation/removal | Recover the family journal. Retained enrollment IDs are metadata, not evidence that enrollment proof still exists. |
| Removed tombstone | Return the existing result; do not replace or revive it. |

New reviewed deployments may explicitly select `negative-fence-v1` recovery.
Those enrollments use a separate v2 metadata format. If the browser stops before
the server registers the request, recovery can permanently fence the exact
attempt, both proof commitments, client, redirect and selected resource. The
server commits that fence before returning its distinct receipt; the native
coordinator saves the receipt before deleting its exact owned proof. A delayed
copy of that authorization URL then refuses enrollment.

This protocol is prospective. Existing v1 records and requests keep their
original format and registered-request recovery. A missing old request or an
empty HTTP 200 remains unknown; neither permits proof deletion. A negative
receipt cannot clean a profile that has already retained an initial refresh or
adopted a family. Registered recovery continues to confirm the actual request,
grant and family instead. Protective recovery compares the original saved
binding even if its client, redirect or resource registration has since changed.

Logout requires positive confirmation of the exact remote family before local
proof removal. Empty OAuth revocation HTTP 200 alone is not that confirmation.
Unknown remote or local writes retain recovery metadata and block use. Successful
logout removes only the exact owned secrets and leaves a nonreusable name
tombstone. It does not clear unrelated API-key profiles or another Platform
session. Platform browser logout does not revoke the separate CLI/MCP grant;
Platform's developer-access revocation remains its separate control.

## Acceptance boundaries

Portable orchestration fixtures exercise real callback HTTP and the actual
family/client/command modules with disclosed memory custody and mutex ports.
They prove ordering, fixed private errors, resource separation and joined cleanup
at those seams. They do not qualify Credential Manager persistence, NTFS ACLs,
native cross-process locking, installed CLI provenance, real browser/account
consent, deployed HTTPS/TLS or a complete production login journey. The new
Windows delegated store uses a separate OS-selected profile leaf; it neither
repairs inherited AppData permissions nor falls back to plaintext storage.

The installed packed consumer separately checks the unchanged configuration-off
resolver. A verification-only preload runs before the real installed entrypoint
and refuses guarded process, network, native-module and filesystem effects.
Nine developer commands must return the fixed configuration error, with empty
stdout and zero guarded effect attempts. Module-loader reads, six exact public
Linux startup metadata paths and the instrument's own report write are allowed.
These tripwires cover the current bootstrap seams; they are not an adversarial
sandbox or evidence of a configured native login. The preload is not shipped.

Real acceptance requires the reviewed native source/runtime cohort, exact trusted
server/client configuration, deployed ingress/Portal/resource acceptance and a
real Platform-account end-to-end receipt. DEV source selection does not complete
these checks or activate cloud resources. Default production configuration stays
off. The existing guarded installed consumer checks that unchanged default path;
it does not qualify configured DEV native bootstrap or a live login.
