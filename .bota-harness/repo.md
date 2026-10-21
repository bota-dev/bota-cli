### Project and contracts

This repository builds `@bota.dev/cli`, a TypeScript CLI with local MCP tooling. Runtime commands live in `src/commands/`; client and profile contracts live in `src/`; synthetic regressions live in `tests/`. Read `README.md` and the relevant document in `docs/reviews/` when a change touches those behaviors.

### Setup and verification

- Use Node.js 22.23.2 or newer and the repository's npm lockfile. CI currently uses Node 24.
- Install with `npm ci`.
- Run `npm run type-check` and `npm test` for runtime behavior changes. Tests use synthetic data and local fixtures; use affected tests during iteration.
- Run `npm run license-check` when dependencies or package metadata change.
- Run `npm run verify:package` when packaging, executable behavior or release metadata changes; it builds and verifies a locally installed package candidate.
- Run `python3 scripts/bota-harness.py check` for harness changes. After editing this file, run `python3 scripts/bota-harness.py render`.

### Compatibility and release requirements

- Preserve documented authentication selection, explicit-profile refusal/fallback rules, safe error output and credential handling. Never use real account keys in routine tests.
- Preserve existing Windows-native credential-storage activation limits; consult the native-profile transaction review before changes in that area.
- The current source is a preview candidate. Source tests and package checks do not authorize npm publication, a license grant, backend deployment or moving the public `latest` tag. Follow `docs/reviews/2026-10-19-cli-preview-release.md` and the publication guard.
- Keep the existing CI, license checks and package verification intact. The harness workflow adds a separate consistency check.
