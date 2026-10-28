import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';
import type { Command } from 'commander';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';
import { getProductionDeveloperDeployment } from './delegated-production-deployment.js';
import { DeveloperProfileError } from './developer-profile-error.js';

// Reviewed backend DEV candidate 551927a19f751fa20a1b420aaa5a5bffa4f2128b.
// This literal selects source configuration, not deployed readiness or consent.
const development = parseDelegatedLoginDeployment({
  version: 1,
  issuer: 'https://api.dev.bota.dev',
  recoveryProtocol: 'negative-fence-v1',
  endpoints: {
    authorization: 'https://api.dev.bota.dev/oauth/authorize',
    token: 'https://api.dev.bota.dev/oauth/token',
    revocation: 'https://api.dev.bota.dev/oauth/revoke',
  },
  resources: { rest: 'https://api.dev.bota.dev/v1', mcp: 'https://api.dev.bota.dev/mcp' },
  client: {
    clientId: 'bota-cli-dev-v1', kind: 'native', pkceMethod: 'S256',
    redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'],
    resourceKinds: ['rest', 'mcp'],
  },
});
// Reviewed backend production cohort8a20fef1a8a5c2e73d087983654a01a001e159ed.
// Explicit selection is source configuration; deployed readiness is separate.
const production = parseDelegatedLoginDeployment({
  version: 1,
  issuer: 'https://api.bota.dev',
  recoveryProtocol: 'negative-fence-v1',
  endpoints: {
    authorization: 'https://api.bota.dev/oauth/authorize',
    token: 'https://api.bota.dev/oauth/token',
    revocation: 'https://api.bota.dev/oauth/revoke',
  },
  resources: { rest: 'https://api.bota.dev/v1', mcp: 'https://api.bota.dev/mcp' },
  client: {
    clientId: 'bota-cli-prod-v1', kind: 'native', pkceMethod: 'S256',
    redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'],
    resourceKinds: ['rest', 'mcp'],
  },
});
const knownDeployments = [JSON.stringify(development), JSON.stringify(production)];
/** Metadata filtering only: exact source-owned configuration supplies no
 * identity, credential or live-readiness authority and samples no selection. */
export function isKnownDeveloperDeployment(value: unknown): boolean {
  try { return knownDeployments.includes(JSON.stringify(parseDelegatedLoginDeployment(value))); }
  catch { return false; }
}
type DeveloperDeploymentSelection = 'dev' | 'prod';
interface SelectionOwner {
  active: boolean;
  state: 'uncaptured' | 'sampling' | 'captured' | 'invalid';
  selected?: DeveloperDeploymentSelection;
  readonly read: () => unknown;
}
const selection = new AsyncLocalStorage<SelectionOwner>();
function invalid(): never { throw new DeveloperProfileError('developer_profile_invalid'); }

/** Trusted executable assembly only. Commander parses inside this lifetime, so
 * the source reader is sampled once after parsing. No endpoint input is accepted.
 * The owner remains live through the whole command, including hosted stdio MCP. */
export async function withDeveloperDeploymentSelection<T>(read: () => unknown, work: () => Promise<T>): Promise<T> {
  if (typeof read !== 'function' || types.isProxy(read) || typeof work !== 'function' || types.isProxy(work)) invalid();
  const owner: SelectionOwner = { active: true, state: 'uncaptured', read };
  return selection.run(owner, async () => {
    try { return await work(); }
    finally { owner.active = false; }
  });
}

/** Captures the parsed enum; saved metadata and environment never select it. */
export function readDeveloperDeploymentSelection(): DeveloperDeploymentSelection | undefined {
  const owner = selection.getStore();
  if (!owner) return undefined;
  if (!owner.active) invalid();
  if (owner.state === 'invalid' || owner.state === 'sampling') { owner.state = 'invalid'; invalid(); }
  if (owner.state === 'uncaptured') {
    // Retire sampling before invoking trusted code so a reentrant reader cannot
    // recursively acquire or replace a selection.
    owner.state = 'sampling';
    let value: unknown;
    try { value = owner.read(); } catch { owner.state = 'invalid'; return invalid(); }
    if (owner.state !== 'sampling' || value !== undefined && value !== 'dev' && value !== 'prod') { owner.state = 'invalid'; invalid(); }
    owner.selected = value;
    owner.state = 'captured';
  }
  return owner.selected;
}

/** The default production resolver stays off. Explicit source-owned enums select
 * reviewed literals; no arbitrary persisted or supplied URL is used. */
export function getSelectedDeveloperDeployment(): DelegatedLoginDeployment {
  const selected = readDeveloperDeploymentSelection();
  return selected === 'dev' ? development : selected === 'prod' ? production : getProductionDeveloperDeployment();
}

/** Bind the current private owner to request callbacks. EventEmitter dispatch
 * inherits its emitter's async resource, which may predate command selection.
 * Only the nonsecret owner is retained; settlement permanently withdraws it. */
export function captureDeveloperDeploymentSelection(): <T>(work: () => Promise<T>) => Promise<T> {
  const owner = selection.getStore();
  if (owner) readDeveloperDeploymentSelection();
  return async <T>(work: () => Promise<T>): Promise<T> => {
    if (typeof work !== 'function' || types.isProxy(work) || owner && !owner.active) invalid();
    const result = await (owner ? selection.run(owner, work) : selection.exit(work));
    if (owner && !owner.active) invalid();
    return result;
  };
}

/** Source-owned Commander pre-action guard. These objects are the actual parsed
 * command, not a public configuration or credential-provider input port. */
export function validateDeveloperDeploymentCommand(program: Command, action: Command): void {
  if (readDeveloperDeploymentSelection() === undefined) return;
  const options = program.opts();
  if (['profile', 'secureProfile', 'apiUrl', 'dashboardUrl'].some(name => options[name] !== undefined)) invalid();
  const route: string[] = [];
  for (let current: Command | null = action; current && current !== program; current = current.parent) route.unshift(current.name());
  if (route[0] === 'auth' && route[1] === 'developer-profiles') {
    if (options['developerProfile'] !== undefined) invalid();
    return;
  }
  if (route[0] === 'auth' && route[1] === 'login' && action.args.length === 0) return;
  if (options['developerProfile'] === undefined) invalid();
  if (!['end-users', 'devices', 'recordings', 'mcp'].includes(route[0] ?? '')
    && !(route[0] === 'auth' && ['status', 'logout'].includes(route[1] ?? ''))) invalid();
}
