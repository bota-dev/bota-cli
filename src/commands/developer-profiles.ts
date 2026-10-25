import { Command } from 'commander';
import { createInterface } from 'node:readline/promises';
import { delegatedScopes } from '../delegated-family-state.js';
import type { DelegatedLoginSelection } from '../delegated-login.js';
import type { DelegatedNativeProfile } from '../delegated-native-runtime.js';
import type { DeveloperProfileService } from '../developer-profile-service.js';
import { DeveloperProfileError, developerProfileFailure, sanitizeDeveloperProfileError } from '../developer-profile-error.js';
import { printError } from '../output.js';
import { writeDeveloperCommandOutput } from '../developer-profile-production.js';
import { acknowledgeDeveloperOutput } from '../developer-output-acknowledgement.js';

export type DeveloperMetadataWriter = (channel: 'stdout' | 'stderr', text: string) => Promise<void>;

export function safeDeveloperJson(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function developerProfileProjection(profile: DelegatedNativeProfile): Record<string, unknown> {
  return { name: profile.name, credential_type: 'developer_delegation', state: profile.state,
    issuer: profile.deployment.issuer, client_id: profile.deployment.client.clientId,
    resources: profile.deployment.resources, recovery_required: !['ready', 'removed'].includes(profile.state) };
}
/** Service cleanup must join before publication. Acknowledgement is bounded;
 * withdrawal cannot retract public bytes already queued to native stdio. */
export async function publishDeveloperText(channel: 'stdout' | 'stderr', text: string, signal: AbortSignal, write: DeveloperMetadataWriter,
  expiry?: number): Promise<void> {
  const check = () => {
    if (signal.aborted) throw new DeveloperProfileError('developer_cancelled');
    if (expiry !== undefined && Math.floor(Date.now() / 1000) >= expiry) throw new DeveloperProfileError('developer_deadline');
  };
  check();
  try { await acknowledgeDeveloperOutput(channel, text, write, check, signal); check(); }
  catch (error) {
    try { check(); }
    catch (guard) { throw sanitizeDeveloperProfileError(guard, developerProfileFailure(error)?.recovery_required === true, true); }
    throw sanitizeDeveloperProfileError(error, false, true);
  }
}
export async function publishDeveloperMetadata(value: unknown, signal: AbortSignal, write: DeveloperMetadataWriter,
  expiry?: number): Promise<void> {
  await publishDeveloperText('stdout', safeDeveloperJson(value) + '\n', signal, write, expiry);
}
export async function developerCommandBoundary(work: (signal: AbortSignal) => Promise<void>): Promise<void> {
  const controller = new AbortController(); let interrupt: number | undefined;
  const sigint = () => { interrupt = 130; controller.abort(); }, sigterm = () => { interrupt = 143; controller.abort(); };
  process.once('SIGINT', sigint); process.once('SIGTERM', sigterm);
  try { await work(controller.signal); }
  catch (error) {
    const safe = sanitizeDeveloperProfileError(error);
    if (interrupt === undefined && developerProfileFailure(safe)?.code === 'developer_cancelled') interrupt = 130;
    throw safe;
  } finally {
    process.removeListener('SIGINT', sigint); process.removeListener('SIGTERM', sigterm);
    if (interrupt !== undefined) process.exitCode = interrupt;
  }
}
/** This is a nonsecret, explicit authority choice. Stdio MCP never invokes it. */
export async function chooseDeveloperScopes(options: { scope?: string[]; identityOnly?: boolean }, signal: AbortSignal,
  prompt?: (question: string, signal: AbortSignal) => Promise<string>): Promise<DelegatedLoginSelection['scopes']> {
  if (options.identityOnly && options.scope?.length) throw new DeveloperProfileError('developer_profile_invalid');
  if (options.identityOnly) return Object.freeze([]);
  if (options.scope?.length) {
    if (new Set(options.scope).size !== options.scope.length || options.scope.some(scope => !delegatedScopes.includes(scope))) throw new DeveloperProfileError('developer_profile_invalid');
    return Object.freeze([...options.scope]) as DelegatedLoginSelection['scopes'];
  }
  let answer: string;
  const question = 'Requested developer read scopes:\n' + delegatedScopes.map((scope, index) => `${index + 1}. ${scope}`).join('\n')
    + '\nEnter comma-separated numbers, or 0 for identity only: ';
  if (prompt) answer = await prompt(question, signal);
  else {
    if (!process.stdin.isTTY || !process.stderr.isTTY) throw new DeveloperProfileError('developer_login_scope_required');
    const terminal = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    try { answer = await terminal.question(question, { signal }); } finally { terminal.close(); }
  }
  if (signal.aborted) throw new DeveloperProfileError('developer_cancelled');
  if (answer === '0') return Object.freeze([]);
  if (typeof answer !== 'string' || answer.length > 32 || !/^[1-5](?:\s*,\s*[1-5])*$/.test(answer)) throw new DeveloperProfileError('developer_login_scope_required');
  const selected = answer.split(',').map(item => Number(item.trim()) - 1);
  if (new Set(selected).size !== selected.length) throw new DeveloperProfileError('developer_profile_invalid');
  return Object.freeze(selected.map(index => delegatedScopes[index]!)) as DelegatedLoginSelection['scopes'];
}
export function registerDeveloperProfiles(auth: Command, program: Command, service: DeveloperProfileService,
  write: DeveloperMetadataWriter = writeDeveloperCommandOutput): void {
  const profiles = new Command('developer-profiles').description('Inspect and explicitly recover protected Platform developer sessions')
    .allowExcessArguments(false).configureOutput({ outputError: () => printError(new DeveloperProfileError('developer_profile_invalid'), Boolean(program.opts()['json'])) });
  auth.addCommand(profiles);
  profiles.command('list').allowExcessArguments(false).action(() => developerCommandBoundary(async signal => {
    await publishDeveloperMetadata((await service.list({ signal })).map(developerProfileProjection), signal, write);
  }));
  profiles.command('show <name>').allowExcessArguments(false).action((name: string) => developerCommandBoundary(async signal => {
    await publishDeveloperMetadata(developerProfileProjection(await service.inspect(name, { signal })), signal, write);
  }));
  profiles.command('recover <name>').allowExcessArguments(false).description('Recover exact retained state without repeating code exchange').action((name: string) => developerCommandBoundary(async signal => {
    await publishDeveloperMetadata(developerProfileProjection(await service.recover(name, { signal })), signal, write);
  }));
  profiles.command('logout <name>').allowExcessArguments(false).description('Confirm remote family revocation, remove exact local refs and retain its tombstone').action((name: string) => developerCommandBoundary(async signal => {
    await publishDeveloperMetadata(developerProfileProjection(await service.logout(name, { signal })), signal, write);
  }));
}
