import { constants, type Stats } from 'node:fs';
import { lstat, mkdir, open, readdir, rmdir, link, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { ProjectIdentity } from './client.js';

export type ProfileErrorCode =
  | 'profile_invalid_name' | 'profile_invalid_origin' | 'profile_not_found'
  | 'profile_exists' | 'profile_invalid_metadata' | 'profile_unavailable'
  | 'profile_busy' | 'profile_key_required' | 'profile_invalid_key'
  | 'profile_origin_mismatch' | 'profile_identity_failed'
  | 'profile_identity_mismatch' | 'profile_write_failed' | 'profile_remove_failed';

const messages: Record<ProfileErrorCode, string> = {
  profile_invalid_name: 'Profile names must contain 1 to 64 lowercase letters, digits or hyphens.',
  profile_invalid_origin: 'Select an HTTPS API origin, or explicitly allow literal HTTP loopback development.',
  profile_not_found: 'The selected profile does not exist.',
  profile_exists: 'The profile already exists. Profiles are never replaced implicitly.',
  profile_invalid_metadata: 'The profile metadata is invalid or unsupported.',
  profile_unavailable: 'The profile directory or file is unavailable or unsafe.',
  profile_busy: 'The profile is being changed or requires lock recovery.',
  profile_key_required: 'The selected profile requires BOTA_API_KEY in the environment.',
  profile_invalid_key: 'The selected environment credential is invalid.',
  profile_origin_mismatch: 'The API origin override does not match the selected profile.',
  profile_identity_failed: 'The credential identity could not be verified.',
  profile_identity_mismatch: 'The credential does not match the selected project and organization.',
  profile_write_failed: 'The profile could not be created safely.',
  profile_remove_failed: 'The profile metadata could not be removed safely.',
};

export class ProfileError extends Error {
  constructor(readonly code: ProfileErrorCode) {
    super(messages[code]);
    this.name = 'ProfileError';
  }
}

export interface EnvironmentProfile {
  name: string;
  format_version: 1;
  api_origin: string;
  project_id: string;
  organization_id: string;
  credential_source: 'environment';
  allow_http_loopback: boolean;
}

export type IdentityReader = (apiUrl: string, key: string) => Promise<ProjectIdentity>;
type Environment = Record<string, string | undefined>;
const MAX_METADATA_BYTES = 8192;
const MAX_KEY_BYTES = 16 * 1024;
const fields = ['name', 'format_version', 'api_origin', 'project_id', 'organization_id', 'credential_source', 'allow_http_loopback'];

function nameChecked(name: unknown): asserts name is string {
  if (typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(name)) throw new ProfileError('profile_invalid_name');
}

export function normalizeProfileOrigin(input: string, allowHttpLoopback = false): string {
  try {
    if (typeof input !== 'string' || input.length > 2048 || !/^[\x21-\x7e]+$/.test(input) || input.includes('\\')) throw new Error();
    // URL parsing normalizes dot paths, empty query/fragment markers and some
    // malformed authorities. Accept a raw origin form before canonicalizing.
    if (!/^https:\/\/[^/?#@]+\/?$/i.test(input) && !/^http:\/\/(127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/i.test(input)) throw new Error();
    const url = new URL(input);
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || !url.hostname || url.port === '0') throw new Error();
    if (url.protocol !== 'https:') {
      if (url.protocol !== 'http:' || !allowHttpLoopback || !/^http:\/\/(127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/i.test(input)) throw new Error();
    }
    return url.origin;
  } catch {
    throw new ProfileError('profile_invalid_origin');
  }
}

function nativeCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

function profilePath(directory: string, name: string): string {
  return join(directory, `${Buffer.from(name, 'utf8').toString('hex')}.json`);
}

function directoryPath(directory?: string): string {
  try { return resolve(directory ?? join(homedir(), '.bota', 'profiles')); }
  catch { throw new ProfileError('profile_unavailable'); }
}

function trustedPosixEntry(stat: Stats, stickyAncestor = false): boolean {
  // Windows ownership/ACLs are provided by the user's protected profile
  // directory; POSIX uid/mode values do not describe that ACL policy.
  if (process.platform === 'win32') return true;
  const uid = process.getuid?.();
  return uid !== undefined && (stat.uid === uid || stat.uid === 0)
    && ((stat.mode & 0o022) === 0 || stickyAncestor && stat.uid === 0 && (stat.mode & 0o1000) !== 0);
}

// No legacy config or native credential store is inspected. Refuse links at
// every directory boundary. This is not a sandbox against a malicious user
// concurrently replacing their own filesystem entries.
async function checkedDirectory(directory: string, create: boolean): Promise<boolean> {
  const paths: string[] = [];
  let current = directory;
  for (;;) {
    paths.unshift(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const path of paths) {
    try {
      let stat;
      try { stat = await lstat(path); }
      catch (error) {
        if (nativeCode(error) !== 'ENOENT') throw error;
        if (!create) return false;
        try { await mkdir(path, { mode: 0o700 }); }
        catch (failure) { if (nativeCode(failure) !== 'EEXIST') throw failure; }
        stat = await lstat(path);
      }
      if (!stat.isDirectory() || stat.isSymbolicLink() || !trustedPosixEntry(stat, path !== directory)) throw new Error();
    } catch { throw new ProfileError('profile_unavailable'); }
  }
  return true;
}

function identifier(value: unknown, key?: string): value is string {
  return typeof value === 'string' && value.length !== 0 && Buffer.byteLength(value, 'utf8') <= 2048
    && (key === undefined || !value.includes(key));
}

function decodedProfile(value: unknown, name: string): EnvironmentProfile {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    const data = value as Record<string, unknown>;
    if (Object.keys(data).length !== fields.length || fields.some(field => !Object.hasOwn(data, field))
      || data.name !== name || data.format_version !== 1 || data.credential_source !== 'environment'
      || typeof data.allow_http_loopback !== 'boolean' || typeof data.api_origin !== 'string'
      || normalizeProfileOrigin(data.api_origin, data.allow_http_loopback) !== data.api_origin
      || !identifier(data.project_id) || !identifier(data.organization_id)) throw new Error();
    return {
      name, format_version: 1, api_origin: data.api_origin,
      project_id: data.project_id, organization_id: data.organization_id,
      credential_source: 'environment', allow_http_loopback: data.allow_http_loopback,
    };
  } catch { throw new ProfileError('profile_invalid_metadata'); }
}

async function readProfile(directory: string, name: string): Promise<EnvironmentProfile> {
  const path = profilePath(directory, name);
  let file;
  try {
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink() || !trustedPosixEntry(before)) throw new ProfileError('profile_unavailable');
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = await file.stat();
    if (!stat.isFile() || !trustedPosixEntry(stat) || stat.dev !== before.dev || stat.ino !== before.ino) throw new ProfileError('profile_unavailable');
    if (stat.size === 0 || stat.size > MAX_METADATA_BYTES) throw new ProfileError('profile_invalid_metadata');
    const bytes = Buffer.alloc(MAX_METADATA_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await file.read(bytes, length, bytes.length - length, length);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length > MAX_METADATA_BYTES) throw new ProfileError('profile_invalid_metadata');
    let value: unknown;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length))); }
    catch { throw new ProfileError('profile_invalid_metadata'); }
    return decodedProfile(value, name);
  } catch (error) {
    if (error instanceof ProfileError) throw error;
    if (nativeCode(error) === 'ENOENT') throw new ProfileError('profile_not_found');
    throw new ProfileError('profile_unavailable');
  } finally { if (file) await file.close().catch(() => undefined); }
}

export async function readEnvironmentProfile(name: string, directory?: string): Promise<EnvironmentProfile> {
  nameChecked(name);
  const location = directoryPath(directory);
  if (!await checkedDirectory(location, false)) throw new ProfileError('profile_not_found');
  return readProfile(location, name);
}

export async function listEnvironmentProfiles(directory?: string): Promise<EnvironmentProfile[]> {
  const location = directoryPath(directory);
  if (!await checkedDirectory(location, false)) return [];
  try {
    const result: EnvironmentProfile[] = [];
    for (const entry of await readdir(location)) {
      if (!/^(?:[0-9a-f]{2}){1,64}\.json$/.test(entry)) continue;
      const name = Buffer.from(entry.slice(0, -5), 'hex').toString('utf8');
      nameChecked(name);
      if (profilePath(location, name) !== join(location, entry)) throw new ProfileError('profile_invalid_metadata');
      try { result.push(await readProfile(location, name)); }
      catch (error) { if (!(error instanceof ProfileError && error.code === 'profile_not_found')) throw error; }
    }
    return result.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  } catch (error) {
    if (error instanceof ProfileError) throw error;
    throw new ProfileError('profile_unavailable');
  }
}

async function mutation<T>(directory: string, name: string, work: () => Promise<T>): Promise<T> {
  const lock = join(directory, `.${Buffer.from(name).toString('hex')}.lock`);
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) { throw new ProfileError(nativeCode(error) === 'EEXIST' ? 'profile_busy' : 'profile_unavailable'); }
  let succeeded = false;
  try { const result = await work(); succeeded = true; return result; }
  finally {
    try { await rmdir(lock); }
    catch { if (succeeded) throw new ProfileError('profile_unavailable'); }
  }
}

export async function removeEnvironmentProfile(name: string, directory?: string): Promise<void> {
  nameChecked(name);
  const location = directoryPath(directory);
  if (!await checkedDirectory(location, false)) throw new ProfileError('profile_not_found');
  await mutation(location, name, async () => {
    await readProfile(location, name);
    try { await unlink(profilePath(location, name)); }
    catch { throw new ProfileError('profile_remove_failed'); }
  });
}

function environmentKey(env: Environment): string {
  let value: unknown;
  try { value = Object.hasOwn(env, 'BOTA_API_KEY') ? env.BOTA_API_KEY : undefined; }
  catch { throw new ProfileError('profile_invalid_key'); }
  if (value === undefined) throw new ProfileError('profile_key_required');
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_KEY_BYTES || !/^[\x21-\x7e]+$/.test(value)) throw new ProfileError('profile_invalid_key');
  return value;
}

function reflectsCredential(values: unknown[], apiKey: string): boolean {
  return values.some(value => typeof value === 'string' && value.includes(apiKey));
}

function checkOriginOverrides(apiOrigin: string, allowHttpLoopback: boolean, env: Environment, explicit?: string): void {
  let environmentOrigin: unknown;
  try { environmentOrigin = Object.hasOwn(env, 'BOTA_API_URL') ? env.BOTA_API_URL : undefined; }
  catch { throw new ProfileError('profile_invalid_origin'); }
  for (const override of [explicit, environmentOrigin]) {
    if (override === undefined) continue;
    if (typeof override !== 'string' || normalizeProfileOrigin(override, allowHttpLoopback) !== apiOrigin) throw new ProfileError('profile_origin_mismatch');
  }
}

async function verifiedIdentity(readIdentity: IdentityReader, apiUrl: string, apiKey: string): Promise<ProjectIdentity> {
  try {
    const value = await readIdentity(apiUrl, apiKey);
    if (!value || typeof value !== 'object' || !identifier(value.project_id, apiKey)
      || !identifier(value.organization_id, apiKey) || !identifier(value.key_id, apiKey)
      || typeof value.is_test_mode !== 'boolean'
      || !(value.key_type === 'secret' && value.scope_mode === 'project_secret' && value.scopes === null
        || value.key_type === 'restricted' && value.scope_mode === 'restricted' && Array.isArray(value.scopes)
          && value.scopes.every(scope => typeof scope === 'string' && !scope.includes(apiKey)))) throw new Error();
    return {
      project_id: value.project_id, organization_id: value.organization_id, key_id: value.key_id,
      key_type: value.key_type, is_test_mode: value.is_test_mode, scope_mode: value.scope_mode,
      scopes: value.scopes === null ? null : [...value.scopes],
    };
  } catch { throw new ProfileError('profile_identity_failed'); }
}

export async function enrollEnvironmentProfile(options: {
  name: string; apiUrl: string; allowHttpLoopback?: boolean; env?: Environment;
  directory?: string; readIdentity: IdentityReader;
}): Promise<EnvironmentProfile> {
  nameChecked(options.name);
  const allowHttpLoopback = options.allowHttpLoopback ?? false;
  if (typeof allowHttpLoopback !== 'boolean') throw new ProfileError('profile_invalid_origin');
  const apiUrl = normalizeProfileOrigin(options.apiUrl, allowHttpLoopback);
  const env = options.env ?? process.env;
  checkOriginOverrides(apiUrl, allowHttpLoopback, env);
  const location = directoryPath(options.directory);
  if (await checkedDirectory(location, false)) {
    try { await lstat(profilePath(location, options.name)); throw new ProfileError('profile_exists'); }
    catch (error) { if (nativeCode(error) !== 'ENOENT') throw error instanceof ProfileError ? error : new ProfileError('profile_unavailable'); }
  }
  const apiKey = environmentKey(env);
  if (reflectsCredential([options.name, apiUrl, 'environment'], apiKey)) throw new ProfileError('profile_invalid_key');
  const identity = await verifiedIdentity(options.readIdentity, apiUrl, apiKey);
  const profile: EnvironmentProfile = {
    name: options.name, format_version: 1, api_origin: apiUrl,
    project_id: identity.project_id, organization_id: identity.organization_id,
    credential_source: 'environment', allow_http_loopback: allowHttpLoopback,
  };
  const metadata = Buffer.from(`${JSON.stringify(profile, null, 2)}\n`, 'utf8');
  if (metadata.length > MAX_METADATA_BYTES) throw new ProfileError('profile_invalid_metadata');
  await checkedDirectory(location, true);
  await mutation(location, options.name, async () => {
    const temporary = join(location, `.profile-${randomUUID()}.tmp`);
    let created = false;
    try {
      const file = await open(temporary, 'wx', 0o600);
      created = true;
      try { await file.writeFile(metadata); await file.sync(); }
      finally { await file.close(); }
      // link() is exclusive: a concurrent/cooperative enrollment cannot replace
      // an existing record, and readers never see a partially written record.
      await link(temporary, profilePath(location, options.name));
    } catch (error) {
      throw new ProfileError(nativeCode(error) === 'EEXIST' ? 'profile_exists' : 'profile_write_failed');
    } finally { if (created) await unlink(temporary).catch(() => undefined); }
  });
  return profile;
}

export async function resolveEnvironmentProfile(options: {
  name: string; apiUrlOverride?: string; env?: Environment; directory?: string; readIdentity: IdentityReader;
}): Promise<{ profile: EnvironmentProfile; apiKey: string; apiUrl: string; identity: ProjectIdentity }> {
  const profile = await readEnvironmentProfile(options.name, options.directory);
  const env = options.env ?? process.env;
  checkOriginOverrides(profile.api_origin, profile.allow_http_loopback, env, options.apiUrlOverride);
  const apiKey = environmentKey(env);
  if (reflectsCredential(Object.values(profile), apiKey)) throw new ProfileError('profile_invalid_metadata');
  const identity = await verifiedIdentity(options.readIdentity, profile.api_origin, apiKey);
  if (identity.project_id !== profile.project_id || identity.organization_id !== profile.organization_id) throw new ProfileError('profile_identity_mismatch');
  return { profile, apiKey, apiUrl: profile.api_origin, identity };
}
