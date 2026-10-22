/** Closed delegated credential cohort. API-key targets and references are separate. */
import { familyObject, familySeconds, familyUuid, familyFail } from './delegated-family-state.js';

export const DELEGATED_NATIVE_STORE_ID = 'windows-delegated-credential-manager';
export const DELEGATED_NATIVE_CREDENTIAL_NAMESPACE = 'Bota/DeveloperToolchain/delegated/v1';
export const DELEGATED_NATIVE_DATABASE = 'delegated-v1.sqlite3';
export const DELEGATED_NATIVE_JOURNAL = `${DELEGATED_NATIVE_DATABASE}-journal`;
export const DELEGATED_NATIVE_APPLICATION_ID = 0x42544431;
export const DELEGATED_NATIVE_VERSION = 1;
export const DELEGATED_NATIVE_PAGE_SIZE = 4096;
export const DELEGATED_NATIVE_MAX_DATABASE_BYTES = 64 * 1024 * 1024;
export const DELEGATED_NATIVE_MAX_JOURNAL_BYTES = 128 * 1024 * 1024;
export const DELEGATED_NATIVE_MAX_RECORDS = 2048;
export const DELEGATED_NATIVE_MAX_RECORD_BYTES = 96 * 1024;

export type DelegatedNativeSecretReference = Readonly<{
  kind: 'attempt-proof' | 'initial-refresh'; ownerId: string; credentialId: string;
}> | Readonly<{
  kind: 'family-refresh'; ownerId: string; credentialId: string; localGeneration: number;
}>;
export interface DelegatedNativeSecretApi {
  assertHealthy(): void;
  readCredential(reference: DelegatedNativeSecretReference): Readonly<{ status: 'absent' } | { status: 'present'; secret: string }>;
  /** Create only under the owned native namespace lease. */
  writeCredential(reference: DelegatedNativeSecretReference, secret: string): 'stored' | 'not_stored' | 'unknown';
  /** Validate the exact ownership marker and payload before removing one entry. */
  deleteCredential(reference: DelegatedNativeSecretReference): 'deleted' | 'absent' | 'not_deleted' | 'unknown';
}

export function delegatedNativeSecretReference(value: unknown): DelegatedNativeSecretReference {
  try {
    const item = familyObject(value, ['kind', 'ownerId', 'credentialId'], ['localGeneration']);
    if (!familyUuid(item.ownerId) || !familyUuid(item.credentialId) || item.ownerId === item.credentialId) familyFail();
    if (item.kind === 'family-refresh' && familySeconds(item.localGeneration)) return Object.freeze({
      kind: item.kind, ownerId: item.ownerId, credentialId: item.credentialId, localGeneration: item.localGeneration });
    if ((item.kind === 'attempt-proof' || item.kind === 'initial-refresh') && !Object.hasOwn(item, 'localGeneration'))
      return Object.freeze({ kind: item.kind, ownerId: item.ownerId, credentialId: item.credentialId });
    return familyFail();
  } catch { return familyFail('invalid_input'); }
}
function canonical32(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, 'base64url').toString('base64url') === value;
}
export function encodeDelegatedNativeProof(value: unknown): string {
  try {
    const item = familyObject(value, ['recoveryVerifier', 'pkceVerifier']);
    if (!canonical32(item.recoveryVerifier) || !canonical32(item.pkceVerifier) || item.recoveryVerifier === item.pkceVerifier) familyFail();
    return `bota_dep1_${item.recoveryVerifier}.${item.pkceVerifier}`;
  } catch { return familyFail('invalid_input'); }
}
export function decodeDelegatedNativeProof(value: unknown): Readonly<{ recoveryVerifier: string; pkceVerifier: string }> {
  try {
    if (typeof value !== 'string' || value.length !== 97 || !value.startsWith('bota_dep1_')) familyFail();
    const recoveryVerifier = value.slice(10, 53), pkceVerifier = value.slice(54);
    if (value[53] !== '.' || !canonical32(recoveryVerifier) || !canonical32(pkceVerifier) || recoveryVerifier === pkceVerifier) familyFail();
    return Object.freeze({ recoveryVerifier, pkceVerifier });
  } catch { return familyFail('invalid_input'); }
}
export function delegatedNativeSecret(reference: DelegatedNativeSecretReference, value: unknown): string {
  const checked = delegatedNativeSecretReference(reference);
  if (checked.kind === 'attempt-proof') {
    decodeDelegatedNativeProof(value); return value as string;
  }
  if (typeof value !== 'string' || value.length !== 52 || !value.startsWith('bota_dr1_') || !canonical32(value.slice(9)))
    return familyFail('invalid_input');
  return value;
}
/** A closed reference derives both markers. Never accept an arbitrary target. */
export function delegatedNativeCredentialNames(value: unknown): Readonly<{ target: string; username: string }> {
  const reference = delegatedNativeSecretReference(value);
  const parts = [DELEGATED_NATIVE_CREDENTIAL_NAMESPACE, reference.kind, reference.ownerId, reference.credentialId,
    ...reference.kind === 'family-refresh' ? [String(reference.localGeneration)] : []];
  return Object.freeze({ target: parts.join('/'), username: parts.join(':') });
}
