/** Inactive delegated-family v1 data/bytes. Separate from API-key v1/v2 and
 * every native credential adapter. No persistence or network is constructed. */
import { types } from 'node:util';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';

export const DELEGATED_FAMILY_FORMAT = 'bota-delegated-family-v1' as const;
export const DELEGATED_REFRESH_NAMESPACE = 'bota/delegated/refresh/v1' as const;
export const DELEGATED_FAMILY_MAX_BYTES = 64 * 1024;
export const delegatedScopes = Object.freeze(['end_users:read', 'devices:read', 'recordings:read', 'transcriptions:read', 'summaries:read']);
export type DelegatedFamilyFailure = 'invalid_input' | 'invalid_state' | 'not_found' | 'exists' | 'pending'
  | 'cancelled' | 'deadline' | 'lease_failed' | 'metadata_unknown' | 'store_unknown' | 'store_absent'
  | 'identity_failed' | 'binding_mismatch' | 'refresh_unknown' | 'revocation_unknown' | 'removed' | 'operation_failed';
const failureCodes: readonly DelegatedFamilyFailure[] = ['invalid_input', 'invalid_state', 'not_found', 'exists', 'pending', 'cancelled', 'deadline',
  'lease_failed', 'metadata_unknown', 'store_unknown', 'store_absent', 'identity_failed', 'binding_mismatch', 'refresh_unknown', 'revocation_unknown', 'removed', 'operation_failed'];
const genuineFailures = new WeakSet<object>();
export class DelegatedFamilyError extends Error {
  constructor(readonly code: DelegatedFamilyFailure, readonly recoveryRequired = false) {
    super('Delegated family state or operation is invalid, unavailable or requires recovery.'); this.name = 'DelegatedFamilyError';
    genuineFailures.add(this);
  }
}
/** Copy only fixed diagnostic fields. Never traverse a thrown value's prototype,
 * invoke hooks or rethrow its mutable message, stack, cause or original object. */
export function delegatedFamilyFailure(value: unknown): Readonly<{ code: DelegatedFamilyFailure; recoveryRequired: boolean }> | null {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !genuineFailures.has(value)) return null;
  const code = Object.getOwnPropertyDescriptor(value, 'code'), recovery = Object.getOwnPropertyDescriptor(value, 'recoveryRequired');
  if (!code || !recovery || !Object.hasOwn(code, 'value') || !Object.hasOwn(recovery, 'value')
    || typeof code.value !== 'string' || !failureCodes.includes(code.value as DelegatedFamilyFailure) || typeof recovery.value !== 'boolean') return null;
  return Object.freeze({ code: code.value as DelegatedFamilyFailure, recoveryRequired: recovery.value });
}
export function familyFail(code: DelegatedFamilyFailure = 'invalid_state', pending = false): never { throw new DelegatedFamilyError(code, pending); }
export function familyObject(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) familyFail();
  const keys = Reflect.ownKeys(value), allowed = [...required, ...optional];
  if (keys.length > allowed.length || keys.some(key => typeof key !== 'string' || !allowed.includes(key))
    || required.some(key => !Object.hasOwn(value, key))) familyFail();
  const output: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    const item = Object.getOwnPropertyDescriptor(value, key);
    if (!item?.enumerable || !Object.hasOwn(item, 'value')) familyFail();
    output[key] = item.value;
  }
  return output;
}
export function familyArray(value: unknown, maximum: number): readonly unknown[] {
  if (types.isProxy(value) || !Array.isArray(value) || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) familyFail();
  const output: unknown[] = [];
  for (let index = 0; index < value.length; index++) {
    const item = Object.getOwnPropertyDescriptor(value, String(index));
    if (!item?.enumerable || !Object.hasOwn(item, 'value')) familyFail(); output.push(item.value);
  }
  return output;
}
export function familyUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}
/** Server UUID wire spelling is canonical lowercase, without a version gate. */
export function familyServerUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
}
export function familySeconds(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }
export function familyStrings(value: unknown, allowed: readonly string[], minimum = 0): readonly string[] {
  const items = familyArray(value, allowed.length);
  if (items.length < minimum || items.some(item => typeof item !== 'string' || !allowed.includes(item)) || new Set(items).size !== items.length) familyFail();
  return Object.freeze((items as string[]).sort());
}
export function sameFamilySet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every(value => right.includes(value));
}
function opaque(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 2048 && Buffer.byteLength(value) <= 2048
    && !/[\x00-\x1f\x7f]/.test(value) && !/bota_d[acr]1_/.test(value);
}
export interface DelegatedFamilyKey { readonly storeId: string; readonly issuer: string; readonly clientId: string; readonly familyId: string }
export interface DelegatedFamilyIdentity {
  readonly issuer: string; readonly clientId: string; readonly userId: string; readonly organizationId: string; readonly projectId: string;
  readonly grantId: string; readonly familyId: string; readonly grantResourceUris: readonly string[]; readonly grantScopes: readonly string[];
}
export interface DelegatedRefreshReference {
  readonly namespace: typeof DELEGATED_REFRESH_NAMESPACE; readonly storeId: string;
  readonly localFamilyId: string; readonly credentialId: string; readonly localGeneration: number;
}
export type DelegatedFamilyState = 'enrolling' | 'ready' | 'refreshing' | 'suspended' | 'rotating' | 'revoking' | 'revoked' | 'removing' | 'removed';
export interface DelegatedFamilyIntent {
  readonly transactionId: string; readonly operation: 'enroll' | 'refresh' | 'revoke' | 'remove';
  readonly resource: string | null; readonly candidate: DelegatedRefreshReference | null;
}
export interface DelegatedFamilySnapshot {
  readonly format: typeof DELEGATED_FAMILY_FORMAT; readonly revision: string; readonly storeId: string; readonly localFamilyId: string;
  readonly deployment: DelegatedLoginDeployment; readonly binding: DelegatedFamilyIdentity;
  /** Local monotonic rotation count; never a claim about server generation. */
  readonly localGeneration: number; readonly state: DelegatedFamilyState;
  readonly current: DelegatedRefreshReference | null; readonly proof: DelegatedRefreshReference | null;
  readonly cleanup: readonly DelegatedRefreshReference[]; readonly intent: DelegatedFamilyIntent | null;
}
export function delegatedFamilyKey(value: unknown): DelegatedFamilyKey {
  try {
    const item = familyObject(value, ['storeId', 'issuer', 'clientId', 'familyId']);
    if (typeof item.storeId !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(item.storeId)
      || typeof item.issuer !== 'string' || typeof item.clientId !== 'string' || !familyServerUuid(item.familyId)) familyFail();
    const url = new URL(item.issuer);
    if (!item.issuer.startsWith('https://') || item.issuer !== url.origin || !/^[\x21-\x7e]+$/.test(item.issuer)
      || /[\\%?#@]/.test(item.issuer) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(item.clientId)) familyFail();
    return Object.freeze({ storeId: item.storeId, issuer: item.issuer, clientId: item.clientId, familyId: item.familyId });
  } catch { return familyFail('invalid_input'); }
}
export function delegatedFamilyIdentity(value: unknown, deployment: DelegatedLoginDeployment): DelegatedFamilyIdentity {
  const item = familyObject(value, ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId', 'grantResourceUris', 'grantScopes']);
  if (item.issuer !== deployment.issuer || item.clientId !== deployment.client.clientId || !familyServerUuid(item.userId)
    || !opaque(item.organizationId) || !opaque(item.projectId) || !familyServerUuid(item.grantId) || !familyServerUuid(item.familyId)) familyFail();
  return Object.freeze({ issuer: item.issuer, clientId: item.clientId, userId: item.userId, organizationId: item.organizationId,
    projectId: item.projectId, grantId: item.grantId, familyId: item.familyId,
    grantResourceUris: familyStrings(item.grantResourceUris, deployment.client.resourceKinds.map(kind => deployment.resources[kind]), 1),
    grantScopes: familyStrings(item.grantScopes, delegatedScopes) });
}
export function familyKeyOf(value: Pick<DelegatedFamilySnapshot, 'storeId' | 'binding'>): DelegatedFamilyKey {
  return delegatedFamilyKey({ storeId: value.storeId, issuer: value.binding.issuer, clientId: value.binding.clientId, familyId: value.binding.familyId });
}
export function sameRefreshReference(left: DelegatedRefreshReference, right: DelegatedRefreshReference): boolean {
  return left.namespace === right.namespace && left.storeId === right.storeId && left.localFamilyId === right.localFamilyId
    && left.credentialId === right.credentialId && left.localGeneration === right.localGeneration;
}
export function familyReferences(value: DelegatedFamilySnapshot): readonly DelegatedRefreshReference[] {
  const result: DelegatedRefreshReference[] = [];
  for (const ref of [value.current, value.proof, ...value.cleanup, value.intent?.candidate]) {
    if (ref && !result.some(item => sameRefreshReference(item, ref))) result.push(ref);
  }
  return Object.freeze(result);
}
function reference(value: unknown, storeId: string, localFamilyId: string): DelegatedRefreshReference {
  const item = familyObject(value, ['namespace', 'storeId', 'localFamilyId', 'credentialId', 'localGeneration']);
  if (item.namespace !== DELEGATED_REFRESH_NAMESPACE || item.storeId !== storeId || item.localFamilyId !== localFamilyId
    || !familyUuid(item.credentialId) || item.credentialId === localFamilyId || !familySeconds(item.localGeneration)) familyFail();
  return Object.freeze({ namespace: DELEGATED_REFRESH_NAMESPACE, storeId, localFamilyId, credentialId: item.credentialId, localGeneration: item.localGeneration });
}
export function decodeDelegatedFamilySnapshot(value: unknown, expectedKey: DelegatedFamilyKey): DelegatedFamilySnapshot {
  try {
    const key = delegatedFamilyKey(expectedKey), item = familyObject(value, ['format', 'revision', 'storeId', 'localFamilyId', 'deployment',
      'binding', 'localGeneration', 'state', 'current', 'proof', 'cleanup', 'intent']);
    if (item.format !== DELEGATED_FAMILY_FORMAT || !familyUuid(item.revision) || item.storeId !== key.storeId
      || !familyUuid(item.localFamilyId) || !familySeconds(item.localGeneration) || item.localGeneration >= Number.MAX_SAFE_INTEGER) familyFail();
    const deployment = parseDelegatedLoginDeployment(item.deployment), binding = delegatedFamilyIdentity(item.binding, deployment);
    if (binding.issuer !== key.issuer || binding.clientId !== key.clientId || binding.familyId !== key.familyId) familyFail();
    const current = item.current === null ? null : reference(item.current, key.storeId, item.localFamilyId);
    const proof = item.proof === null ? null : reference(item.proof, key.storeId, item.localFamilyId);
    const cleanup = Object.freeze(familyArray(item.cleanup, 3).map(value => reference(value, key.storeId, item.localFamilyId as string)));
    let intent: DelegatedFamilyIntent | null = null;
    if (item.intent !== null) {
      const data = familyObject(item.intent, ['transactionId', 'operation', 'resource', 'candidate']);
      if (!familyUuid(data.transactionId) || !['enroll', 'refresh', 'revoke', 'remove'].includes(data.operation as string)
        || data.resource !== null && !binding.grantResourceUris.includes(data.resource as string)) familyFail();
      intent = Object.freeze({ transactionId: data.transactionId, operation: data.operation as DelegatedFamilyIntent['operation'], resource: data.resource as string | null,
        candidate: data.candidate === null ? null : reference(data.candidate, key.storeId, item.localFamilyId) });
    }
    const base = current !== null && current.localGeneration === item.localGeneration
      && (item.localGeneration === 0 ? proof === null : proof !== null && proof.localGeneration === item.localGeneration - 1);
    const refreshing = base && cleanup.length === 0 && intent?.operation === 'refresh' && intent.resource !== null
      && intent.candidate !== null && intent.candidate.localGeneration === item.localGeneration + 1
      && intent.candidate.credentialId !== current?.credentialId && intent.candidate.credentialId !== proof?.credentialId;
    const valid = item.state === 'enrolling' ? base && item.localGeneration === 0 && cleanup.length === 0 && intent?.operation === 'enroll' && intent.resource !== null && intent.candidate === null
      : item.state === 'ready' ? base && cleanup.length === 0 && intent === null
        : item.state === 'refreshing' || item.state === 'suspended' ? refreshing
          : item.state === 'rotating' ? base && proof !== null && intent?.operation === 'refresh' && intent.resource !== null
            && intent.candidate !== null && sameRefreshReference(intent.candidate, current!) && cleanup.length <= 1
            && cleanup.every(ref => ref.localGeneration < proof.localGeneration)
            : item.state === 'revoking' ? base && cleanup.length <= 1 && intent?.operation === 'revoke' && intent.resource === null && intent.candidate === null
              : item.state === 'revoked' ? base && cleanup.length <= 1 && intent === null
                : item.state === 'removing' ? current === null && proof === null && intent?.operation === 'remove' && intent.resource === null && intent.candidate === null
                  : item.state === 'removed' ? current === null && proof === null && cleanup.length === 0 && intent === null : false;
    if (!valid) familyFail();
    const refs = [current, proof, ...cleanup].filter((value): value is DelegatedRefreshReference => value !== null);
    const ids = [item.revision, item.localFamilyId, ...refs.map(value => value.credentialId), ...(intent ? [intent.transactionId] : []),
      ...(intent?.candidate && !refs.some(ref => sameRefreshReference(ref, intent.candidate!)) ? [intent.candidate.credentialId] : [])];
    if (new Set(ids).size !== ids.length) familyFail();
    const result = Object.freeze({ format: DELEGATED_FAMILY_FORMAT, revision: item.revision, storeId: key.storeId, localFamilyId: item.localFamilyId,
      deployment, binding, localGeneration: item.localGeneration, state: item.state as DelegatedFamilyState, current, proof, cleanup, intent });
    if (Buffer.byteLength(JSON.stringify(result)) > DELEGATED_FAMILY_MAX_BYTES) familyFail(); return result;
  } catch { return familyFail(); }
}
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
const byteBuffer = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer')!.get!;
export function encodeDelegatedFamilySnapshot(value: unknown, key: DelegatedFamilyKey): Uint8Array {
  const checked = decodeDelegatedFamilySnapshot(value, key);
  const bytes = Buffer.from(JSON.stringify(checked) + '\n');
  if (bytes.length > DELEGATED_FAMILY_MAX_BYTES) familyFail(); return new Uint8Array(bytes);
}
export function decodeDelegatedFamilySnapshotBytes(input: Uint8Array, key: DelegatedFamilyKey): DelegatedFamilySnapshot {
  try {
    if (types.isProxy(input) || !types.isUint8Array(input) || ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) familyFail();
    const size = byteLength.call(input);
    if (size < 1 || size > DELEGATED_FAMILY_MAX_BYTES || types.isSharedArrayBuffer(byteBuffer.call(input))) familyFail();
    const bytes = new Uint8Array(size); Uint8Array.prototype.set.call(bytes, input);
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const checked = decodeDelegatedFamilySnapshot(JSON.parse(text), key), canonical = encodeDelegatedFamilySnapshot(checked, key);
    if (bytes.length !== canonical.length || !bytes.every((value, index) => value === canonical[index])) familyFail();
    return checked;
  } catch { return familyFail(); }
}
