/** Nonsecret delegated enrollment metadata. Proofs and tokens never enter these bytes. */
import { types } from 'node:util';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment, type DelegatedLoginRecoveryBinding } from './delegated-login.js';
import { familyObject, familyArray, familyUuid, familyServerUuid, familyFail, delegatedScopes, delegatedFamilyKey,
  type DelegatedFamilyKey } from './delegated-family-state.js';
import { delegatedNativeSecretReference, DELEGATED_NATIVE_STORE_ID, DELEGATED_NATIVE_MAX_RECORD_BYTES,
  type DelegatedNativeSecretReference } from './delegated-native-contract.js';

export const DELEGATED_NATIVE_PROFILE_FORMAT = 'bota-delegated-native-profile-v1';
export type DelegatedNativeProfileState = 'reserved' | 'proof-intent' | 'proof-ready' | 'refresh-intent' | 'refresh-ready'
  | 'adopting' | 'ready' | 'cleanup-confirmed' | 'removing' | 'removed';
export interface DelegatedNativeAttempt {
  readonly attemptId: string; readonly redirectUri: string; readonly resource: string;
  readonly grantResources: readonly string[]; readonly scopes: readonly string[];
  readonly proof: DelegatedNativeSecretReference | null;
}
export interface DelegatedNativeInitial {
  readonly grantId: string; readonly familyId: string; readonly resource: string; readonly scopes: readonly string[];
  readonly reference: DelegatedNativeSecretReference | null;
}
export interface DelegatedNativeCleanupReceipt {
  readonly attemptId: string; readonly authorizationRequestId: string; readonly grantId: string | null; readonly familyId: string | null;
}
export interface DelegatedNativeProfileRecord {
  readonly format: typeof DELEGATED_NATIVE_PROFILE_FORMAT; readonly revision: string; readonly name: string;
  readonly deployment: DelegatedLoginDeployment; readonly state: DelegatedNativeProfileState;
  readonly attempt: DelegatedNativeAttempt | null; readonly initial: DelegatedNativeInitial | null;
  readonly family: Readonly<{ key: DelegatedFamilyKey; revision: string }> | null;
  readonly cleanupReceipt: DelegatedNativeCleanupReceipt | null;
}
export function delegatedNativeName(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z0-9-]{1,64}$/.test(value)) return familyFail('invalid_input');
  return value;
}
export function delegatedNativeStrings(value: unknown, allowed: readonly string[], minimum = 0): readonly string[] {
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return familyFail('invalid_input');
  const copied = familyArray(value, allowed.length);
  if (copied.length < minimum || copied.some(item => typeof item !== 'string' || !allowed.includes(item)) || new Set(copied).size !== copied.length)
    return familyFail('invalid_input');
  return Object.freeze(copied as string[]);
}
export function delegatedNativeAttempt(value: unknown, deployment: DelegatedLoginDeployment): DelegatedNativeAttempt {
  const item = familyObject(value, ['attemptId', 'redirectUri', 'resource', 'grantResources', 'scopes', 'proof']);
  if (!familyUuid(item.attemptId) || typeof item.redirectUri !== 'string' || typeof item.resource !== 'string') return familyFail();
  const redirect = new URL(item.redirectUri), base = `http://${redirect.hostname}/oauth/callback`;
  if (item.redirectUri !== redirect.href || redirect.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(redirect.hostname)
    || !redirect.port || !/^[1-9][0-9]{0,4}$/.test(redirect.port) || Number(redirect.port) > 65535
    || redirect.pathname !== '/oauth/callback' || redirect.username || redirect.password || redirect.search || redirect.hash
    || !deployment.client.redirectUris.includes(base)) return familyFail();
  const grantResources = delegatedNativeStrings(item.grantResources, deployment.client.resourceKinds.map(kind => deployment.resources[kind]), 1);
  if (!grantResources.includes(item.resource)) return familyFail();
  const proof = item.proof === null ? null : delegatedNativeSecretReference(item.proof);
  if (proof && (proof.kind !== 'attempt-proof' || proof.ownerId !== item.attemptId)) return familyFail();
  return Object.freeze({ attemptId: item.attemptId, redirectUri: item.redirectUri, resource: item.resource,
    grantResources, scopes: delegatedNativeStrings(item.scopes, delegatedScopes), proof });
}
export function delegatedNativeRecoveryMetadata(value: unknown, deployment: DelegatedLoginDeployment,
  proof: DelegatedNativeSecretReference): DelegatedNativeAttempt {
  const item = familyObject(value, ['attemptId', 'recoveryVerifier', 'pkceVerifier', 'issuer', 'clientId', 'redirectUri', 'resource', 'grantResources', 'scopes']);
  if (item.issuer !== deployment.issuer || item.clientId !== deployment.client.clientId) return familyFail('binding_mismatch');
  return delegatedNativeAttempt({ attemptId: item.attemptId, redirectUri: item.redirectUri, resource: item.resource,
    grantResources: item.grantResources, scopes: item.scopes, proof }, deployment);
}
export function delegatedNativeCleanupReceipt(value: unknown, attemptId: string): DelegatedNativeCleanupReceipt {
  const item = familyObject(value, ['attemptId', 'authorizationRequestId', 'grantId', 'familyId']);
  if (item.attemptId !== attemptId || !familyServerUuid(item.authorizationRequestId)
    || item.grantId !== null && !familyServerUuid(item.grantId) || item.familyId !== null && !familyServerUuid(item.familyId)
    || item.familyId !== null && item.grantId === null) return familyFail('invalid_input');
  return Object.freeze({ attemptId, authorizationRequestId: item.authorizationRequestId,
    grantId: item.grantId as string | null, familyId: item.familyId as string | null });
}
export function decodeDelegatedNativeProfile(value: unknown, expectedName: string): DelegatedNativeProfileRecord {
  try {
    const item = familyObject(value, ['format', 'revision', 'name', 'deployment', 'state', 'attempt', 'initial', 'family', 'cleanupReceipt']);
    if (item.format !== DELEGATED_NATIVE_PROFILE_FORMAT || !familyUuid(item.revision) || item.name !== delegatedNativeName(expectedName)) return familyFail();
    const deployment = parseDelegatedLoginDeployment(item.deployment), attempt = item.attempt === null ? null : delegatedNativeAttempt(item.attempt, deployment);
    let initial: DelegatedNativeInitial | null = null;
    if (item.initial !== null) {
      const data = familyObject(item.initial, ['grantId', 'familyId', 'resource', 'scopes', 'reference']);
      if (!attempt || !familyServerUuid(data.grantId) || !familyServerUuid(data.familyId) || data.resource !== attempt.resource) return familyFail();
      const reference = data.reference === null ? null : delegatedNativeSecretReference(data.reference);
      if (reference && (reference.kind !== 'initial-refresh' || reference.ownerId !== attempt.attemptId
        || reference.credentialId === attempt.proof?.credentialId)) return familyFail();
      initial = Object.freeze({ grantId: data.grantId, familyId: data.familyId, resource: data.resource as string,
        scopes: delegatedNativeStrings(data.scopes, attempt.scopes), reference });
    }
    let family: DelegatedNativeProfileRecord['family'] = null;
    if (item.family !== null) {
      const data = familyObject(item.family, ['key', 'revision']); const key = delegatedFamilyKey(data.key);
      if (!initial || key.storeId !== DELEGATED_NATIVE_STORE_ID || key.issuer !== deployment.issuer
        || key.clientId !== deployment.client.clientId || key.familyId !== initial.familyId || !familyUuid(data.revision)) return familyFail();
      family = Object.freeze({ key, revision: data.revision });
    }
    const cleanupReceipt = item.cleanupReceipt === null ? null : delegatedNativeCleanupReceipt(item.cleanupReceipt, attempt?.attemptId ?? '');
    if (cleanupReceipt && initial && (cleanupReceipt.grantId !== initial.grantId || cleanupReceipt.familyId !== initial.familyId)) return familyFail();
    const pendingProof = !!attempt?.proof, pendingInitial = !!initial?.reference;
    const valid = item.state === 'reserved' ? attempt === null && initial === null && family === null && cleanupReceipt === null
      : item.state === 'proof-intent' || item.state === 'proof-ready' ? pendingProof && initial === null && family === null && cleanupReceipt === null
        : item.state === 'refresh-intent' || item.state === 'refresh-ready' ? pendingProof && pendingInitial && family === null && cleanupReceipt === null
          : item.state === 'adopting' ? !!attempt && !!initial && family !== null && cleanupReceipt === null
            : item.state === 'ready' ? !!attempt && !!initial && family !== null && !pendingProof && !pendingInitial && cleanupReceipt === null
              : item.state === 'cleanup-confirmed' || item.state === 'removing' ? !!attempt && cleanupReceipt !== null && family === null
                : item.state === 'removed' ? attempt === null && initial === null && family === null && cleanupReceipt === null
                  || !!attempt && !pendingProof && !pendingInitial
                    && (cleanupReceipt !== null && family === null || cleanupReceipt === null && family !== null && initial !== null) : false;
    if (!valid) return familyFail();
    const result = Object.freeze({ format: DELEGATED_NATIVE_PROFILE_FORMAT, revision: item.revision, name: item.name as string,
      deployment, state: item.state as DelegatedNativeProfileState, attempt, initial, family, cleanupReceipt });
    if (Buffer.byteLength(JSON.stringify(result)) > DELEGATED_NATIVE_MAX_RECORD_BYTES) return familyFail();
    return result;
  } catch { return familyFail('invalid_state'); }
}
export function encodeDelegatedNativeProfile(value: unknown, name: string): Uint8Array {
  return new Uint8Array(Buffer.from(JSON.stringify(decodeDelegatedNativeProfile(value, name)) + '\n'));
}
const nativeByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
const nativeBuffer = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer')!.get!;
export function decodeDelegatedNativeProfileBytes(value: Uint8Array, name: string): DelegatedNativeProfileRecord {
  try {
    if (types.isProxy(value) || !types.isUint8Array(value) || ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(value))
      || types.isSharedArrayBuffer(nativeBuffer.call(value))) return familyFail();
    const length = nativeByteLength.call(value); if (length < 1 || length > DELEGATED_NATIVE_MAX_RECORD_BYTES) return familyFail();
    const bytes = new Uint8Array(length); Uint8Array.prototype.set.call(bytes, value);
    const decoded = decodeDelegatedNativeProfile(JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)), name);
    const canonical = encodeDelegatedNativeProfile(decoded, name);
    if (canonical.length !== length || !bytes.every((byte, index) => byte === canonical[index])) return familyFail();
    return decoded;
  } catch { return familyFail('invalid_state'); }
}
export function recoverDelegatedNativeBinding(record: DelegatedNativeProfileRecord,
  proof: Readonly<{ recoveryVerifier: string; pkceVerifier: string }>): DelegatedLoginRecoveryBinding {
  if (!record.attempt) return familyFail('pending', true);
  return Object.freeze({ attemptId: record.attempt.attemptId, ...proof, issuer: record.deployment.issuer,
    clientId: record.deployment.client.clientId, redirectUri: record.attempt.redirectUri, resource: record.attempt.resource,
    grantResources: record.attempt.grantResources, scopes: record.attempt.scopes as DelegatedLoginRecoveryBinding['scopes'] });
}
