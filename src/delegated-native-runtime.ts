/** Native delegated custody, separate from API-key profiles. */
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment, type DelegatedLoginRetentionPort, type DelegatedLoginRecoveryBinding } from './delegated-login.js';
import type { DelegatedInitialRefreshCustody, DelegatedEnrollmentRevocationConfirmation } from './delegated-http.js';
import type { DelegatedFamilyContext, DelegatedFamilyPorts } from './delegated-family-engine.js';
import { familyObject, familyUuid, familyFail, delegatedFamilyFailure, delegatedFamilyKey, familyReferences, sameFamilySet,
  decodeDelegatedFamilySnapshot, type DelegatedFamilySnapshot, type DelegatedFamilyKey, type DelegatedRefreshReference } from './delegated-family-state.js';
import { DELEGATED_NATIVE_STORE_ID, delegatedNativeSecret, delegatedNativeSecretReference, encodeDelegatedNativeProof, decodeDelegatedNativeProof,
  type DelegatedNativeSecretReference, type DelegatedNativeSecretApi } from './delegated-native-contract.js';
import { DELEGATED_NATIVE_PROFILE_FORMAT, delegatedNativeName, decodeDelegatedNativeProfile, delegatedNativeRecoveryMetadata,
  delegatedNativeCleanupReceipt, delegatedNativeStrings, recoverDelegatedNativeBinding,
  type DelegatedNativeProfileRecord, type DelegatedNativeProfileState } from './delegated-native-state.js';
import { DelegatedNativeSnapshots, delegatedNativeLeaseName, type DelegatedNativeRecordKey } from './delegated-native-snapshots.js';
import { openWindowsNativeLease, WINDOWS_NATIVE_STORE_ID, type WindowsNativeLease } from './windows-native-lease.js';
import { createWindowsDelegatedCredentialApi } from './windows-native-api.js';
import { createWindowsDelegatedSnapshotGuard } from './windows-native-snapshot-files.js';
import { getWindowsDelegatedRoot } from './windows-delegated-root.js';
import { qualifyWindowsSnapshotRuntime } from './windows-native-snapshots.js';

export interface DelegatedNativeProfile {
  readonly name: string; readonly state: DelegatedNativeProfileState; readonly attemptId: string | null;
  readonly familyKey: DelegatedFamilyKey | null;
  /** Unverified first-response cleanup target. NEVER selection/admission authority. */
  readonly pendingFamilyKey: DelegatedFamilyKey | null;
  readonly deployment: DelegatedLoginDeployment;
}
export interface DelegatedNativeRuntime {
  readonly familyPorts: Pick<DelegatedFamilyPorts, 'store' | 'snapshots' | 'lease'>;
  reserve(name: string, deployment: DelegatedLoginDeployment, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  abandonReserved(name: string, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  load(name: string, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile | null>;
  list(context: DelegatedFamilyContext): Promise<readonly DelegatedNativeProfile[]>;
  retentionPort(name: string): DelegatedLoginRetentionPort;
  retainInitialRefresh(name: string): DelegatedInitialRefreshCustody;
  adopt(name: string, expectedAttemptId: string, key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  readRecovery(name: string, expectedAttemptId: string, context: DelegatedFamilyContext): Promise<DelegatedLoginRecoveryBinding>;
  confirmCleanup(name: string, expectedAttemptId: string, receipt: DelegatedEnrollmentRevocationConfirmation, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  resumeCleanup(name: string, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  finalizeRemoval(name: string, expectedFamilyKey: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile>;
  close(): void | Promise<void>;
}

export interface DelegatedNativeRuntimeTrustedPorts {
  readonly lease: Pick<WindowsNativeLease, 'runExclusive' | 'runMetadataExclusive' | 'close'>;
  readonly snapshots: Pick<DelegatedNativeSnapshots, 'load' | 'publish' | 'readRelatedFamily' | 'list'>;
  readonly credentials: DelegatedNativeSecretApi;
  readonly newId?: () => string;
}
interface Ticket { readonly key: DelegatedNativeRecordKey | null; readonly context: DelegatedFamilyContext; active: boolean; effects: boolean; family?: DelegatedFamilySnapshot }
const nativeAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const nativeAdd = EventTarget.prototype.addEventListener, nativeRemove = EventTarget.prototype.removeEventListener, nativeAbort = AbortController.prototype.abort;
function parentGuard(input: DelegatedFamilyContext): () => void {
  try {
    const item = familyObject(input, ['signal', 'budget']); if (!item.budget || typeof item.budget !== 'object' || types.isProxy(item.budget) || types.isProxy(item.signal)) return familyFail('invalid_input');
    nativeAborted.call(item.signal); const budget = item.budget as DelegatedFamilyContext['budget'];
    const field = Object.getOwnPropertyDescriptor(budget, 'assertActive'); if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'function' || types.isProxy(field.value)) return familyFail('invalid_input');
    const assertion = field.value, signal = item.signal as AbortSignal;
    return () => {
      const current = familyObject(input, ['signal', 'budget']), currentAssertion = Object.getOwnPropertyDescriptor(budget, 'assertActive');
      if (current.signal !== signal || current.budget !== budget || !currentAssertion || !Object.hasOwn(currentAssertion, 'value') || currentAssertion.value !== assertion) return familyFail('invalid_input');
      if (nativeAborted.call(signal)) return familyFail('cancelled');
      try { Reflect.apply(assertion, budget, []); } catch { return familyFail('deadline'); }
      if (nativeAborted.call(signal)) return familyFail('cancelled');
      const after = familyObject(input, ['signal', 'budget']); if (after.signal !== signal || after.budget !== budget
        || Object.getOwnPropertyDescriptor(budget, 'assertActive')?.value !== assertion) return familyFail('invalid_input');
    };
  } catch { return familyFail('invalid_input'); }
}
function profileKey(name: string): DelegatedNativeRecordKey { return Object.freeze({ kind: 'profile', name: delegatedNativeName(name) }); }
function pendingKey(record: DelegatedNativeProfileRecord): DelegatedFamilyKey | null {
  return record.initial ? delegatedFamilyKey({ storeId: DELEGATED_NATIVE_STORE_ID, issuer: record.deployment.issuer,
    clientId: record.deployment.client.clientId, familyId: record.initial.familyId }) : null;
}
function metadata(record: DelegatedNativeProfileRecord): DelegatedNativeProfile {
  return Object.freeze({ name: record.name, state: record.state, attemptId: record.attempt?.attemptId ?? null,
    familyKey: record.family?.key ?? null, pendingFamilyKey: record.family ? null : pendingKey(record), deployment: record.deployment });
}
function sameKey(left: DelegatedFamilyKey, right: DelegatedFamilyKey): boolean { return JSON.stringify(delegatedFamilyKey(left)) === JSON.stringify(delegatedFamilyKey(right)); }

/** Trusted fixture assembly only. Production always uses the fixed native
 * factories below, never a caller root/namespace/persistence choice. */
export function createDelegatedNativeRuntimeForTrustedPorts(ports: DelegatedNativeRuntimeTrustedPorts): DelegatedNativeRuntime {
  const scope = new AsyncLocalStorage<Ticket>(), jobs = new Set<Promise<unknown>>(), controllers = new Set<AbortController>();
  const lease = ports.lease, snapshots = ports.snapshots, credentials = ports.credentials;
  let closed = false, closePromise: Promise<void> | undefined;
  const fresh = () => { const value = (ports.newId ?? randomUUID)(); if (!familyUuid(value)) return familyFail('invalid_input'); return value; };
  const check = (context: DelegatedFamilyContext): Ticket => {
    if (closed) return familyFail('lease_failed', true); const ticket = scope.getStore();
    if (!ticket?.active || ticket.context !== context) return familyFail('lease_failed', true);
    parentGuard(context)(); credentials.assertHealthy(); return ticket;
  };
  const effect = (context: DelegatedFamilyContext) => { check(context).effects = true; };
  function own<T>(key: DelegatedNativeRecordKey | null, context: DelegatedFamilyContext, work: () => Promise<T>): Promise<T> {
    const guard = parentGuard(context); guard(); if (closed) return Promise.reject(new Error('Delegated native runtime is closed.'));
    const ticket: Ticket = { key, context, active: false, effects: false }; let callback: Promise<T> | undefined, entered = false, ownerOpen = true;
    let output: T, leaseRejected = false, leaseFailure: unknown, propagatedFamilyFailure: unknown, propagateFamilyFailure = false;
    const job = Promise.resolve().then(async () => {
      try {
        guard(); if (closed) return familyFail('lease_failed', false);
        const action = () => {
          if (!ownerOpen || entered || closed) return Promise.reject(new Error('Delegated native lease is unavailable.'));
          entered = true; ticket.active = true;
          callback = scope.run(ticket, async () => { try { check(context); const value = await work(); check(context); return value; } finally { ticket.active = false; } });
          void callback.catch(() => undefined); return callback;
        };
        try { output = await (key ? lease.runExclusive(WINDOWS_NATIVE_STORE_ID, delegatedNativeLeaseName(key), context, action)
          : lease.runMetadataExclusive(WINDOWS_NATIVE_STORE_ID, context, action)); }
        catch (error) { leaseRejected = true; leaseFailure = error; }
        ownerOpen = false; const early = ticket.active; ticket.active = false;
        const settled = callback ? (await Promise.allSettled([callback]))[0] : undefined;
        if (early || !entered) return familyFail('lease_failed', ticket.effects || entered);
        if (leaseRejected) { const known = delegatedFamilyFailure(leaseFailure);
          // The family engine distinguishes an unchanged callback rejection
          // from a failed kernel release by exact identity, then makes its own
          // fresh fixed projection. Only that genuine callback error crosses
          // this private lease port; native/foreign reasons never do.
          if (key?.kind === 'family' && known && settled?.status === 'rejected' && settled.reason === leaseFailure) {
            propagatedFamilyFailure = leaseFailure; propagateFamilyFailure = true; throw leaseFailure;
          }
          return familyFail(known?.code ?? 'lease_failed', ticket.effects || known?.recoveryRequired === true); }
        guard(); if (closed) return familyFail('lease_failed', ticket.effects); return output!;
      } catch (error) { if (propagateFamilyFailure && error === propagatedFamilyFailure) throw error;
        const known = delegatedFamilyFailure(error); return familyFail(known?.code ?? 'operation_failed', ticket.effects || known?.recoveryRequired === true); }
      finally { ownerOpen = false; ticket.active = false; }
    });
    jobs.add(job); void job.finally(() => jobs.delete(job)).catch(() => undefined); return job;
  }
  async function operation<T>(key: DelegatedNativeRecordKey | null, input: DelegatedFamilyContext,
    action: (context: DelegatedFamilyContext) => Promise<T>): Promise<T> {
    const guard = parentGuard(input); guard(); const controller = new AbortController(); controllers.add(controller); let retired = false;
    const abort = () => nativeAbort.call(controller); nativeAdd.call(input.signal, 'abort', abort, { once: true });
    const child = Object.freeze({ signal: controller.signal, budget: Object.freeze({ assertActive() { if (retired) return familyFail('lease_failed', true); guard(); if (nativeAborted.call(controller.signal)) return familyFail('cancelled'); } }) });
    try { guard(); return await own(key, child, () => action(child)); }
    finally { retired = true; nativeAbort.call(controller); nativeRemove.call(input.signal, 'abort', abort); controllers.delete(controller); }
  }
  const selectedProfile = async (name: string, context: DelegatedFamilyContext): Promise<DelegatedNativeProfileRecord | null> => {
    const ticket = check(context); if (!ticket.key || ticket.key.kind !== 'profile' || ticket.key.name !== name) return familyFail('binding_mismatch');
    const value = await snapshots.load(profileKey(name), context); check(context); return value === null ? null : decodeDelegatedNativeProfile(value, name);
  };
  const requiredProfile = async (name: string, context: DelegatedFamilyContext) => { const value = await selectedProfile(name, context); if (!value) return familyFail('not_found'); return value; };
  const publishProfile = async (previous: DelegatedNativeProfileRecord | null, next: DelegatedNativeProfileRecord, context: DelegatedFamilyContext) => {
    effect(context); const result = await snapshots.publish(profileKey(next.name), previous?.revision ?? null, next, context); check(context);
    if (result !== 'committed') return familyFail('metadata_unknown', true); return next;
  };
  const nextProfile = (previous: DelegatedNativeProfileRecord, changes: Partial<DelegatedNativeProfileRecord>) => {
    const revision = fresh(); if (revision === previous.revision || revision === previous.attempt?.attemptId) return familyFail('invalid_state');
    return decodeDelegatedNativeProfile({ ...previous, ...changes, revision }, previous.name);
  };
  const readSecret = (reference: DelegatedNativeSecretReference, context: DelegatedFamilyContext): string | null => {
    check(context); const value = credentials.readCredential(delegatedNativeSecretReference(reference)); check(context);
    const item = familyObject(value, ['status'], ['secret']);
    if (item.status === 'absent' && !Object.hasOwn(item, 'secret')) return null;
    if (item.status !== 'present') return familyFail('store_unknown', true); return delegatedNativeSecret(reference, item.secret);
  };
  const writeSecret = (reference: DelegatedNativeSecretReference, value: string, context: DelegatedFamilyContext) => {
    effect(context); const result = credentials.writeCredential(reference, delegatedNativeSecret(reference, value)); check(context);
    if (result !== 'stored' || readSecret(reference, context) !== value) return familyFail('store_unknown', true);
  };
  const discardSecret = (reference: DelegatedNativeSecretReference, context: DelegatedFamilyContext) => {
    if (readSecret(reference, context) === null) return; effect(context); const result = credentials.deleteCredential(reference); check(context);
    if (!['deleted', 'absent'].includes(result) || readSecret(reference, context) !== null) return familyFail('store_unknown', true);
  };
  const relatedFamily = async (record: DelegatedNativeProfileRecord, key: DelegatedFamilyKey, context: DelegatedFamilyContext) => {
    check(context); const value = await snapshots.readRelatedFamily(record.name, key, context); check(context);
    return value === null ? null : decodeDelegatedFamilySnapshot(value, key);
  };
  const familyTicket = (key: DelegatedFamilyKey, context: DelegatedFamilyContext) => {
    const selected = delegatedFamilyKey(key), ticket = check(context);
    if (!ticket.key || ticket.key.kind !== 'family' || !sameKey(ticket.key.key, selected)) return familyFail('binding_mismatch'); return ticket;
  };
  const familyReference = (reference: DelegatedRefreshReference, context: DelegatedFamilyContext): DelegatedNativeSecretReference => {
    const ticket = check(context); if (!ticket.key || ticket.key.kind !== 'family' || !ticket.family) return familyFail('binding_mismatch');
    // Parse by exact matching the canonical decoder's owned reference set.
    const value = familyObject(reference, ['namespace', 'storeId', 'localFamilyId', 'credentialId', 'localGeneration']);
    const found = familyReferences(ticket.family).find(item => Object.keys(value).every(key => value[key] === item[key as keyof DelegatedRefreshReference]));
    if (!found) return familyFail('binding_mismatch');
    return delegatedNativeSecretReference({ kind: 'family-refresh', ownerId: found.localFamilyId, credentialId: found.credentialId, localGeneration: found.localGeneration });
  };
  const finishConfirmedCleanup = async (previous: DelegatedNativeProfileRecord, context: DelegatedFamilyContext): Promise<DelegatedNativeProfile> => {
    let record = previous;
    if (!record.attempt || !record.cleanupReceipt || !['cleanup-confirmed', 'removing', 'removed'].includes(record.state)) return familyFail('pending', true);
    const confirmed = delegatedNativeCleanupReceipt(record.cleanupReceipt, record.attempt.attemptId);
    if (record.initial && (confirmed.grantId !== record.initial.grantId || confirmed.familyId !== record.initial.familyId)) return familyFail('binding_mismatch', true);
    const pending = pendingKey(record); if (pending) { const family = await relatedFamily(record, pending, context); if (family && family.state !== 'removed') return familyFail('pending', true); }
    if (record.state === 'removed') return metadata(record);
    if (record.attempt.proof) { discardSecret(record.attempt.proof, context); record = await publishProfile(record, nextProfile(record, { state: 'removing', attempt: { ...record.attempt, proof: null } }), context); }
    if (record.initial?.reference) { discardSecret(record.initial.reference, context); record = await publishProfile(record, nextProfile(record, { state: 'removing', initial: { ...record.initial, reference: null } }), context); }
    return metadata(await publishProfile(record, nextProfile(record, { state: 'removed' }), context));
  };
  const familyPorts: DelegatedNativeRuntime['familyPorts'] = Object.freeze({
    lease: Object.freeze({ runExclusive<T>(key: DelegatedFamilyKey, context: DelegatedFamilyContext, work: () => Promise<T>) {
      const selected = delegatedFamilyKey(key); if (selected.storeId !== DELEGATED_NATIVE_STORE_ID || typeof work !== 'function' || types.isProxy(work)) return Promise.reject(new Error('Delegated family is unavailable.'));
      return own(Object.freeze({ kind: 'family', key: selected }), context, work);
    } }),
    snapshots: Object.freeze({ async load(key: DelegatedFamilyKey, context: DelegatedFamilyContext) {
      const ticket = familyTicket(key, context); ticket.family = undefined; const value = await snapshots.load({ kind: 'family', key }, context); check(context);
      if (value === null) return null; ticket.family = decodeDelegatedFamilySnapshot(value, key); return ticket.family;
    }, async publish(key: DelegatedFamilyKey, expectedRevision: string | null, value: DelegatedFamilySnapshot, context: DelegatedFamilyContext) {
      const ticket = familyTicket(key, context), next = decodeDelegatedFamilySnapshot(value, key); effect(context);
      const result = await snapshots.publish({ kind: 'family', key }, expectedRevision, next, context); check(context);
      if (result === 'committed') ticket.family = next; else ticket.family = undefined; return result;
    } }),
    store: Object.freeze({ id: DELEGATED_NATIVE_STORE_ID,
      async read(ref: DelegatedRefreshReference, context: DelegatedFamilyContext) { const value = readSecret(familyReference(ref, context), context); return value === null ? Object.freeze({ status: 'absent' }) : Object.freeze({ status: 'present', refreshToken: value }); },
      async write(ref: DelegatedRefreshReference, token: string, context: DelegatedFamilyContext) { const selected = familyReference(ref, context); effect(context); const result = credentials.writeCredential(selected, delegatedNativeSecret(selected, token)); check(context); return result; },
      async delete(ref: DelegatedRefreshReference, context: DelegatedFamilyContext) { const selected = familyReference(ref, context); effect(context); const result = credentials.deleteCredential(selected); check(context); return result; },
    }),
  });
  return Object.freeze({ familyPorts,
    reserve(name, deployment, context) { const selected = delegatedNativeName(name), checked = parseDelegatedLoginDeployment(deployment);
      return operation(profileKey(selected), context, async context => { if (await selectedProfile(selected, context)) return familyFail('exists');
        const next = decodeDelegatedNativeProfile({ format: DELEGATED_NATIVE_PROFILE_FORMAT, revision: fresh(), name: selected, deployment: checked,
          state: 'reserved', attempt: null, initial: null, family: null, cleanupReceipt: null }, selected);
        return metadata(await publishProfile(null, next, context)); }); },
    abandonReserved(name, context) { const selected = delegatedNativeName(name); return operation(profileKey(selected), context, async context => {
      const record = await requiredProfile(selected, context);
      if (record.attempt !== null || record.initial !== null || record.family !== null || record.cleanupReceipt !== null || !['reserved', 'removed'].includes(record.state)) return familyFail('pending', true);
      return record.state === 'removed' ? metadata(record) : metadata(await publishProfile(record, nextProfile(record, { state: 'removed' }), context));
    }); },
    load(name, context) { const selected = delegatedNativeName(name); return operation(profileKey(selected), context, async context => { const value = await selectedProfile(selected, context); return value ? metadata(value) : null; }); },
    list(context) { return operation(null, context, async context => { const ticket = check(context); if (ticket.key !== null) return familyFail('binding_mismatch');
      const rows = await snapshots.list(context); check(context); return Object.freeze(rows.map(row => metadata(decodeDelegatedNativeProfile(row, row.name)))); }); },
    retentionPort(name) { const selected = delegatedNativeName(name); return Object.freeze({ retain(binding: DelegatedLoginRecoveryBinding, context: DelegatedFamilyContext) {
      return operation(profileKey(selected), context, async context => {
        let record = await requiredProfile(selected, context); if (record.state !== 'reserved') return familyFail('pending', true);
        const item = familyObject(binding, ['attemptId', 'recoveryVerifier', 'pkceVerifier', 'issuer', 'clientId', 'redirectUri', 'resource', 'grantResources', 'scopes']);
        const proof = encodeDelegatedNativeProof({ recoveryVerifier: item.recoveryVerifier, pkceVerifier: item.pkceVerifier });
        const reference = delegatedNativeSecretReference({ kind: 'attempt-proof', ownerId: item.attemptId, credentialId: fresh() });
        const attempt = delegatedNativeRecoveryMetadata(binding, record.deployment, reference);
        record = await publishProfile(record, nextProfile(record, { state: 'proof-intent', attempt }), context);
        writeSecret(reference, proof, context);
        record = await publishProfile(record, nextProfile(record, { state: 'proof-ready' }), context);
        return Object.freeze({ status: 'retained' as const, attemptId: record.attempt!.attemptId });
      });
    } }); },
    retainInitialRefresh(name) { const selected = delegatedNativeName(name); return (value, context) => operation(profileKey(selected), context, async context => {
      let record = await requiredProfile(selected, context); const item = familyObject(value, ['attemptId', 'refreshToken', 'resource', 'grantId', 'familyId', 'scopes']);
      if (record.state !== 'proof-ready' || !record.attempt || record.attempt.attemptId !== item.attemptId || item.resource !== record.attempt.resource) return familyFail('binding_mismatch', true);
      const reference = delegatedNativeSecretReference({ kind: 'initial-refresh', ownerId: item.attemptId, credentialId: fresh() });
      const secret = delegatedNativeSecret(reference, item.refreshToken);
      const initial = { grantId: item.grantId, familyId: item.familyId, resource: item.resource, scopes: delegatedNativeStrings(item.scopes, record.attempt.scopes), reference };
      record = await publishProfile(record, nextProfile(record, { state: 'refresh-intent', initial: initial as DelegatedNativeProfileRecord['initial'] }), context);
      writeSecret(reference, secret, context); record = await publishProfile(record, nextProfile(record, { state: 'refresh-ready' }), context);
      return Object.freeze({ status: 'retained', attemptId: record.attempt!.attemptId, grantId: record.initial!.grantId, familyId: record.initial!.familyId });
    }); },
    adopt(name, expectedAttemptId, key, context) { const selected = delegatedNativeName(name), requested = delegatedFamilyKey(key);
      return operation(profileKey(selected), context, async context => {
        let record = await requiredProfile(selected, context);
        if (!record.attempt || record.attempt.attemptId !== expectedAttemptId || !record.initial || !['refresh-ready', 'adopting'].includes(record.state)
          || !sameKey(pendingKey(record)!, requested)) return familyFail('binding_mismatch', true);
        const family = await relatedFamily(record, requested, context);
        if (!family || family.state !== 'ready' || family.localGeneration !== 0 || !family.current || family.proof || family.binding.grantId !== record.initial.grantId
          || JSON.stringify(family.deployment) !== JSON.stringify(record.deployment) || !family.binding.grantResourceUris.includes(record.attempt.resource)
          || family.binding.grantResourceUris.some(uri => !record.attempt!.grantResources.includes(uri))
          || family.binding.grantScopes.some(value => !record.attempt!.scopes.includes(value))) return familyFail('binding_mismatch', true);
        if (record.state === 'refresh-ready') {
          const ref = delegatedNativeSecretReference({ kind: 'family-refresh', ownerId: family.current.localFamilyId, credentialId: family.current.credentialId, localGeneration: family.current.localGeneration });
          if (!record.initial.reference || readSecret(record.initial.reference, context) !== readSecret(ref, context) || readSecret(ref, context) === null) return familyFail('store_unknown', true);
          record = await publishProfile(record, nextProfile(record, { state: 'adopting', family: { key: requested, revision: family.revision } }), context);
        } else if (record.family?.revision !== family.revision) return familyFail('binding_mismatch', true);
        if (record.attempt!.proof) { discardSecret(record.attempt!.proof, context); record = await publishProfile(record, nextProfile(record, { attempt: { ...record.attempt!, proof: null } }), context); }
        if (record.initial!.reference) { discardSecret(record.initial!.reference, context); record = await publishProfile(record, nextProfile(record, { initial: { ...record.initial!, reference: null } }), context); }
        return metadata(await publishProfile(record, nextProfile(record, { state: 'ready' }), context));
      }); },
    readRecovery(name, expectedAttemptId, context) { const selected = delegatedNativeName(name); return operation(profileKey(selected), context, async context => {
      const record = await requiredProfile(selected, context); if (!record.attempt?.proof || record.attempt.attemptId !== expectedAttemptId || ['ready', 'removed'].includes(record.state)) return familyFail('pending', true);
      const proof = readSecret(record.attempt.proof, context); if (!proof) return familyFail('store_absent', true); return recoverDelegatedNativeBinding(record, decodeDelegatedNativeProof(proof));
    }); },
    confirmCleanup(name, expectedAttemptId, receipt, context) { const selected = delegatedNativeName(name); return operation(profileKey(selected), context, async context => {
      let record = await requiredProfile(selected, context); if (!record.attempt || record.attempt.attemptId !== expectedAttemptId || ['ready', 'adopting'].includes(record.state)) return familyFail('binding_mismatch', true);
      const confirmed = delegatedNativeCleanupReceipt(receipt, expectedAttemptId);
      if (record.initial && (confirmed.grantId !== record.initial.grantId || confirmed.familyId !== record.initial.familyId)) return familyFail('binding_mismatch', true);
      const pending = pendingKey(record); if (pending) { const family = await relatedFamily(record, pending, context); if (family && family.state !== 'removed') return familyFail('pending', true); }
      if (record.state === 'removed') { if (JSON.stringify(record.cleanupReceipt) !== JSON.stringify(confirmed)) return familyFail('binding_mismatch'); return metadata(record); }
      if (record.cleanupReceipt && JSON.stringify(record.cleanupReceipt) !== JSON.stringify(confirmed)) return familyFail('binding_mismatch', true);
      if (!record.cleanupReceipt) record = await publishProfile(record, nextProfile(record, { state: 'cleanup-confirmed', family: null, cleanupReceipt: confirmed }), context);
      return finishConfirmedCleanup(record, context);
    }); },
    resumeCleanup(name, context) { const selected = delegatedNativeName(name); return operation(profileKey(selected), context, async context => finishConfirmedCleanup(await requiredProfile(selected, context), context)); },
    finalizeRemoval(name, expectedFamilyKey, context) { const selected = delegatedNativeName(name), expected = delegatedFamilyKey(expectedFamilyKey); return operation(profileKey(selected), context, async context => {
      const record = await requiredProfile(selected, context); if (!record.family || !sameKey(record.family.key, expected) || !['ready', 'removed'].includes(record.state)) return familyFail('binding_mismatch', true);
      const family = await relatedFamily(record, expected, context); if (!family || family.state !== 'removed' || familyReferences(family).length !== 0) return familyFail('pending', true);
      if (record.state === 'removed' && record.family.revision === family.revision) return metadata(record);
      return metadata(await publishProfile(record, nextProfile(record, { state: 'removed', family: { key: expected, revision: family.revision } }), context));
    }); },
    close() { if (closePromise) return closePromise;
      let done!: () => void, rejected!: (error: unknown) => void;
      closePromise = new Promise<void>((resolve, reject) => { done = resolve; rejected = reject; });
      closed = true; for (const controller of controllers) nativeAbort.call(controller);
      void (async () => { while (jobs.size) await Promise.allSettled([...jobs]); try { lease.close(); } catch { return familyFail('lease_failed', true); } scope.disable(); })().then(done, rejected);
      return closePromise; },
  } satisfies DelegatedNativeRuntime);
}

/** Single new-format canonical location; no root/env/fallback/migration option. */
export async function createWindowsDelegatedNativeRuntime(context: DelegatedFamilyContext): Promise<DelegatedNativeRuntime> {
  const guard = parentGuard(context); guard(); qualifyWindowsSnapshotRuntime(); guard(); let lease: WindowsNativeLease | undefined;
  try {
    const root = await getWindowsDelegatedRoot(context); guard(); lease = await openWindowsNativeLease(root, context); guard();
    const credentials = await createWindowsDelegatedCredentialApi(); guard();
    const snapshots = new DelegatedNativeSnapshots(await createWindowsDelegatedSnapshotGuard(lease)); guard();
    return createDelegatedNativeRuntimeForTrustedPorts({ lease, snapshots, credentials });
  } catch (error) { if (lease) { try { lease.close(); } catch { return familyFail('lease_failed', true); } }
    const known = delegatedFamilyFailure(error); return familyFail(known?.code ?? 'operation_failed', known?.recoveryRequired === true); }
}
