/** Inactive adapter-neutral T09 engine. Ports are trusted assembly seams, not
 * production adapters. No HTTP, filesystem, credential store or lock is opened. */
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { parseDelegatedLoginDeployment, type DelegatedLoginDeployment } from './delegated-login.js';
import { DELEGATED_FAMILY_FORMAT, DELEGATED_REFRESH_NAMESPACE, DelegatedFamilyError, decodeDelegatedFamilySnapshot,
  delegatedFamilyFailure, delegatedFamilyIdentity, delegatedFamilyKey, delegatedScopes, encodeDelegatedFamilySnapshot, familyFail,
  familyKeyOf, familyObject, familyReferences, familySeconds, familyServerUuid, familyStrings, familyUuid, sameFamilySet,
  sameRefreshReference, type DelegatedFamilyIdentity, type DelegatedFamilyKey, type DelegatedFamilySnapshot,
  type DelegatedRefreshReference } from './delegated-family-state.js';

export interface DelegatedFamilyContext { readonly signal: AbortSignal; readonly budget: { assertActive(): void } }
export interface DelegatedTokenPair {
  readonly accessToken: string; readonly refreshToken: string; readonly resource: string; readonly expiresAtSeconds: number;
  readonly grantId: string; readonly familyId: string; readonly scopes: readonly string[];
}
export interface DelegatedVerifiedAccess extends DelegatedFamilyIdentity {
  readonly resource: string; readonly accessScopes: readonly string[]; readonly expiresAtSeconds: number;
}
export interface DelegatedRevocationBinding { readonly grantId: string; readonly familyId: string }
export interface DelegatedFamilyPorts {
  readonly store: {
    readonly id: string;
    /** Exact delegated namespace+family+generation+credential marker required.
     * Create only: refuse collision, never enumerate, adopt or overwrite. */
    read(ref: DelegatedRefreshReference, context: DelegatedFamilyContext): Promise<unknown>;
    write(ref: DelegatedRefreshReference, refreshToken: string, context: DelegatedFamilyContext): Promise<'stored' | 'not_stored' | 'unknown'>;
    delete(ref: DelegatedRefreshReference, context: DelegatedFamilyContext): Promise<'deleted' | 'absent' | 'not_deleted' | 'unknown'>;
  };
  readonly snapshots: {
    load(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<unknown>;
    /** Atomic durable entire-family CAS. No cross-resource/profile alias rows. */
    publish(key: DelegatedFamilyKey, expectedRevision: string | null, next: DelegatedFamilySnapshot,
      context: DelegatedFamilyContext): Promise<'committed' | 'not_committed' | 'unknown'>;
  };
  readonly lease: {
    /** Same store+issuer+client+SERVER FAMILY across all resources/processes.
     * Exclusive process-lifetime ownership held through every awaited port and
     * caller action, and joined release before returning. PID/age/directory and
     * mocked mutexes do not qualify native cross-process locking. */
    runExclusive<T>(key: DelegatedFamilyKey, context: DelegatedFamilyContext, work: () => Promise<T>): Promise<T>;
  };
  /** Authoritative current identity/scopes/family admission, not decoded token
   * claims, a requested resource set, a profile label or a public copied DTO. */
  verifyAccess(deployment: DelegatedLoginDeployment, accessToken: string, resource: string, context: DelegatedFamilyContext): Promise<unknown>;
  exchange(deployment: DelegatedLoginDeployment, refreshToken: string, resource: string, context: DelegatedFamilyContext): Promise<unknown>;
  /** Trusted definitive commit confirmation for the expected grant/family and
   * exact current/consumed proof. Ordinary RFC7009 empty200 is unknown, never a
   * confirmation. A future HTTP adapter must verify its configured endpoint and
   * explicit bound confirmation before normalizing these two IDs. Only explicit
   * recovery may repeat this operation; no HTTP adapter is implemented here. */
  revoke(deployment: DelegatedLoginDeployment, refreshToken: string, expected: DelegatedRevocationBinding,
    context: DelegatedFamilyContext): Promise<DelegatedRevocationBinding | 'unknown' | 'not_submitted'>;
  nowSeconds(): number;
  newId?(): string;
}
export interface DelegatedEnrollmentHandoff { readonly stage: 'trusted-definitive-exchange-handoff' }
const handoffs = new WeakMap<DelegatedEnrollmentHandoff, { deployment: DelegatedLoginDeployment; receive: (context: DelegatedFamilyContext) => Promise<unknown>; used: boolean }>();
/** TRUSTED TRANSPORT ASSEMBLY ONLY. Receive must deliver a definitively received
 * first code-exchange pair, never perform/retry an exchange on consumption.
 * The opaque one-use handle is not authority; verifyAccess remains mandatory. */
export function createTrustedDelegatedEnrollmentHandoff(deployment: unknown,
  receive: (context: DelegatedFamilyContext) => Promise<unknown>): DelegatedEnrollmentHandoff {
  try {
    if (typeof receive !== 'function' || types.isProxy(receive)) familyFail('invalid_input');
    const checked = parseDelegatedLoginDeployment(deployment), handle = Object.freeze({ stage: 'trusted-definitive-exchange-handoff' as const });
    handoffs.set(handle, { deployment: checked, receive, used: false }); return handle;
  } catch { return familyFail('invalid_input'); }
}
function credential(kind: 'access' | 'refresh', value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 52 || !value.startsWith(kind === 'access' ? 'bota_da1_' : 'bota_dr1_')) return false;
  const tail = value.slice(9); return /^[A-Za-z0-9_-]{43}$/.test(tail) && Buffer.from(tail, 'base64url').toString('base64url') === tail;
}
function tokens(value: unknown, deployment: DelegatedLoginDeployment, now: number): DelegatedTokenPair {
  const item = familyObject(value, ['accessToken', 'refreshToken', 'resource', 'expiresAtSeconds', 'grantId', 'familyId', 'scopes']);
  if (!credential('access', item.accessToken) || !credential('refresh', item.refreshToken) || !familyServerUuid(item.grantId) || !familyServerUuid(item.familyId)
    || !Object.values(deployment.resources).includes(item.resource as string) || !familySeconds(item.expiresAtSeconds)
    || item.expiresAtSeconds <= now || item.expiresAtSeconds > now + 300) familyFail('identity_failed');
  return Object.freeze({ accessToken: item.accessToken, refreshToken: item.refreshToken, resource: item.resource as string,
    expiresAtSeconds: item.expiresAtSeconds, grantId: item.grantId, familyId: item.familyId, scopes: familyStrings(item.scopes, delegatedScopes) });
}
const identityFields = ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId', 'grantResourceUris', 'grantScopes'];
function identity(value: unknown, deployment: DelegatedLoginDeployment, accessToken: string, resource: string, now: number): DelegatedVerifiedAccess {
  const item = familyObject(value, [...identityFields, 'resource', 'accessScopes', 'expiresAtSeconds']);
  const binding = delegatedFamilyIdentity(Object.fromEntries(identityFields.map(key => [key, item[key]])), deployment);
  const accessScopes = familyStrings(item.accessScopes, binding.grantScopes);
  if (item.resource !== resource || !binding.grantResourceUris.includes(resource) || !familySeconds(item.expiresAtSeconds)
    || item.expiresAtSeconds <= now || item.expiresAtSeconds > now + 300
    || JSON.stringify(binding).includes(accessToken)) familyFail('identity_failed');
  return Object.freeze({ ...binding, resource, accessScopes, expiresAtSeconds: item.expiresAtSeconds });
}
function pinned(actual: DelegatedFamilyIdentity, expected: DelegatedFamilyIdentity): boolean {
  return ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId'].every(key =>
    actual[key as keyof DelegatedFamilyIdentity] === expected[key as keyof DelegatedFamilyIdentity])
    && sameFamilySet(actual.grantResourceUris, expected.grantResourceUris) && sameFamilySet(actual.grantScopes, expected.grantScopes);
}
function confirmedRevocation(value: unknown, expected: DelegatedRevocationBinding): boolean {
  try {
    const receipt = familyObject(value, ['grantId', 'familyId']);
    return familyServerUuid(receipt.grantId) && familyServerUuid(receipt.familyId)
      && receipt.grantId === expected.grantId && receipt.familyId === expected.familyId;
  } catch { return false; }
}
interface Scope { readonly context: DelegatedFamilyContext; assertActive(): void }
type TransientAccess = Pick<DelegatedTokenPair, 'accessToken' | 'resource' | 'expiresAtSeconds' | 'scopes'>;
interface Cache { readonly revision: string; readonly localGeneration: number; readonly pair: TransientAccess }
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const listenAbort = EventTarget.prototype.addEventListener;
const unlistenAbort = EventTarget.prototype.removeEventListener;
const abortChild = AbortController.prototype.abort;

export class DelegatedFamilyEngine {
  private readonly storeId: string;
  private readonly cache = new Map<string, Cache>();
  private readonly contexts = new WeakMap<DelegatedFamilyContext, { check(): void; retire(): void; markEffect(): void }>();
  constructor(private readonly ports: DelegatedFamilyPorts) {
    this.storeId = ports.store.id;
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(this.storeId)) familyFail('invalid_input');
  }
  private check(context: DelegatedFamilyContext): void {
    const guard = this.contexts.get(context); if (!guard) familyFail('invalid_input'); guard.check();
  }
  private markEffect(context: DelegatedFamilyContext): void {
    const guard = this.contexts.get(context); if (!guard) familyFail('invalid_input'); guard.check(); guard.markEffect();
  }
  private async operation<T>(input: DelegatedFamilyContext, work: (context: DelegatedFamilyContext) => Promise<T>): Promise<T> {
    let signal: AbortSignal, budget: DelegatedFamilyContext['budget'], assertion: () => void;
    try {
      const value = familyObject(input, ['signal', 'budget']);
      if (!value.budget || typeof value.budget !== 'object' || types.isProxy(value.budget) || types.isProxy(value.signal)) familyFail('invalid_input');
      const descriptor = Object.getOwnPropertyDescriptor(value.budget, 'assertActive');
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) familyFail('invalid_input');
      aborted.call(value.signal); signal = value.signal as AbortSignal; budget = value.budget as DelegatedFamilyContext['budget']; assertion = descriptor.value;
    } catch { return familyFail('invalid_input'); }
    let retired = false, cancelled = aborted.call(signal) as boolean, effects = false;
    const child = new AbortController();
    const onAbort = () => { cancelled = true; abortChild.call(child, new DelegatedFamilyError('cancelled', effects)); };
    const check = () => {
      if (retired) familyFail('lease_failed', true);
      if (cancelled || aborted.call(signal) || aborted.call(child.signal)) familyFail('cancelled', effects);
      try { assertion.call(budget); } catch { familyFail('deadline', effects); }
    };
    const context = Object.freeze({ signal: child.signal, budget: Object.freeze({ assertActive: check }) });
    const retire = () => { if (!retired) { retired = true; abortChild.call(child, new DelegatedFamilyError('lease_failed', true)); } };
    this.contexts.set(context, { check, retire, markEffect: () => { effects = true; } });
    listenAbort.call(signal, 'abort', onAbort, { once: true });
    if (cancelled) onAbort();
    try { this.check(context); return await work(context); }
    catch (error) {
      const failure = delegatedFamilyFailure(error);
      if (failure) return familyFail(failure.code, effects || failure.recoveryRequired);
      return familyFail('operation_failed', effects);
    }
    finally { retire(); unlistenAbort.call(signal, 'abort', onAbort); this.contexts.delete(context); }
  }
  private now(): number {
    try { const value = this.ports.nowSeconds(); if (!familySeconds(value)) familyFail('invalid_input'); return value; }
    catch { return familyFail('invalid_input'); }
  }
  private remember(key: DelegatedFamilyKey, snapshot: DelegatedFamilySnapshot, pair: DelegatedTokenPair): void {
    const access = Object.freeze({ accessToken: pair.accessToken, resource: pair.resource, expiresAtSeconds: pair.expiresAtSeconds, scopes: pair.scopes });
    this.cache.set(this.cacheKey(key, pair.resource), { revision: snapshot.revision, localGeneration: snapshot.localGeneration, pair: access });
  }
  private cacheKey(key: DelegatedFamilyKey, resource: string): string { return JSON.stringify([key.storeId, key.issuer, key.clientId, key.familyId, resource]); }
  private id(snapshot?: DelegatedFamilySnapshot, extra: readonly string[] = []): string {
    const value = (this.ports.newId ?? randomUUID)();
    const reserved = snapshot ? [snapshot.revision, snapshot.localFamilyId, snapshot.binding.userId, snapshot.binding.grantId,
      snapshot.binding.familyId, ...familyReferences(snapshot).map(ref => ref.credentialId), ...(snapshot.intent ? [snapshot.intent.transactionId] : [])] : [];
    if (!familyUuid(value) || [...reserved, ...extra].includes(value)) familyFail('invalid_state'); return value;
  }
  private async leased<T>(input: DelegatedFamilyKey, context: DelegatedFamilyContext, work: (key: DelegatedFamilyKey, scope: Scope) => Promise<T>): Promise<T> {
    const key = delegatedFamilyKey(input); if (key.storeId !== this.storeId) familyFail('binding_mismatch'); this.check(context);
    let entered = false, active = false, ownerOpen = true, violated = false, owned: Promise<T> | undefined;
    let leaseError: unknown, leaseRejected = false;
    try {
      await this.ports.lease.runExclusive(key, context, () => {
        if (!ownerOpen || entered) {
          violated = true; const denied = Promise.reject<T>(new DelegatedFamilyError('lease_failed', entered));
          void denied.catch(() => undefined); return denied;
        }
        entered = true; active = true;
        const scope = { context, assertActive: () => { if (!active || !ownerOpen) familyFail('lease_failed', true); this.check(context); } };
        owned = (async () => { try { scope.assertActive(); return await work(key, scope); } finally { active = false; } })();
        void owned.catch(() => undefined); return owned;
      });
    } catch (error) { leaseRejected = true; leaseError = error; }
    // Retire before joining a defective lease's already-started callback. A
    // later first callback must not start, and an awaited port cannot resume
    // into another side effect after its owner has observed lease settlement.
    ownerOpen = false; const early = active; active = false;
    if (!entered || early || violated || leaseRejected) this.contexts.get(context)?.retire();
    const settled = owned ? await Promise.allSettled([owned]) : [];
    if (!entered || early || violated) familyFail('lease_failed', entered);
    const completion = settled[0];
    if (leaseRejected) {
      const failure = delegatedFamilyFailure(leaseError);
      if (completion?.status === 'rejected' && leaseError === completion.reason && failure) return familyFail(failure.code, failure.recoveryRequired);
      familyFail('lease_failed', true);
    }
    if (completion?.status === 'rejected') {
      const failure = delegatedFamilyFailure(completion.reason);
      if (failure) return familyFail(failure.code, failure.recoveryRequired); familyFail('lease_failed', true);
    }
    if (!completion || completion.status !== 'fulfilled') familyFail('lease_failed', true);
    this.check(context); return completion.value;
  }
  private async load(key: DelegatedFamilyKey, scope: Scope): Promise<DelegatedFamilySnapshot | null> {
    scope.assertActive(); let value: unknown;
    try { value = await this.ports.snapshots.load(key, scope.context); } catch { return familyFail('metadata_unknown', true); }
    scope.assertActive(); return value === null ? null : decodeDelegatedFamilySnapshot(value, key);
  }
  private async required(key: DelegatedFamilyKey, scope: Scope): Promise<DelegatedFamilySnapshot> {
    const value = await this.load(key, scope); if (!value) familyFail('not_found'); return value;
  }
  private next(previous: DelegatedFamilySnapshot, patch: Partial<DelegatedFamilySnapshot>): DelegatedFamilySnapshot {
    return decodeDelegatedFamilySnapshot({ ...previous, ...patch, revision: this.id(previous) }, familyKeyOf(previous));
  }
  private async publish(key: DelegatedFamilyKey, previous: DelegatedFamilySnapshot | null, next: DelegatedFamilySnapshot, scope: Scope): Promise<DelegatedFamilySnapshot> {
    scope.assertActive(); let result: unknown;
    this.markEffect(scope.context);
    try { result = await this.ports.snapshots.publish(key, previous?.revision ?? null, next, scope.context); }
    catch { return familyFail('metadata_unknown', true); }
    scope.assertActive();
    // An unknown ACK never causes a retry. A future fresh exact ready snapshot
    // may be authoritative; a lost REMOTE response never reaches ready CAS.
    if (result !== 'committed') familyFail('metadata_unknown', true);
    const actual = await this.load(key, scope);
    if (!actual || !Buffer.from(encodeDelegatedFamilySnapshot(actual, key)).equals(Buffer.from(encodeDelegatedFamilySnapshot(next, key)))) familyFail('metadata_unknown', true);
    return actual;
  }
  private async verify(deployment: DelegatedLoginDeployment, pair: Pick<DelegatedTokenPair, 'accessToken' | 'resource' | 'scopes' | 'expiresAtSeconds'>, scope: Scope): Promise<DelegatedVerifiedAccess> {
    scope.assertActive(); let raw: unknown;
    try { raw = await this.ports.verifyAccess(deployment, pair.accessToken, pair.resource, scope.context); }
    catch { return familyFail('identity_failed'); }
    scope.assertActive(); const actual = identity(raw, deployment, pair.accessToken, pair.resource, this.now());
    if (!sameFamilySet(actual.accessScopes, pair.scopes) || actual.expiresAtSeconds !== pair.expiresAtSeconds) familyFail('identity_failed');
    return actual;
  }
  private async read(ref: DelegatedRefreshReference, scope: Scope): Promise<string | null> {
    scope.assertActive(); let raw: unknown;
    try { raw = await this.ports.store.read(ref, scope.context); } catch { return familyFail('store_unknown', true); }
    scope.assertActive();
    const item = familyObject(raw, ['status'], ['refreshToken']);
    if (item.status === 'absent' && !Object.hasOwn(item, 'refreshToken')) return null;
    if (item.status !== 'present' || !credential('refresh', item.refreshToken)) familyFail('store_unknown', true);
    return item.refreshToken;
  }
  private async store(ref: DelegatedRefreshReference, secret: string, scope: Scope): Promise<void> {
    scope.assertActive(); let result: unknown;
    this.markEffect(scope.context);
    try { result = await this.ports.store.write(ref, secret, scope.context); } catch { return familyFail('store_unknown', true); }
    scope.assertActive(); if (result !== 'stored' || await this.read(ref, scope) !== secret) familyFail('store_unknown', true);
  }
  private async discard(ref: DelegatedRefreshReference, scope: Scope): Promise<void> {
    if (await this.read(ref, scope) === null) return;
    scope.assertActive(); let result: unknown;
    this.markEffect(scope.context);
    try { result = await this.ports.store.delete(ref, scope.context); } catch { return familyFail('store_unknown', true); }
    scope.assertActive(); if (!['deleted', 'absent'].includes(result as string) || await this.read(ref, scope) !== null) familyFail('store_unknown', true);
  }
  private ready(snapshot: DelegatedFamilySnapshot, resource?: string): void {
    if (snapshot.state === 'removed') familyFail('removed');
    if (snapshot.state !== 'ready') familyFail('pending', true);
    if (resource !== undefined && !snapshot.binding.grantResourceUris.includes(resource)) familyFail('binding_mismatch');
  }
  async inspect(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot | null> {
    return this.operation(context, context => this.leased(key, context, (key, scope) => this.load(key, scope)));
  }
  async enroll(handoff: DelegatedEnrollmentHandoff, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.enrollPinned(handoff, context));
  }
  private async enrollPinned(handoff: DelegatedEnrollmentHandoff, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    this.check(context); const initial = handoffs.get(handoff); if (!initial || initial.used) familyFail('invalid_input'); initial.used = true;
    let value: unknown;
    try { value = await initial.receive(context); } catch { return familyFail('identity_failed'); }
    this.check(context); const pair = tokens(value, initial.deployment, this.now());
    // The handoff and public token fields alone grant no authority. Verify the
    // actual credential before deriving/entering its canonical family lease.
    const pre = await this.verify(initial.deployment, pair, { context, assertActive: () => this.check(context) });
    if (pair.familyId !== pre.familyId || pair.grantId !== pre.grantId || JSON.stringify(pre).includes(pair.refreshToken)) familyFail('binding_mismatch');
    const key = delegatedFamilyKey({ storeId: this.storeId, issuer: pre.issuer, clientId: pre.clientId, familyId: pre.familyId });
    return this.leased(key, context, async (key, scope) => {
      if (await this.load(key, scope)) familyFail('exists');
      const verified = await this.verify(initial.deployment, pair, scope); if (!pinned(verified, pre)) familyFail('binding_mismatch');
      const localFamilyId = this.id(undefined, [pre.familyId, pre.grantId, pre.userId]), credentialId = this.id(undefined, [localFamilyId]);
      const current = Object.freeze({ namespace: DELEGATED_REFRESH_NAMESPACE, storeId: this.storeId, localFamilyId, credentialId, localGeneration: 0 });
      const snapshot = decodeDelegatedFamilySnapshot({ format: DELEGATED_FAMILY_FORMAT, revision: this.id(undefined, [localFamilyId, credentialId]),
        storeId: this.storeId, localFamilyId, deployment: initial.deployment, binding: Object.fromEntries(identityFields.map(field => [field, pre[field as keyof DelegatedFamilyIdentity]])),
        localGeneration: 0, state: 'enrolling', current, proof: null, cleanup: [], intent: { transactionId: this.id(undefined, [localFamilyId, credentialId]), operation: 'enroll', resource: pair.resource, candidate: null } }, key);
      let state = await this.publish(key, null, snapshot, scope);
      await this.store(current, pair.refreshToken, scope);
      state = await this.publish(key, state, this.next(state, { state: 'ready', intent: null }), scope);
      this.remember(key, state, pair); return state;
    });
  }
  private async finishRotation(key: DelegatedFamilyKey, state: DelegatedFamilySnapshot, scope: Scope): Promise<DelegatedFamilySnapshot> {
    if (state.state !== 'rotating') familyFail('pending', true);
    if (!state.current || await this.read(state.current, scope) === null) familyFail('store_absent', true);
    for (const ref of state.cleanup) await this.discard(ref, scope);
    return this.publish(key, state, this.next(state, { state: 'ready', intent: null, cleanup: [] }), scope);
  }
  private async remoteUnknown(key: DelegatedFamilyKey, state: DelegatedFamilySnapshot, scope: Scope): Promise<never> {
    // The already durable intent is blocking even if cancellation or a second
    // metadata uncertainty prevents publishing this explicit suspended label.
    try { await this.publish(key, state, this.next(state, { state: 'suspended' }), scope); } catch { /* Preserve every exact reference and the original remote uncertainty. */ }
    return familyFail('refresh_unknown', true);
  }
  private async rotate(key: DelegatedFamilyKey, state: DelegatedFamilySnapshot, resource: string, scope: Scope): Promise<DelegatedFamilySnapshot> {
    this.ready(state, resource);
    const refresh = await this.read(state.current!, scope); if (!refresh) familyFail('store_absent');
    const candidate = Object.freeze({ ...state.current!, credentialId: this.id(state), localGeneration: state.localGeneration + 1 });
    state = await this.publish(key, state, this.next(state, { state: 'refreshing', intent: {
      transactionId: this.id(state, [candidate.credentialId]), operation: 'refresh', resource, candidate } }), scope);
    let response: unknown;
    scope.assertActive(); this.markEffect(scope.context);
    try { response = await this.ports.exchange(state.deployment, refresh, resource, scope.context); }
    catch { return this.remoteUnknown(key, state, scope); }
    scope.assertActive(); let pair: DelegatedTokenPair;
    try { pair = tokens(response, state.deployment, this.now()); }
    catch { return this.remoteUnknown(key, state, scope); }
    if (pair.refreshToken === refresh || pair.familyId !== state.binding.familyId || pair.grantId !== state.binding.grantId || pair.resource !== resource) return this.remoteUnknown(key, state, scope);
    const verified = await this.verify(state.deployment, pair, scope);
    if (!pinned(verified, state.binding) || JSON.stringify(verified).includes(pair.refreshToken)) familyFail('binding_mismatch', true);
    await this.store(candidate, pair.refreshToken, scope);
    state = await this.publish(key, state, this.next(state, { state: 'rotating', localGeneration: candidate.localGeneration,
      current: candidate, proof: state.current, cleanup: state.proof ? [state.proof] : [] }), scope);
    state = await this.finishRotation(key, state, scope);
    this.remember(key, state, pair); return state;
  }
  async refresh(key: DelegatedFamilyKey, resource: string, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.rotate(key, await this.required(key, scope), resource, scope)));
  }
  async withAccess<T>(key: DelegatedFamilyKey, resource: string, context: DelegatedFamilyContext,
    work: (access: Readonly<{ accessToken: string; resource: string; identity: DelegatedVerifiedAccess }>) => Promise<T>): Promise<T> {
    if (typeof work !== 'function') familyFail('invalid_input');
    return this.operation(context, context => this.leased(key, context, async (key, scope) => {
      let state = await this.required(key, scope); this.ready(state, resource);
      let cached = this.cache.get(this.cacheKey(key, resource));
      if (!cached || cached.revision !== state.revision || cached.localGeneration !== state.localGeneration || cached.pair.expiresAtSeconds <= this.now()) {
        state = await this.rotate(key, state, resource, scope); cached = this.cache.get(this.cacheKey(key, resource));
      }
      if (!cached) familyFail('pending', true);
      const actual = await this.verify(state.deployment, cached.pair, scope); if (!pinned(actual, state.binding)) familyFail('binding_mismatch');
      scope.assertActive(); let result: T;
      this.markEffect(scope.context);
      try { result = await work(Object.freeze({ accessToken: cached.pair.accessToken, resource, identity: actual })); }
      catch { return familyFail('operation_failed'); }
      scope.assertActive(); return result;
    }));
  }
  async recoverRotation(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.finishRotation(key, await this.required(key, scope), scope)));
  }
  private async revokeLocked(key: DelegatedFamilyKey, state: DelegatedFamilySnapshot, scope: Scope, recovery: boolean): Promise<DelegatedFamilySnapshot> {
    if (state.state === 'removed') familyFail('removed');
    if (state.state === 'revoked') return state;
    if (recovery ? state.state !== 'revoking' : state.state === 'revoking' || state.state === 'removing') familyFail('pending', true);
    if (!recovery) {
      const candidate = state.intent?.candidate;
      const cleanup = [...state.cleanup];
      if (candidate && !familyReferences({ ...state, intent: null }).some(ref => sameRefreshReference(ref, candidate))) cleanup.push(candidate);
      state = await this.publish(key, state, this.next(state, { state: 'revoking', cleanup, intent: {
        transactionId: this.id(state), operation: 'revoke', resource: null, candidate: null } }), scope);
    }
    const proof = state.proof ?? state.current; if (!proof) familyFail('store_absent', true);
    const refresh = await this.read(proof, scope); if (!refresh) familyFail('store_absent', true);
    scope.assertActive(); let result: unknown;
    const expected = Object.freeze({ grantId: state.binding.grantId, familyId: state.binding.familyId });
    this.markEffect(scope.context);
    try { result = await this.ports.revoke(state.deployment, refresh, expected, scope.context); } catch { return familyFail('revocation_unknown', true); }
    scope.assertActive(); if (!confirmedRevocation(result, expected)) familyFail('revocation_unknown', true);
    return this.publish(key, state, this.next(state, { state: 'revoked', intent: null }), scope);
  }
  async revoke(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.revokeLocked(key, await this.required(key, scope), scope, false)));
  }
  async recoverRevocation(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.revokeLocked(key, await this.required(key, scope), scope, true)));
  }
  private async removeLocked(key: DelegatedFamilyKey, state: DelegatedFamilySnapshot, scope: Scope, recovery: boolean): Promise<DelegatedFamilySnapshot> {
    if (state.state === 'removed') return state;
    if (state.state !== (recovery ? 'removing' : 'revoked')) familyFail('pending', true);
    if (!recovery) state = await this.publish(key, state, this.next(state, { state: 'removing', current: null, proof: null,
      cleanup: familyReferences(state), intent: { transactionId: this.id(state), operation: 'remove', resource: null, candidate: null } }), scope);
    while (state.cleanup.length) {
      await this.discard(state.cleanup[0]!, scope);
      state = await this.publish(key, state, this.next(state, { cleanup: state.cleanup.slice(1) }), scope);
    }
    return this.publish(key, state, this.next(state, { state: 'removed', intent: null }), scope);
  }
  async remove(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.removeLocked(key, await this.required(key, scope), scope, false)));
  }
  async recoverRemoval(key: DelegatedFamilyKey, context: DelegatedFamilyContext): Promise<DelegatedFamilySnapshot> {
    return this.operation(context, context => this.leased(key, context, async (key, scope) => this.removeLocked(key, await this.required(key, scope), scope, true)));
  }
}
