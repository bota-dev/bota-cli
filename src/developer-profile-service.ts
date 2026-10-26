/** Explicit named delegated sessions. This coordinator never chooses endpoints
 * from an environment variable, legacy config or saved profile metadata. */
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { startRecoverableDelegatedLoginAttempt, readDelegatedLoginRecoveryBinding, parseDelegatedLoginDeployment,
  type DelegatedLoginDeployment, type DelegatedLoginSelection } from './delegated-login.js';
import { createDelegatedHttpAdapterForTrustedPorts, type DelegatedIdentityVerifier } from './delegated-http.js';
import { createDelegatedRestIdentityVerifierForTrustedPorts } from './delegated-rest-identity-http.js';
import { createDelegatedMcpIdentityVerifierForTrustedPorts } from './delegated-mcp-identity-http.js';
import { DelegatedFamilyEngine, createTrustedDelegatedEnrollmentHandoff, createTrustedDelegatedRevocationHandoff, type DelegatedFamilyContext } from './delegated-family-engine.js';
import { familyObject, familyArray, familyUuid, familySeconds, familyKeyOf, delegatedFamilyKey, delegatedFamilyFailure, delegatedScopes,
  type DelegatedFamilyKey } from './delegated-family-state.js';
import { bindDelegatedInvocationForTrustedPorts } from './delegated-invocation.js';
import type { DelegatedNativeRuntime, DelegatedNativeProfile } from './delegated-native-runtime.js';
import { DELEGATED_NATIVE_MAX_RECORDS } from './delegated-native-contract.js';
import { DeveloperProfileError, sanitizeDeveloperProfileError, developerProfileFailure } from './developer-profile-error.js';
import { bufferDeveloperCommandOutput } from './developer-command-output.js';
import { isKnownDeveloperDeployment } from './developer-deployment-selection.js';

export interface DeveloperProfileOptions { readonly signal?: AbortSignal; readonly timeoutMs?: number }
export interface DeveloperProfileServicePorts {
  getDeployment(): unknown;
  createRuntime(context: DelegatedFamilyContext): Promise<DelegatedNativeRuntime>;
  openBrowser(url: string, context: DelegatedFamilyContext): Promise<void>;
  readonly fetch: typeof fetch;
  writeOutput(channel: 'stdout' | 'stderr', text: string): Promise<void>;
  /** Explicit resource-aware fixture seam; production supplies the real HTTP
   * verifiers below. No command/environment input can replace this port. */
  readonly verifyAccess?: DelegatedIdentityVerifier;
}
type Kind = 'rest' | 'mcp';
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const maximumOutput = 64 * 1024 * 1024;
function fail(code: ConstructorParameters<typeof DeveloperProfileError>[0] = 'developer_operation_failed', recovery = false, effect = false): never {
  throw new DeveloperProfileError(code, recovery, effect);
}
function nameOf(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z0-9-]{1,64}$/.test(value)) fail('developer_profile_invalid'); return value;
}
function loginSelection(input: unknown, deployment: DelegatedLoginDeployment): DelegatedLoginSelection {
  const value = familyObject(input, ['resourceKind', 'grantResourceKinds', 'scopes', 'loopbackHost']);
  const kinds = familyArray(value.grantResourceKinds, 2), scopes = familyArray(value.scopes, delegatedScopes.length);
  if (!['rest', 'mcp'].includes(value.resourceKind as string) || !kinds.includes(value.resourceKind) || kinds.length < 1
    || new Set(kinds).size !== kinds.length || kinds.some(kind => !deployment.client.resourceKinds.includes(kind as Kind))
    || new Set(scopes).size !== scopes.length || scopes.some(scope => !delegatedScopes.includes(scope as string))
    || !['127.0.0.1', '::1'].includes(value.loopbackHost as string)
    || !deployment.client.redirectUris.includes(value.loopbackHost === '127.0.0.1' ? 'http://127.0.0.1/oauth/callback' : 'http://[::1]/oauth/callback')) fail('developer_profile_invalid');
  return Object.freeze({ resourceKind: value.resourceKind as Kind, grantResourceKinds: Object.freeze(kinds as Kind[]),
    scopes: Object.freeze(scopes as DelegatedLoginSelection['scopes'][number][]), loopbackHost: value.loopbackHost as DelegatedLoginSelection['loopbackHost'] });
}
function checkedProfile(value: unknown, name: string, deployment: DelegatedLoginDeployment): DelegatedNativeProfile {
  const item = familyObject(value, ['name', 'state', 'attemptId', 'familyKey', 'pendingFamilyKey', 'deployment']);
  if (item.name !== name || !['reserved', 'proof-intent', 'proof-ready', 'refresh-intent', 'refresh-ready', 'adopting', 'ready', 'cleanup-confirmed', 'removing', 'removed'].includes(item.state as string)
    || item.attemptId !== null && !familyUuid(item.attemptId)
    || JSON.stringify(parseDelegatedLoginDeployment(item.deployment)) !== JSON.stringify(deployment)) fail('developer_profile_invalid');
  const familyKey = item.familyKey === null ? null : delegatedFamilyKey(item.familyKey);
  const pendingFamilyKey = item.pendingFamilyKey === null ? null : delegatedFamilyKey(item.pendingFamilyKey);
  for (const key of [familyKey, pendingFamilyKey]) if (key && (key.issuer !== deployment.issuer || key.clientId !== deployment.client.clientId)) fail('developer_profile_invalid');
  if (item.state === 'ready' && !familyKey) fail('developer_profile_invalid');
  return Object.freeze({ name, state: item.state as DelegatedNativeProfile['state'], attemptId: item.attemptId as string | null,
    familyKey, pendingFamilyKey, deployment });
}
function safeFailure(error: unknown, effect: boolean): DeveloperProfileError {
  if (developerProfileFailure(error)) return sanitizeDeveloperProfileError(error, effect, effect);
  const family = delegatedFamilyFailure(error);
  const code = family?.code === 'cancelled' ? 'developer_cancelled' : family?.code === 'deadline' ? 'developer_deadline'
    : family?.code === 'exists' ? 'developer_profile_exists' : family?.code === 'not_found' ? 'developer_profile_missing'
      : family?.recoveryRequired ? 'developer_recovery_required' : 'developer_operation_failed';
  return new DeveloperProfileError(code, effect || family?.recoveryRequired === true, effect);
}

/** Portable orchestration tests inject trusted ports; this never qualifies
 * those ports as OS persistence, native locking, production TLS or a browser. */
export function createDeveloperProfileServiceForTrustedPorts(input: DeveloperProfileServicePorts) {
  const captured = familyObject(input, ['getDeployment', 'createRuntime', 'openBrowser', 'fetch', 'writeOutput'], ['verifyAccess']);
  for (const key of ['getDeployment', 'createRuntime', 'openBrowser', 'fetch', 'writeOutput'])
    if (typeof captured[key] !== 'function' || types.isProxy(captured[key])) fail('developer_profile_invalid');
  if (captured.verifyAccess !== undefined && (typeof captured.verifyAccess !== 'function' || types.isProxy(captured.verifyAccess))) fail('developer_profile_invalid');
  const ports = Object.freeze(captured) as unknown as DeveloperProfileServicePorts;
  const configuration = () => { try { return parseDelegatedLoginDeployment(ports.getDeployment()); } catch { return fail('developer_configuration_unavailable'); } };

  async function operation<T>(options: DeveloperProfileOptions, work: (state: {
    context: DelegatedFamilyContext; deployment: DelegatedLoginDeployment; runtime: DelegatedNativeRuntime;
    markEffect(): void; selected(name: string): Promise<DelegatedNativeProfile>;
    engine(name: string): { engine: DelegatedFamilyEngine; http: ReturnType<typeof createDelegatedHttpAdapterForTrustedPorts> };
  }) => Promise<T>, afterClose?: (result: T, check: () => void, signal: AbortSignal) => Promise<void>, beforeNative?: (deployment: DelegatedLoginDeployment) => void): Promise<T> {
    const values = familyObject(options, [], ['signal', 'timeoutMs']);
    const parent = values.signal as AbortSignal | undefined;
    if (parent !== undefined) try { if (types.isProxy(parent)) fail('developer_profile_invalid'); aborted.call(parent); } catch { fail('developer_profile_invalid'); }
    const timeout = values.timeoutMs ?? 120_000;
    if (!Number.isSafeInteger(timeout) || (timeout as number) < 1 || (timeout as number) > 300_000) fail('developer_profile_invalid');
    // Configuration must fail before any native directory, listener or browser.
    const deployment = configuration();
    beforeNative?.(deployment);
    const controller = new AbortController(), deadline = performance.now() + (timeout as number);
    let live = true, expired = false, effect = false, expiry: number | undefined, runtime: DelegatedNativeRuntime | undefined;
    const stop = () => controller.abort();
    const timer = setTimeout(() => { expired = true; stop(); }, timeout as number);
    if (parent) EventTarget.prototype.addEventListener.call(parent, 'abort', stop, { once: true });
    const check = () => {
      if (!live) fail('developer_operation_failed', effect, effect);
      if (expired || performance.now() >= deadline || expiry !== undefined && Math.floor(Date.now() / 1000) >= expiry) fail('developer_deadline', effect, effect);
      if (aborted.call(controller.signal) || parent && aborted.call(parent)) fail('developer_cancelled', effect, effect);
    };
    const context = Object.freeze({ signal: controller.signal, budget: Object.freeze({ assertActive: check }) });
    let result: T | undefined, failed = false, failure: unknown;
    try {
      check(); runtime = await ports.createRuntime(context); check();
      const owned = runtime;
      const selected = async (name: string) => { check(); const profile = await owned.load(name, context); check();
        if (profile === null) fail('developer_profile_missing'); return checkedProfile(profile, name, deployment); };
      const engine = (name: string) => {
        const rest = createDelegatedRestIdentityVerifierForTrustedPorts(deployment, { identityUrl: deployment.resources.rest + '/auth/delegated-identity' }, { fetch: ports.fetch });
        const mcp = createDelegatedMcpIdentityVerifierForTrustedPorts(deployment, { fetch: ports.fetch });
        const verify: DelegatedIdentityVerifier = async (selectedDeployment, access, resource, current) => {
          const value = await (ports.verifyAccess ?? (resource === deployment.resources.rest ? rest : resource === deployment.resources.mcp ? mcp : (() => fail('developer_profile_invalid'))))(selectedDeployment, access, resource, current);
          check(); const facts = familyObject(value, ['issuer', 'clientId', 'userId', 'organizationId', 'projectId', 'grantId', 'familyId', 'grantResourceUris', 'grantScopes', 'resource', 'accessScopes', 'expiresAtSeconds']);
          if (!familySeconds(facts.expiresAtSeconds)) fail('developer_operation_failed');
          expiry = expiry === undefined ? facts.expiresAtSeconds : Math.min(expiry, facts.expiresAtSeconds);
          return value;
        };
        const http = createDelegatedHttpAdapterForTrustedPorts(deployment, { fetch: ports.fetch, verifyAccess: verify, retainInitialRefresh: owned.retainInitialRefresh(name) });
        return { http, engine: new DelegatedFamilyEngine({ ...owned.familyPorts, verifyAccess: http.verifyAccess,
          exchange: http.exchange, revoke: http.revoke, nowSeconds: () => Math.floor(Date.now() / 1000) }) };
      };
      try { result = await work({ context, deployment, runtime: owned, selected, engine, markEffect() { effect = true; } }); }
      catch (error) { failed = true; failure = error; }
      try { await owned.close(); runtime = undefined; }
      catch { runtime = undefined; failed = true; failure = new DeveloperProfileError('developer_recovery_required', true, effect); }
      check();
      if (failed) throw failure;
      if (afterClose) try { await afterClose(result as T, check, context.signal); }
      catch (error) { check(); throw error; }
      check(); return result as T;
    } catch (error) { throw safeFailure(error, effect); }
    finally {
      // A partially constructed/opened runtime is still joined on every path.
      let cleanupFailed = false;
      if (runtime) { try { await runtime.close(); } catch { cleanupFailed = true; } }
      live = false; controller.abort(); clearTimeout(timer);
      if (parent) EventTarget.prototype.removeEventListener.call(parent, 'abort', stop);
      if (cleanupFailed) fail('developer_recovery_required', true, effect);
    }
  }

  const keyFor = (profile: DelegatedNativeProfile): DelegatedFamilyKey => {
    if (profile.state !== 'ready' || !profile.familyKey) fail('developer_recovery_required', true); return profile.familyKey;
  };
  const cleanupFamily = async (engine: DelegatedFamilyEngine, key: DelegatedFamilyKey, context: DelegatedFamilyContext, explicitRecovery: boolean) => {
    let snapshot = await engine.inspect(key, context); if (!snapshot) fail('developer_recovery_required', true);
    if (snapshot.state === 'removed') return;
    if (snapshot.state === 'removing') { if (!explicitRecovery) fail('developer_recovery_required', true); await engine.recoverRemoval(key, context); return; }
    if (snapshot.state === 'revoking') { if (!explicitRecovery) fail('developer_recovery_required', true); snapshot = await engine.recoverRevocation(key, context); }
    else if (snapshot.state !== 'revoked') snapshot = await engine.revoke(key, context);
    if (snapshot.state !== 'revoked') fail('developer_recovery_required', true); await engine.remove(key, context);
  };
  return Object.freeze({
    configuration,
    login(nameInput: string, selection: DelegatedLoginSelection, options: DeveloperProfileOptions = {}) {
      const name = nameOf(nameInput); let requested: DelegatedLoginSelection;
      return operation(options, async state => {
        const { context, deployment, runtime } = state; state.markEffect();
        checkedProfile(await runtime.reserve(name, deployment, context), name, deployment);
        const attempt = await startRecoverableDelegatedLoginAttempt(deployment, requested, runtime.retentionPort(name), { signal: context.signal });
        let completed = false;
        try {
          context.budget.assertActive(); await ports.openBrowser(attempt.authorizationUrl, context); context.budget.assertActive();
          await attempt.result; context.budget.assertActive();
          const { engine, http } = state.engine(name), pair = await http.exchangeCode(attempt, context);
          const snapshot = await engine.enroll(createTrustedDelegatedEnrollmentHandoff(deployment, async () => pair), context);
          const proof = readDelegatedLoginRecoveryBinding(attempt);
          const profile = checkedProfile(await runtime.adopt(name, proof.attemptId, familyKeyOf(snapshot), context), name, deployment);
          if (profile.state !== 'ready') fail('developer_enrollment_unknown', true, true);
          completed = true; return profile;
        } finally {
          await attempt.cancel();
          // Failure never retries code exchange, overwrites a name or discards
          // retained proof/refresh state. Explicit recover owns the next step.
          if (!completed) context.budget.assertActive();
        }
      }, undefined, deployment => { requested = loginSelection(selection, deployment); });
    },
    inspect(nameInput: string, options: DeveloperProfileOptions = {}) { const name = nameOf(nameInput); return operation(options, state => state.selected(name)); },
    list(options: DeveloperProfileOptions = {}) { return operation(options, async state => {
      const values = familyArray(await state.runtime.list(state.context), DELEGATED_NATIVE_MAX_RECORDS);
      const names = new Set<string>(), selected = JSON.stringify(state.deployment);
      // Validate the whole metadata inventory before omitting a known foreign
      // deployment. Unknown or malformed records never disappear through filter.
      const profiles = values.map(value => {
        const fields = familyObject(value, ['name', 'state', 'attemptId', 'familyKey', 'pendingFamilyKey', 'deployment']);
        const name = nameOf(fields.name); if (names.has(name)) fail('developer_profile_invalid'); names.add(name);
        return checkedProfile(value, name, parseDelegatedLoginDeployment(fields.deployment));
      });
      return Object.freeze(profiles.filter(profile => {
        if (JSON.stringify(profile.deployment) === selected) return true;
        if (!isKnownDeveloperDeployment(profile.deployment)) fail('developer_profile_invalid');
        return false;
      }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    }); },
    status(nameInput: string, options: DeveloperProfileOptions = {}) { const name = nameOf(nameInput); return operation(options, async state => {
      const profile = await state.selected(name), key = keyFor(profile), { engine } = state.engine(name); state.markEffect();
      return engine.withAccess(key, state.deployment.resources.rest, state.context, async access => Object.freeze({ profile: name, credential_type: 'developer_delegation', ...access.identity }));
    }); },
    async run<T>(nameInput: string, kind: Kind, action: () => Promise<T>, options: DeveloperProfileOptions = {}, expected?: DelegatedFamilyKey): Promise<T> {
      const name = nameOf(nameInput); if (!['rest', 'mcp'].includes(kind)) fail('developer_profile_invalid');
      const captured = await operation(options, async state => {
        const profile = await state.selected(name), key = keyFor(profile);
        if (expected && JSON.stringify(key) !== JSON.stringify(delegatedFamilyKey(expected))) fail('developer_profile_invalid');
        const { engine } = state.engine(name); state.markEffect();
        const binding = await bindDelegatedInvocationForTrustedPorts(engine, key, state.deployment, state.context, { fetch: ports.fetch });
        return binding.run(kind, state.context, () => kind === 'rest' ? bufferDeveloperCommandOutput(action, maximumOutput)
          : action().then(value => ({ value, publish: async () => {} })));
      }, async (result, check, signal) => result.publish(check, ports.writeOutput, signal));
      return captured.value;
    },
    pin(nameInput: string, options: DeveloperProfileOptions = {}) { const name = nameOf(nameInput); return operation(options, async state => keyFor(await state.selected(name))); },
    logout(nameInput: string, options: DeveloperProfileOptions = {}) { const name = nameOf(nameInput); return operation(options, async state => {
      const profile = await state.selected(name), key = keyFor(profile), { engine } = state.engine(name); state.markEffect();
      await cleanupFamily(engine, key, state.context, false);
      return checkedProfile(await state.runtime.finalizeRemoval(name, key, state.context), name, state.deployment);
    }); },
    recover(nameInput: string, options: DeveloperProfileOptions = {}) { const name = nameOf(nameInput); return operation(options, async state => {
      const profile = await state.selected(name);
      if (profile.state === 'removed') return profile;
      state.markEffect();
      if (profile.state === 'reserved') return checkedProfile(await state.runtime.abandonReserved(name, state.context), name, state.deployment);
      if (profile.state === 'cleanup-confirmed' || profile.state === 'removing')
        return checkedProfile(await state.runtime.resumeCleanup(name, state.context), name, state.deployment);
      const { engine, http } = state.engine(name);
      if (profile.attemptId && (profile.state === 'adopting' || profile.state === 'refresh-ready')) {
        const candidate = profile.familyKey ?? profile.pendingFamilyKey;
        const snapshot = candidate ? await engine.inspect(candidate, state.context) : null;
        if (candidate && snapshot?.state === 'ready' && snapshot.localGeneration === 0) {
          // The native adopter verifies the exact durable generation0 family,
          // retained first refresh and deletion journal. No exchange is rerun.
          return checkedProfile(await state.runtime.adopt(name, profile.attemptId, candidate, state.context), name, state.deployment);
        }
        if (profile.state === 'adopting') fail('developer_recovery_required', true, true);
      }
      if (profile.attemptId && ['proof-intent', 'proof-ready', 'refresh-intent', 'refresh-ready'].includes(profile.state)) {
        const proof = await state.runtime.readRecovery(name, profile.attemptId, state.context);
        const key = profile.familyKey ?? profile.pendingFamilyKey;
        let receipt: Awaited<ReturnType<typeof http.revokeEnrollmentAttempt>> | undefined;
        if (key) {
          const snapshot = await engine.inspect(key, state.context);
          if (snapshot) {
            const confirmed = await engine.acceptConfirmedRevocation(key, createTrustedDelegatedRevocationHandoff(state.deployment, profile.attemptId,
              async context => { receipt = await http.revokeEnrollmentAttempt(proof, context); return receipt; }), state.context);
            if (confirmed.state === 'removing') await engine.recoverRemoval(key, state.context);
            else if (confirmed.state !== 'removed') await engine.remove(key, state.context);
          }
        }
        if (receipt === undefined) receipt = await http.revokeEnrollmentAttempt(proof, state.context);
        if (!receipt || typeof receipt !== 'object') fail('developer_recovery_required', true, true);
        return checkedProfile(await state.runtime.confirmCleanup(name, profile.attemptId, receipt, state.context), name, state.deployment);
      }
      const key = profile.familyKey; if (!key) fail('developer_recovery_required', true);
      await cleanupFamily(engine, key, state.context, true);
      return checkedProfile(await state.runtime.finalizeRemoval(name, key, state.context), name, state.deployment);
    }); },
  });
}
export type DeveloperProfileService = ReturnType<typeof createDeveloperProfileServiceForTrustedPorts>;
