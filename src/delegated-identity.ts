/** Inactive parsed-value codec for the backend's delegated identity v1 DTO.
 * This validates data, not authentication. A future resource-aware owner must
 * supply a fresh successful response from its explicitly trusted endpoint and
 * reject duplicate JSON members before calling this parsed-object boundary.
 * No route, request, token, profile, clock or deployment default is selected. */
import { parseDelegatedLoginDeployment } from './delegated-login.js';
import { delegatedFamilyIdentity, delegatedScopes, familyObject, familySeconds,
  familyServerUuid, familyStrings } from './delegated-family-state.js';
import type { DelegatedVerifiedAccess } from './delegated-family-engine.js';

export interface DelegatedIdentityContext {
  readonly deployment: unknown;
  readonly resource: string;
  readonly nowSeconds: number;
  /** Already trusted family identity, if known. This is a consistency check,
   * never authentication. Full existing binding comparison belongs to engine. */
  readonly expectedBinding?: Readonly<{ grantId: string; familyId: string }>;
}
export class DelegatedIdentityError extends Error {
  readonly code = 'identity_response_invalid' as const;
  constructor() { super('Delegated identity response or validation context is invalid.'); this.name = 'DelegatedIdentityError'; }
}
function refuse(): never { throw new DelegatedIdentityError(); }

/** Exact 14-field server projection -> copied, frozen 12-field engine DTO.
 * Grant resources/scopes come only from the response, never requested consent,
 * a profile label or the configured client's full registration. Empty scopes
 * are valid; an expired or more-than-300-second access lifetime is not. */
export function normalizeDelegatedIdentity(value: unknown, context: DelegatedIdentityContext): DelegatedVerifiedAccess {
  try {
    const selected = familyObject(context, ['deployment', 'resource', 'nowSeconds'], ['expectedBinding']);
    const deployment = parseDelegatedLoginDeployment(selected.deployment);
    if (typeof selected.resource !== 'string'
      || !deployment.client.resourceKinds.some(kind => deployment.resources[kind] === selected.resource)
      || !familySeconds(selected.nowSeconds)) refuse();
    let expected: Record<string, unknown> | undefined;
    if (Object.hasOwn(selected, 'expectedBinding')) {
      expected = familyObject(selected.expectedBinding, ['grantId', 'familyId']);
      if (!familyServerUuid(expected.grantId) || !familyServerUuid(expected.familyId)) refuse();
    }
    const item = familyObject(value, ['format_version', 'credential_type', 'issuer', 'client_id', 'user_id',
      'organization_id', 'project_id', 'grant_id', 'family_id', 'resource', 'grant_resources', 'grant_scopes', 'access_scopes', 'expires_at']);
    if (item.format_version !== 1 || item.credential_type !== 'developer_delegation' || item.resource !== selected.resource
      || !familySeconds(item.expires_at) || item.expires_at <= selected.nowSeconds || item.expires_at - selected.nowSeconds > 300
      || expected && (item.grant_id !== expected.grantId || item.family_id !== expected.familyId)) refuse();
    const binding = delegatedFamilyIdentity({ issuer: item.issuer, clientId: item.client_id, userId: item.user_id,
      organizationId: item.organization_id, projectId: item.project_id, grantId: item.grant_id, familyId: item.family_id,
      grantResourceUris: item.grant_resources, grantScopes: item.grant_scopes }, deployment);
    const accessScopes = familyStrings(item.access_scopes, delegatedScopes);
    if (!binding.grantResourceUris.includes(selected.resource)
      || !accessScopes.every(scope => binding.grantScopes.includes(scope))) refuse();
    return Object.freeze({ ...binding, resource: selected.resource, accessScopes, expiresAtSeconds: item.expires_at });
  } catch { return refuse(); }
}
