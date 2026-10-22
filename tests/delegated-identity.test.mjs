import assert from 'node:assert/strict';
import test from 'node:test';
import { DelegatedIdentityError, normalizeDelegatedIdentity } from '../src/delegated-identity.ts';

// Exact projection from backend developer-auth-runtime-postgres.test.ts and
// developer-auth-identity.ts at 2a0825c3. No backend import/DB/auth is involved.
const deployment = () => ({ version: 1, issuer: 'https://auth.fixture.invalid', endpoints: {
  authorization: 'https://auth.fixture.invalid/oauth/authorize', token: 'https://auth.fixture.invalid/oauth/token', revocation: 'https://auth.fixture.invalid/oauth/revoke' },
  resources: { rest: 'https://api.fixture.invalid/v1', mcp: 'https://api.fixture.invalid/mcp' }, client: { clientId: 'fixture-cli', kind: 'native',
    redirectUris: ['http://127.0.0.1/oauth/callback'], resourceKinds: ['rest', 'mcp'], pkceMethod: 'S256' } });
const user = '11111111-1111-4111-8111-111111111111', grant = '22222222-2222-4222-8222-222222222222', family = '33333333-3333-4333-8333-333333333333';
function fixture() {
  const d = deployment();
  return { dto: { format_version: 1, credential_type: 'developer_delegation', issuer: d.issuer, client_id: 'fixture-cli', user_id: user,
    organization_id: 'org_fixture', project_id: 'proj_fixture', grant_id: grant, family_id: family, resource: d.resources.rest,
    grant_resources: [d.resources.rest, d.resources.mcp], grant_scopes: ['devices:read'], access_scopes: ['devices:read'], expires_at: 1300 },
    context: { deployment: d, resource: d.resources.rest, nowSeconds: 1000 } };
}
const canary = 'PRIVATE_IDENTITY_CANARY';
function refused(value, context) {
  assert.throws(() => normalizeDelegatedIdentity(value, context), error => {
    assert.ok(error instanceof DelegatedIdentityError); assert.equal(error.code, 'identity_response_invalid');
    assert.equal(error.cause, undefined); assert.doesNotMatch(String(error) + JSON.stringify(error), /PRIVATE_IDENTITY_CANARY|bota_d[acr]1_|fixture\.invalid/); return true;
  });
}
test('maps the exact backend REST DTO to 12 frozen copied engine fields', () => {
  const { dto, context } = fixture(), result = normalizeDelegatedIdentity(dto, context);
  assert.equal(Object.keys(dto).length, 14); assert.equal(Object.keys(result).length, 12);
  assert.deepEqual(result, { issuer: dto.issuer, clientId: dto.client_id, userId: user, organizationId: 'org_fixture', projectId: 'proj_fixture',
    grantId: grant, familyId: family, grantResourceUris: [...dto.grant_resources].sort(), grantScopes: ['devices:read'],
    resource: dto.resource, accessScopes: ['devices:read'], expiresAtSeconds: 1300 });
  for (const item of [result, result.grantResourceUris, result.grantScopes, result.accessScopes]) assert.ok(Object.isFrozen(item));
  for (const [target, source] of [[result.grantResourceUris, dto.grant_resources], [result.grantScopes, dto.grant_scopes], [result.accessScopes, dto.access_scopes]]) assert.notEqual(target, source);
  dto.grant_resources.length = 0; dto.grant_scopes[0] = 'recordings:read'; dto.access_scopes.length = 0; dto.project_id = canary;
  assert.equal(result.grantResourceUris.length, 2); assert.deepEqual(result.grantScopes, ['devices:read']); assert.deepEqual(result.accessScopes, ['devices:read']); assert.equal(result.projectId, 'proj_fixture');
});
test('supports exact MCP authority, access subsets, empty scopes and single-resource grants', () => {
  const { dto, context } = fixture(); dto.resource = context.resource = context.deployment.resources.mcp;
  dto.grant_resources = [dto.resource]; dto.grant_scopes = ['recordings:read', 'devices:read']; dto.access_scopes = ['devices:read'];
  const result = normalizeDelegatedIdentity(dto, context); assert.deepEqual(result.grantResourceUris, [dto.resource]); assert.deepEqual(result.accessScopes, ['devices:read']);
  dto.grant_scopes = dto.access_scopes = []; assert.deepEqual(normalizeDelegatedIdentity(dto, context).accessScopes, []);
});
test('uses canonical server UUIDs without an invented version or variant restriction', () => {
  const { dto, context } = fixture(); dto.user_id = '11111111-1111-1111-1111-111111111111'; dto.grant_id = '22222222-2222-5222-0222-222222222222'; dto.family_id = '00000000-0000-0000-0000-000000000000';
  const result = normalizeDelegatedIdentity(dto, context); assert.equal(result.userId, dto.user_id); assert.equal(result.grantId, dto.grant_id); assert.equal(result.familyId, dto.family_id);
  for (const field of ['user_id', 'grant_id', 'family_id']) for (const bad of ['ABCDEFAB-1111-4111-8111-111111111111', user + '\n', ' ' + user, user.slice(1), {}, null]) refused({ ...dto, [field]: bad }, context);
});
test('requires exact version, credential kind, all 14 fields and no private or unknown fields', () => {
  const { dto, context } = fixture();
  for (const field of Object.keys(dto)) { const missing = { ...dto }; delete missing[field]; refused(missing, context); }
  for (const field of ['access_token', 'refresh_token', 'token_hash', 'api_key', 'requested_scopes', 'profile', 'toJSON', 'formatVersion']) refused({ ...dto, [field]: canary }, context);
  for (const version of ['1', 0, 2, true, null]) refused({ ...dto, format_version: version }, context);
  for (const kind of ['api_key', 'device', 'developer_delegation\n', null]) refused({ ...dto, credential_type: kind }, context);
});
test('checks configured issuer/client and actual resource independently of grant registration', () => {
  const { dto, context } = fixture();
  for (const patch of [{ issuer: dto.issuer + '/' }, { issuer: 'https://other.invalid' }, { client_id: 'another-client' },
    { resource: context.deployment.resources.mcp }, { grant_resources: [context.deployment.resources.mcp] },
    { grant_resources: [dto.resource, 'https://other.invalid/v1'] }, { grant_resources: [] }]) refused({ ...dto, ...patch }, context);
  refused(dto, { ...context, resource: context.deployment.resources.mcp });
  refused(dto, { ...context, resource: context.resource + '/' });
  const d = deployment(); d.client.resourceKinds = ['mcp']; refused(dto, { ...context, deployment: d });
  d.client.resourceKinds = ['rest']; refused(dto, { ...context, deployment: d }); // extra MCP grant authority is not registered.
});
test('never infers grant or access authority from configured or requested scope sets', () => {
  const { dto, context } = fixture();
  for (const patch of [{ grant_scopes: ['devices:write'] }, { access_scopes: ['devices:write'] }, { access_scopes: ['recordings:read'] },
    { grant_scopes: [], access_scopes: ['devices:read'] }, { grant_scopes: ['devices:read', 'devices:read'] },
    { access_scopes: ['devices:read', 'devices:read'] }, { grant_resources: [dto.resource, dto.resource] }]) refused({ ...dto, ...patch }, context);
  refused(dto, { ...context, requestedScopes: ['devices:read'] });
  refused({ ...dto, grant_scopes: ['devices:read', 'recordings:read', 'end_users:read', 'transcriptions:read', 'summaries:read', 'devices:read'] }, context);
});
test('checks an optional already-trusted exact grant/family pair without replacing server identity', () => {
  const { dto, context } = fixture(); context.expectedBinding = { grantId: grant, familyId: family };
  assert.equal(normalizeDelegatedIdentity(dto, context).grantId, grant);
  for (const expectedBinding of [{ grantId: user, familyId: family }, { grantId: grant, familyId: user }, { grantId: grant },
    { grantId: grant, familyId: family, accessToken: canary }, { grantId: 'invalid', familyId: family }, null, undefined]) refused(dto, { ...context, expectedBinding });
});
test('bounds exact authoritative expiry against explicit safe current seconds', () => {
  const { dto, context } = fixture();
  for (const expiry of [1001, 1300]) assert.equal(normalizeDelegatedIdentity({ ...dto, expires_at: expiry }, context).expiresAtSeconds, expiry);
  for (const expiry of [0, 999, 1000, 1301, -1, 1001.5, '1300', null, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) refused({ ...dto, expires_at: expiry }, context);
  for (const nowSeconds of [-1, 1.5, '1000', null, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER]) refused(dto, { ...context, nowSeconds });
  assert.equal(normalizeDelegatedIdentity({ ...dto, expires_at: 300 }, { ...context, nowSeconds: 0 }).expiresAtSeconds, 300);
});
test('enforces bounded control-free opaque organization/project IDs and safe credential-free engine binding', () => {
  const { dto, context } = fixture();
  for (const field of ['organization_id', 'project_id']) {
    for (const bad of ['', 'x'.repeat(2049), 'é'.repeat(1025), 'x\n', 'x\u0000', 'x\u007f', 'bota_da1_' + canary, 'bota_dr1_' + canary, 'bota_dc1_' + canary, {}, null]) refused({ ...dto, [field]: bad }, context);
    const result = normalizeDelegatedIdentity({ ...dto, [field]: 'é'.repeat(1024) }, context); assert.equal(result[field === 'organization_id' ? 'organizationId' : 'projectId'], 'é'.repeat(1024));
  }
});
test('rejects inherited, non-enumerable, symbol and reflective DTO shapes without running private hooks', () => {
  const { dto, context } = fixture(); let hooks = 0;
  const inherited = Object.create(dto), hidden = { ...dto }; Object.defineProperty(hidden, 'project_id', { value: 'proj_fixture', enumerable: false });
  const getter = { ...dto }; Object.defineProperty(getter, 'project_id', { enumerable: true, get() { hooks++; throw Error(canary); } });
  const proxy = new Proxy(dto, { get() { hooks++; throw Error(canary); }, getPrototypeOf() { hooks++; throw Error(canary); }, ownKeys() { hooks++; throw Error(canary); } });
  const revoked = Proxy.revocable(dto, {}); revoked.revoke();
  for (const input of [inherited, hidden, getter, proxy, revoked.proxy, { ...dto, [Symbol(canary)]: canary }, [], null, canary]) refused(input, context);
  assert.equal(hooks, 0);
  const nullPrototype = Object.assign(Object.create(null), dto); assert.equal(normalizeDelegatedIdentity(nullPrototype, context).projectId, 'proj_fixture');
});
test('rejects sparse, accessor, proxy, symbol and oversized authority arrays without running hooks', () => {
  const { dto, context } = fixture(); let hooks = 0;
  for (const field of ['grant_resources', 'grant_scopes', 'access_scopes']) {
    const valid = dto[field], getter = [...valid]; Object.defineProperty(getter, '0', { enumerable: true, get() { hooks++; throw Error(canary); } });
    const proxy = new Proxy(valid, { get() { hooks++; throw Error(canary); }, ownKeys() { hooks++; throw Error(canary); } });
    const sparse = new Array(1), extra = [...valid]; extra.private = canary;
    for (const bad of [getter, proxy, sparse, extra, Object.assign([...valid], { [Symbol(canary)]: canary }), null, canary, [new String(valid[0])]]) refused({ ...dto, [field]: bad }, context);
  }
  assert.equal(hooks, 0);
});
test('validates exact own-data context, expected binding and deployment with no ambient fallback or hook invocation', () => {
  const { dto, context } = fixture(); let hooks = 0;
  for (const field of Object.keys(context)) { const missing = { ...context }; delete missing[field]; refused(dto, missing); }
  const getter = { ...context }; Object.defineProperty(getter, 'resource', { enumerable: true, get() { hooks++; throw Error(canary); } });
  const proxy = new Proxy(context, { ownKeys() { hooks++; throw Error(canary); } });
  for (const bad of [undefined, null, {}, getter, proxy, { ...context, private: canary }, Object.create(context)]) refused(dto, bad);
  const binding = { grantId: grant, familyId: family }; Object.defineProperty(binding, 'grantId', { enumerable: true, get() { hooks++; throw Error(canary); } });
  refused(dto, { ...context, expectedBinding: binding });
  refused(dto, { ...context, expectedBinding: new Proxy({}, { ownKeys() { hooks++; throw Error(canary); } }) });
  const d = deployment(); Object.defineProperty(d, 'issuer', { enumerable: true, get() { hooks++; throw Error(canary); } });
  refused(dto, { ...context, deployment: d });
  refused(dto, { ...context, deployment: new Proxy({}, { ownKeys() { hooks++; throw Error(canary); } }) });
  assert.equal(hooks, 0);
});
test('is a parsed-value boundary only: rejects bytes/text and does not claim JSON duplicate detection', () => {
  const { dto, context } = fixture(); refused(JSON.stringify(dto), context); refused(Buffer.from(JSON.stringify(dto)), context);
  // A parser has already destroyed duplicate-member evidence. Future transport
  // must reject it before this call; this assertion makes that limit explicit.
  const lostEvidence = JSON.parse(JSON.stringify(dto).replace('"format_version":1', '"format_version":99,"format_version":1'));
  assert.equal(normalizeDelegatedIdentity(lostEvidence, context).expiresAtSeconds, dto.expires_at);
});
