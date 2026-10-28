import assert from 'node:assert/strict';
import test from 'node:test';
import { AsyncLocalStorage, AsyncResource } from 'node:async_hooks';
import { EventEmitter } from 'node:events';
import { Command } from 'commander';
import { getSelectedDeveloperDeployment, isKnownDeveloperDeployment, readDeveloperDeploymentSelection, validateDeveloperDeploymentCommand,
  withDeveloperDeploymentSelection } from '../src/developer-deployment-selection.ts';
import { getProductionDeveloperDeployment } from '../src/delegated-production-deployment.ts';
import { developerProfileService } from '../src/developer-profile-production.ts';
import { developerProfileFailure } from '../src/developer-profile-error.ts';
import { bindDeveloperMcpRequestAuth } from '../src/invocation-auth.ts';

const refused = code => error => {
  assert.equal(developerProfileFailure(error)?.code, code);
  assert.doesNotMatch(JSON.stringify(developerProfileFailure(error)), /PRIVATE_CANARY/);
  return true;
};
const scope = (selected, work) => withDeveloperDeploymentSelection(() => selected, work);
const unavailable = () => assert.throws(getSelectedDeveloperDeployment, refused('developer_configuration_unavailable'));

test('production remains off without an explicit source-owned selection', async () => {
  assert.throws(getProductionDeveloperDeployment, refused('developer_configuration_unavailable'));
  unavailable();
  await scope(undefined, async () => { unavailable(); assert.throws(() => developerProfileService.configuration(), refused('developer_configuration_unavailable')); });
});

test('DEV selects the fixed reviewed backend client and both independent resource audiences', async () => {
  await scope('dev', async () => {
    const value = getSelectedDeveloperDeployment();
    assert.deepEqual(value, { version: 1, issuer: 'https://api.dev.bota.dev', recoveryProtocol: 'negative-fence-v1',
      endpoints: { authorization: 'https://api.dev.bota.dev/oauth/authorize', token: 'https://api.dev.bota.dev/oauth/token', revocation: 'https://api.dev.bota.dev/oauth/revoke' },
      resources: { rest: 'https://api.dev.bota.dev/v1', mcp: 'https://api.dev.bota.dev/mcp' },
      client: { clientId: 'bota-cli-dev-v1', kind: 'native', pkceMethod: 'S256',
        redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'], resourceKinds: ['rest', 'mcp'] } });
    for (const object of [value, value.endpoints, value.resources, value.client, value.client.redirectUris, value.client.resourceKinds]) assert.equal(Object.isFrozen(object), true);
    // Actual singleton configuration only: no injected runtime/service and no
    // native bootstrap, listener, browser or network action is requested.
    assert.deepEqual(developerProfileService.configuration(), value);
    assert.throws(() => { value.resources.rest = 'https://PRIVATE_CANARY.test'; }, TypeError);
    assert.throws(getProductionDeveloperDeployment, refused('developer_configuration_unavailable'));
  });
  unavailable();
});

test('explicit PROD selects the reviewed source candidate without enabling the default resolver or native factory', async () => {
  await scope('prod', async () => {
    const value = getSelectedDeveloperDeployment();
    assert.deepEqual(value, { version: 1, issuer: 'https://api.bota.dev', recoveryProtocol: 'negative-fence-v1',
      endpoints: { authorization: 'https://api.bota.dev/oauth/authorize', token: 'https://api.bota.dev/oauth/token', revocation: 'https://api.bota.dev/oauth/revoke' },
      resources: { rest: 'https://api.bota.dev/v1', mcp: 'https://api.bota.dev/mcp' },
      client: { clientId: 'bota-cli-prod-v1', kind: 'native', pkceMethod: 'S256',
        redirectUris: ['http://127.0.0.1/oauth/callback', 'http://[::1]/oauth/callback'], resourceKinds: ['rest', 'mcp'] } });
    assert.deepEqual(developerProfileService.configuration(), value);
    for (const object of [value, value.endpoints, value.resources, value.client, value.client.redirectUris, value.client.resourceKinds]) assert.equal(Object.isFrozen(object), true);
    assert.equal(isKnownDeveloperDeployment(value), true);
    assert.equal(isKnownDeveloperDeployment({ ...value, client: { ...value.client, clientId: 'bota-cli-dev-v1' } }), false);
    assert.throws(getProductionDeveloperDeployment, refused('developer_configuration_unavailable'));
  });
  unavailable();
});

test('parsed selection is sampled once and cannot retarget across awaited work', async () => {
  let selected = 'dev', reads = 0;
  await withDeveloperDeploymentSelection(() => { reads++; return selected; }, async () => {
    const first = getSelectedDeveloperDeployment(); selected = 'https://PRIVATE_CANARY.test';
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(getSelectedDeveloperDeployment(), first); assert.equal(readDeveloperDeploymentSelection(), 'dev');
  });
  assert.equal(reads, 1);
});

test('invalid selections remain refused and do not inspect opaque input or exception hooks', async () => {
  let hooks = 0;
  const opaque = { get issuer() { hooks++; throw Error('PRIVATE_CANARY'); }, [Symbol.toPrimitive]() { hooks++; return 'dev'; } };
  for (const value of ['production', 'DEV', 'PROD', 'https://PRIVATE_CANARY.test', '', null, true, ['dev'], opaque,
    new Proxy({}, { get() { hooks++; throw Error('PRIVATE_CANARY'); } })]) {
    await scope(value, async () => {
      for (let index = 0; index < 2; index++) assert.throws(getSelectedDeveloperDeployment, refused('developer_profile_invalid'));
    });
  }
  await withDeveloperDeploymentSelection(() => { throw opaque; }, async () => assert.throws(getSelectedDeveloperDeployment, refused('developer_profile_invalid')));
  const proxy = new Proxy(() => 'dev', { apply() { hooks++; return 'dev'; } });
  await assert.rejects(withDeveloperDeploymentSelection(proxy, async () => {}), refused('developer_profile_invalid'));
  await assert.rejects(withDeveloperDeploymentSelection(() => 'dev', proxy), refused('developer_profile_invalid'));
  assert.equal(hooks, 0);
});

test('reentrant selection cannot replace or recover a refused sampling owner', async () => {
  await withDeveloperDeploymentSelection(() => { assert.throws(getSelectedDeveloperDeployment, refused('developer_profile_invalid')); return 'dev'; }, async () => {
    assert.throws(getSelectedDeveloperDeployment, refused('developer_profile_invalid'));
    assert.throws(getSelectedDeveloperDeployment, refused('developer_profile_invalid'));
  });
});

test('concurrent and nested command scopes isolate their selection', async () => {
  let release, entered;
  const held = new Promise(resolve => { release = resolve; }), started = new Promise(resolve => { entered = resolve; });
  const dev = scope('dev', async () => {
    entered(); await held; assert.equal(getSelectedDeveloperDeployment().client.clientId, 'bota-cli-dev-v1');
    await scope(undefined, async () => unavailable());
    assert.equal(readDeveloperDeploymentSelection(), 'dev');
  });
  await started; await scope('prod', async () => {
    assert.equal(getSelectedDeveloperDeployment().client.clientId, 'bota-cli-prod-v1');
    await scope(undefined, async () => unavailable());
    assert.equal(readDeveloperDeploymentSelection(), 'prod'); release();
  }); await dev;
  unavailable();
});

test('late callbacks lose DEV and PROD selection after successful or failed command settlement', async () => {
  for (const selected of ['dev', 'prod']) for (const fail of [false, true]) {
    let late;
    const running = scope(selected, async () => {
      const captured = AsyncLocalStorage.snapshot(); late = () => captured(getSelectedDeveloperDeployment);
      await new Promise(resolve => setImmediate(resolve));
      if (fail) throw Error('owned failure');
    });
    if (fail) await assert.rejects(running, /owned failure/); else await running;
    assert.throws(late, refused('developer_profile_invalid'));
  }
});

function commandFixture() {
  const calls = [], program = new Command().exitOverride()
    .option('--developer-deployment <name>').option('--developer-profile <name>')
    .option('--profile <name>').option('--secure-profile <name>').option('--api-url <url>').option('--dashboard-url <url>');
  const auth = program.command('auth');
  for (const name of ['login [key]', 'logout', 'status']) auth.command(name).action(() => calls.push({ route: name, deployment: getSelectedDeveloperDeployment() }));
  const management = auth.command('developer-profiles');
  for (const name of ['list', 'show <name>', 'recover <name>', 'logout <name>']) management.command(name).action(() => calls.push({ route: name, deployment: getSelectedDeveloperDeployment() }));
  for (const name of ['devices', 'end-users', 'recordings']) program.command(name).command('list').action(() => calls.push({ route: name, deployment: getSelectedDeveloperDeployment() }));
  program.command('mcp').option('--mode <mode>', 'mode', 'legacy').action(() => calls.push({ route: 'mcp', deployment: getSelectedDeveloperDeployment() }));
  program.command('integrations').command('list').action(() => calls.push('not-delegated'));
  program.hook('preAction', (_command, action) => validateDeveloperDeploymentCommand(program, action));
  return { calls, parse: args => withDeveloperDeploymentSelection(() => program.opts().developerDeployment, () => program.parseAsync(['node', 'bota', ...args])) };
}

test('DEV and PROD selection reach login, management, REST and hosted MCP through the same command lifetime', async () => {
  for (const selected of ['dev', 'prod']) for (const args of [['auth', 'login'], ['auth', 'developer-profiles', 'list'], ['auth', 'developer-profiles', 'show', 'work'],
    ['auth', 'developer-profiles', 'recover', 'work'], ['auth', 'developer-profiles', 'logout', 'work'],
    ['--developer-profile', 'work', 'auth', 'status'], ['--developer-profile', 'work', 'auth', 'logout'],
    ['--developer-profile', 'work', 'devices', 'list'], ['--developer-profile', 'work', 'end-users', 'list'],
    ['--developer-profile', 'work', 'recordings', 'list'], ['--developer-profile', 'work', 'mcp', '--mode', 'hosted']]) {
    const f = commandFixture(); await f.parse(['--developer-deployment', selected, ...args]);
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].deployment.client.clientId, `bota-cli-${selected}-v1`);
  }
});

test('mixed key or URL authority and unselected/unsupported DEV or PROD actions refuse before the action', async () => {
  const commands = [['auth', 'login', 'PRIVATE_CANARY'], ['auth', 'status'], ['auth', 'logout'], ['devices', 'list'], ['mcp', '--mode', 'hosted'],
    ['--developer-profile', 'work', 'integrations', 'list'], ['--developer-profile', 'work', 'auth', 'developer-profiles', 'show', 'work']];
  for (const option of ['--profile', '--secure-profile', '--api-url', '--dashboard-url']) commands.push([option, 'PRIVATE_CANARY', 'auth', 'login']);
  for (const selected of ['dev', 'prod']) for (const args of commands) {
    const f = commandFixture(); await assert.rejects(f.parse(['--developer-deployment', selected, ...args]), refused('developer_profile_invalid'));
    assert.deepEqual(f.calls, []);
  }
  const f = commandFixture(); await assert.rejects(f.parse(['--developer-deployment', 'https://PRIVATE_CANARY.test', 'auth', 'login']), refused('developer_profile_invalid'));
  assert.deepEqual(f.calls, []);
});

test('actual async Commander lifetime keeps PROD authority until a hosted action and its cleanup join', async () => {
  let release, entered, late, settled = false;
  const held = new Promise(resolve => { release = resolve; }), started = new Promise(resolve => { entered = resolve; });
  const program = new Command().option('--developer-deployment <name>').option('--developer-profile <name>');
  program.command('mcp').option('--mode <mode>').action(async () => {
    const captured = AsyncLocalStorage.snapshot(); late = () => captured(getSelectedDeveloperDeployment);
    assert.equal(developerProfileService.configuration().client.clientId, 'bota-cli-prod-v1'); entered();
    await held; assert.equal(developerProfileService.configuration().client.clientId, 'bota-cli-prod-v1');
  });
  program.hook('preAction', (_command, action) => validateDeveloperDeploymentCommand(program, action));
  const running = withDeveloperDeploymentSelection(() => program.opts().developerDeployment, () =>
    program.parseAsync(['node', 'bota', '--developer-deployment', 'prod', '--developer-profile', 'work', 'mcp', '--mode', 'hosted']))
    .finally(() => { settled = true; });
  await started; await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); unavailable(); release(); await running;
  assert.throws(late, refused('developer_profile_invalid'));
});

test('MCP auth re-enters captured DEV and PROD from an external emitter and refuses after owner retirement', async () => {
  for (const selected of ['dev', 'prod']) {
  const clientId = `bota-cli-${selected}-v1`;
  const external = new AsyncResource('pre-existing-stdio'), emitter = new EventEmitter();
  let authenticate, releaseOwner, ownerEntered, callbackResult, admissions = 0, releaseAction, actionEntered, actionSettled = false;
  const ownerHeld = new Promise(resolve => { releaseOwner = resolve; }), started = new Promise(resolve => { ownerEntered = resolve; });
  const actionHeld = new Promise(resolve => { releaseAction = resolve; }), actionStarted = new Promise(resolve => { actionEntered = resolve; });
  const expected = Object.freeze({ familyId: 'owned-metadata-only' });
  const service = {
    async pin() { assert.equal(developerProfileService.configuration().client.clientId, clientId); return expected; },
    async run(_name, kind, action, _options, pinned) {
      admissions++; assert.equal(kind, 'mcp'); assert.equal(pinned, expected);
      assert.equal(developerProfileService.configuration().client.clientId, clientId);
      return action();
    },
  };
  emitter.on('request', () => { callbackResult = authenticate(new AbortController().signal, async () => {
    actionEntered(); await actionHeld;
    assert.equal(developerProfileService.configuration().client.clientId, clientId); return 'owned-result';
  }).finally(() => { actionSettled = true; }); void callbackResult.catch(() => {}); });
  const running = scope(selected, async () => {
    authenticate = await bindDeveloperMcpRequestAuth(service)('work'); ownerEntered();
    await ownerHeld;
  });
  try {
    await started; external.runInAsyncScope(() => emitter.emit('request')); await actionStarted;
    await new Promise(resolve => setImmediate(resolve)); assert.equal(actionSettled, false); assert.equal(admissions, 1);
    releaseAction(); assert.equal(await callbackResult, 'owned-result');
    releaseOwner(); await running;
    external.runInAsyncScope(() => emitter.emit('request'));
    await assert.rejects(callbackResult, refused('developer_profile_invalid')); assert.equal(admissions, 1);
  } finally { releaseAction(); releaseOwner(); await running; emitter.removeAllListeners(); external.emitDestroy(); }
  }
});

test('unselected MCP callbacks cannot inherit another command selection', async () => {
  const calls = [], service = { async pin() { return Object.freeze({}); }, async run(_name, _kind, action) {
    calls.push(readDeveloperDeploymentSelection()); unavailable(); return action();
  } };
  const authenticate = await bindDeveloperMcpRequestAuth(service)('unselected');
  for (const selected of ['dev', 'prod']) await scope(selected, async () => { assert.equal(await authenticate(new AbortController().signal, async () => 'ok'), 'ok'); });
  assert.deepEqual(calls, [undefined, undefined]);
});
