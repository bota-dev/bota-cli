import { Command } from 'commander';
import { readConfig, writeConfig, getApiUrl, getProfileContext } from '../config.js';
import { ok } from '../output.js';
import { showAuthStatus } from './auth-status.js';
import { withCommandAuth } from '../invocation-auth.js';
import { developerProfileService, writeDeveloperCommandOutput } from '../developer-profile-production.js';
import type { DeveloperProfileService } from '../developer-profile-service.js';
import { DeveloperProfileError } from '../developer-profile-error.js';
import { chooseDeveloperScopes, developerCommandBoundary, developerProfileProjection, publishDeveloperMetadata, publishDeveloperText, type DeveloperMetadataWriter } from './developer-profiles.js';

export function registerAuth(program: Command, developer: DeveloperProfileService = developerProfileService,
  write: DeveloperMetadataWriter = writeDeveloperCommandOutput): Command {
  const auth = program.command('auth').description('Manage authentication');

  auth
    .command('login [key]')
    .description('Sign in through configured Platform login, or preserve explicit legacy API-key compatibility')
    .option('--name <name>', 'New local developer profile name', 'default')
    .option('--scope <scope>', 'Explicit requested developer read scope; repeat for multiple scopes', (scope: string, selected: string[]) => [...selected, scope], [])
    .option('--identity-only', 'Explicitly request identity without business-read scopes')
    .option('--no-browser', 'Print the authorization URL to stderr instead of opening a browser')
    .allowExcessArguments(false)
    .action(async (key: string | undefined, options: { name: string; scope: string[]; identityOnly?: boolean; browser?: boolean }) => {
      const globalOpts = program.opts();
      if (key) {
        if (globalOpts['developerProfile'] !== undefined || globalOpts['developerDeployment'] !== undefined || options.name !== 'default' || options.scope.length || options.identityOnly || options.browser === false) throw new DeveloperProfileError('developer_profile_invalid');
        const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);
        // Headless / CI path: accept key directly
        if (!key.startsWith('sk_live_') && !key.startsWith('sk_test_')) {
          console.error('Invalid key format. Must start with sk_live_ or sk_test_');
          process.exit(1);
        }
        const config = readConfig();
        config.apiKey = key;
        config.apiUrl = apiUrl === 'https://api.bota.dev' ? undefined : apiUrl;
        writeConfig(config);
        ok(`Logged in with key ${key.slice(0, 10)}...`);
        return;
      }

      if (['profile', 'secureProfile', 'apiUrl', 'dashboardUrl'].some(option => globalOpts[option] !== undefined)) throw new DeveloperProfileError('developer_profile_invalid');
      const selectedName = globalOpts['developerProfile'] as string | undefined;
      if (selectedName && options.name !== 'default' && selectedName !== options.name) throw new DeveloperProfileError('developer_profile_invalid');
      await developerCommandBoundary(async signal => {
        const deployment = developer.configuration();
        const scopes = await chooseDeveloperScopes(options, signal);
        const profile = await developer.login(selectedName ?? options.name, { resourceKind: deployment.client.resourceKinds.includes('rest') ? 'rest' : 'mcp',
          grantResourceKinds: deployment.client.resourceKinds, scopes,
          loopbackHost: deployment.client.redirectUris.includes('http://127.0.0.1/oauth/callback') ? '127.0.0.1' : '::1' }, { signal, ...(options.browser === false ? { browser: false } : {}) });
        await publishDeveloperMetadata(developerProfileProjection(profile), signal, write);
        if (!globalOpts['json']) { const selectedDeployment = globalOpts['developerDeployment'];
          const deploymentOption = selectedDeployment === 'dev' || selectedDeployment === 'prod' ? `--developer-deployment ${selectedDeployment} ` : '';
          await publishDeveloperText('stderr', `Select this session with ${deploymentOption}--developer-profile ${profile.name}. Revoke it with: bota ${deploymentOption}auth developer-profiles logout ${profile.name}\n`, signal, write); }
      });
    });

  auth
    .command('logout')
    .description('Remove a legacy saved key, or revoke an explicitly selected developer session')
    .action(async () => {
      const name = program.opts()['developerProfile'];
      if (name !== undefined) { await developerCommandBoundary(async signal => {
        await publishDeveloperMetadata(developerProfileProjection(await developer.logout(name as string, { signal })), signal, write);
      }); return; }
      const config = readConfig();
      delete config.apiKey;
      writeConfig(config);
      ok('Logged out');
    });

  auth
    .command('status')
    .description('Show current auth status')
    .action(async () => {
      const globalOpts = program.opts();
      if (globalOpts['developerProfile'] !== undefined) { await developerCommandBoundary(async signal => {
        const value = await developer.status(globalOpts['developerProfile'] as string, { signal });
        await publishDeveloperMetadata(value, signal, write, value.expiresAtSeconds);
      }); return; }
      await withCommandAuth(program, async () => {
      const context = getProfileContext();
      if (context) {
        await showAuthStatus({ ...context, json: Boolean(globalOpts['json']) });
        return;
      }
      const config = readConfig();
      const key = config.apiKey ?? process.env['BOTA_API_KEY'];

      const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);
      await showAuthStatus({ apiKey: key, apiUrl, json: Boolean(globalOpts['json']) });
      })();
    });
  return auth;
}
