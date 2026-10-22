import { Command } from 'commander';
import { readConfig, writeConfig, getApiUrl, getProfileContext } from '../config.js';
import { ok } from '../output.js';
import { showAuthStatus } from './auth-status.js';
import { withCommandAuth } from '../invocation-auth.js';

export function registerAuth(program: Command): Command {
  const auth = program.command('auth').description('Manage authentication');

  auth
    .command('login [key]')
    .description('Save a legacy API key; Platform browser login is unavailable')
    .action(async (key: string | undefined) => {
      const globalOpts = program.opts();
      if (key) {
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

      // Retired browser key export must not be mistaken for delegated login.
      // In particular, never open a callback listener or put a project key in a URL.
      throw Object.assign(new Error('Platform browser login is unavailable. Supply BOTA_API_KEY through your secret manager, or use auth secure-profiles add <name> --key-prompt on a supported host.'),
        { code: 'platform_login_unavailable' });
    });

  auth
    .command('logout')
    .description('Remove saved API key')
    .action(() => {
      const config = readConfig();
      delete config.apiKey;
      writeConfig(config);
      ok('Logged out');
    });

  auth
    .command('status')
    .description('Show current auth status')
    .action(withCommandAuth(program, async () => {
      const globalOpts = program.opts();
      const context = getProfileContext();
      if (context) {
        await showAuthStatus({ ...context, json: Boolean(globalOpts['json']) });
        return;
      }
      const config = readConfig();
      const key = config.apiKey ?? process.env['BOTA_API_KEY'];

      const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);
      await showAuthStatus({ apiKey: key, apiUrl, json: Boolean(globalOpts['json']) });
    }));
  return auth;
}
