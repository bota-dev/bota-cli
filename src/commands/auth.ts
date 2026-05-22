import { Command } from 'commander';
import { readConfig, writeConfig, getApiUrl } from '../config.js';
import { BotaClient } from '../client.js';
import { ok, info, warn } from '../output.js';

export function registerAuth(program: Command): void {
  const auth = program.command('auth').description('Manage authentication');

  auth
    .command('login <key>')
    .description('Save API key')
    .action(async (key: string) => {
      if (!key.startsWith('sk_live_') && !key.startsWith('sk_test_')) {
        console.error('Invalid API key format. Must start with sk_live_ or sk_test_');
        process.exit(1);
      }
      const config = readConfig();
      config.apiKey = key;
      writeConfig(config);
      ok(`Logged in with key ${key.slice(0, 10)}...`);
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
    .action(async () => {
      const config = readConfig();
      const key = config.apiKey ?? process.env['BOTA_API_KEY'];

      if (!key) {
        warn('Not authenticated');
        process.exit(1);
      }

      const masked = `${key.slice(0, 10)}...${key.slice(-4)}`;
      const apiUrl = getApiUrl(program.opts()['apiUrl'] as string | undefined);

      info(`Key:     ${masked}`);
      info(`API URL: ${apiUrl}`);

      try {
        const client = new BotaClient({ apiKey: key, apiUrl });
        await client.get('/v1/end-users', { limit: 1 });
        ok('API key is valid');
      } catch (e) {
        warn(`API key check failed: ${(e as Error).message}`);
        process.exit(1);
      }
    });
}
