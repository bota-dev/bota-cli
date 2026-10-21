import { Command } from 'commander';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readConfig, writeConfig, getApiUrl, getDashboardUrl, getProfileContext } from '../config.js';
import { ok, info } from '../output.js';
import { showAuthStatus } from './auth-status.js';
import { withCommandAuth } from '../invocation-auth.js';

export function registerAuth(program: Command): Command {
  const auth = program.command('auth').description('Manage authentication');

  auth
    .command('login [key]')
    .description('Authenticate via browser (or pass a key directly for CI)')
    .action(async (key: string | undefined) => {
      const globalOpts = program.opts();
      const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);

      if (key) {
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

      // Browser OAuth flow
      const port = 4242;
      const state = randomBytes(16).toString('hex');
      const redirectUri = `http://localhost:${port}/callback`;
      const dashboardUrl = (globalOpts['dashboardUrl'] as string | undefined) ?? getDashboardUrl(apiUrl);
      const authUrl = `${dashboardUrl}/cli/auth?state=${state}&redirect=${encodeURIComponent(redirectUri)}`;

      await new Promise<void>((resolve, reject) => {
        const server = createServer((req: IncomingMessage, res: ServerResponse) => {
          if (!req.url?.startsWith('/callback')) {
            res.writeHead(404);
            res.end();
            return;
          }

          const url = new URL(req.url, `http://localhost:${port}`);
          const returnedState = url.searchParams.get('state');
          const returnedKey = url.searchParams.get('key');
          const email = url.searchParams.get('email');
          const error = url.searchParams.get('error');

          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });

          if (error === 'access_denied') {
            res.end('<html><body><h2>Authorization cancelled. You can close this tab.</h2></body></html>');
            server.close(() => reject(new Error('Authorization cancelled')));
            return;
          }

          if (returnedState !== state || !returnedKey) {
            res.end('<html><body><h2>Invalid response. Please try again.</h2></body></html>');
            server.close(() => reject(new Error('Invalid callback state')));
            return;
          }

          res.end('<html><body><h2>&#10003; Authenticated! You can close this tab.</h2></body></html>');

          const config = readConfig();
          config.apiKey = returnedKey;
          config.apiUrl = apiUrl === 'https://api.bota.dev' ? undefined : apiUrl;
          writeConfig(config);

          ok(`Logged in as ${email ?? 'unknown'}`);
          server.close(() => resolve());
        });

        server.listen(port, async () => {
          info(`Opening browser to authorize...`);
          info(`If the browser doesn't open, visit:\n  ${authUrl}`);
          try {
            const open = (await import('open')).default;
            await open(authUrl);
          } catch {
            // User will copy the URL manually
          }
        });

        server.on('error', reject);

        // Timeout after 5 minutes
        setTimeout(() => {
          server.close(() => reject(new Error('Authorization timed out')));
        }, 5 * 60 * 1000).unref();
      });
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
