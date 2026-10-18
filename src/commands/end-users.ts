import { Command } from 'commander';
import { BotaClient } from '../client.js';
import { printTable, printJson, printDetail, printPagination, printError, ok } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

interface EndUser {
  id: string;
  name: string;
  email?: string;
  external_id?: string;
  created_at: string;
  [key: string]: unknown;
}

interface ListResponse {
  data: EndUser[];
  has_more?: boolean;
  next_cursor?: string;
}

interface TokenResponse {
  token: string;
  connection_command?: string;
  [key: string]: unknown;
}

export function registerEndUsers(program: Command): void {
  const eu = program.command('end-users').description('Manage end users');

  eu
    .command('list')
    .description('List end users')
    .option('--limit <n>', 'Max results', '20')
    .option('--cursor <c>', 'Pagination cursor')
    .option('--external-id <id>', 'Filter by external ID')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.get<ListResponse>('/v1/end-users', {
          limit: opts.limit,
          cursor: opts.cursor,
          external_id: opts.externalId,
        });
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        printTable(
          ['id', 'name', 'email', 'external_id', 'created_at'],
          res.data.map(u => [u.id, u.name, u.email ?? '', u.external_id ?? '', u.created_at]),
        );
        printPagination(res);
      } catch (e) {
        printError(e, Boolean(globalOpts['json']));
        process.exitCode = 1;
      }
    });

  eu
    .command('get <id>')
    .description('Get end user by ID')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const user = await client.get<EndUser>(`/v1/end-users/${id}`);
        if (globalOpts['json']) {
          printJson(user);
          return;
        }
        printDetail(user as Record<string, unknown>);
      } catch (e) {
        printError(e, Boolean(globalOpts['json']));
        process.exitCode = 1;
      }
    });

  eu
    .command('create')
    .description('Create an end user')
    .requiredOption('--name <n>', 'Display name')
    .option('--email <e>', 'Email address')
    .option('--external-id <id>', 'External ID')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const user = await client.post<EndUser>('/v1/end-users', {
          name: opts.name,
          email: opts.email,
          external_id: opts.externalId,
        });
        if (globalOpts['json']) {
          printJson(user);
          return;
        }
        ok(`Created end user ${user.id}`);
        printDetail(user as Record<string, unknown>);
      } catch (e) {
        printError(e, Boolean(globalOpts['json']));
        process.exitCode = 1;
      }
    });

  eu
    .command('token <id>')
    .description('Issue a user token for an end user (replaces any existing token)')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.post<TokenResponse>(`/v1/end-users/${id}/user-token`);
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        console.log('┌─────────────────────────────────────────┐');
        console.log(`  Token: ${res.token}`);
        if (res.connection_command) {
          console.log(`  Command: ${res.connection_command}`);
        }
        console.log('└─────────────────────────────────────────┘');
      } catch (e) {
        printError(e, Boolean(globalOpts['json']));
        process.exitCode = 1;
      }
    });

  eu
    .command('token-revoke <id>')
    .description('Revoke the user token for an end user')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        await client.delete(`/v1/end-users/${id}/user-token`);
        if (!globalOpts['json']) {
          ok(`Token revoked for end user ${id}`);
        }
      } catch (e) {
        printError(e, Boolean(globalOpts['json']));
        process.exitCode = 1;
      }
    });
}
