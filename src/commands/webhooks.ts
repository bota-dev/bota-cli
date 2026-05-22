import { Command } from 'commander';
import { BotaClient } from '../client.js';
import { printTable, printJson, printDetail } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

interface Webhook {
  id: string;
  url: string;
  events: string[];
  created_at: string;
  [key: string]: unknown;
}

interface ListResponse {
  data: Webhook[];
}

export function registerWebhooks(program: Command): void {
  const webhooks = program.command('webhooks').description('Manage webhooks');

  webhooks
    .command('list')
    .description('List webhooks')
    .option('--limit <n>', 'Max results', '20')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.get<ListResponse>('/v1/webhooks', { limit: opts.limit });
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        printTable(
          ['id', 'url', 'events', 'created_at'],
          res.data.map(w => [w.id, w.url, w.events.join(', '), w.created_at]),
        );
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  webhooks
    .command('get <id>')
    .description('Get webhook by ID')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const webhook = await client.get<Webhook>(`/v1/webhooks/${id}`);
        if (globalOpts['json']) {
          printJson(webhook);
          return;
        }
        printDetail({ ...webhook, events: webhook.events.join(', ') } as Record<string, unknown>);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });
}
