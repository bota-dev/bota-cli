import { Command } from 'commander';
import { BotaClient, callMcpTool } from '../client.js';
import { printTable, ok } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

interface Webhook {
  id: string;
  url: string;
  events: string[];
  created_at: string;
}

interface ListResponse {
  data: Webhook[];
}

export function registerTrigger(program: Command): void {
  program
    .command('trigger <event>')
    .description('Trigger a webhook event')
    .option('--webhook <id>', 'Webhook ID to trigger')
    .action(async (event: string, opts) => {
      const globalOpts = program.opts();
      const apiKey = getApiKey();
      const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);
      const client = new BotaClient({ apiKey, apiUrl });

      let webhookId: string = opts.webhook;

      if (!webhookId) {
        try {
          const res = await client.get<ListResponse>('/v1/webhooks');
          if (res.data.length === 0) {
            console.error('No webhooks found. Create one first.');
            process.exit(1);
          }
          if (res.data.length === 1) {
            webhookId = res.data[0].id;
          } else {
            console.error('Multiple webhooks found. Specify one with --webhook:');
            printTable(
              ['id', 'url', 'events'],
              res.data.map(w => [w.id, w.url, w.events.join(', ')]),
            );
            process.exit(1);
          }
        } catch (e) {
          console.error((e as Error).message);
          process.exit(1);
        }
      }

      try {
        const result = await callMcpTool(apiUrl, apiKey, 'trigger_webhook_event', {
          webhook_id: webhookId,
          event_type: event,
        });
        ok(`Triggered ${event} on webhook ${webhookId}`);
        console.log(result);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });
}
