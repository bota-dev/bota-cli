import { Command } from 'commander';
import { callMcpTool } from '../client.js';
import { ok, printJson } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

export function registerTrigger(program: Command): void {
  program.command('trigger <event>')
    .description('Trigger a test event for an existing Platform-managed webhook')
    .option('--webhook <id>', 'Existing webhook ID from Bota Platform (required)')
    .action(async (event: string, opts) => {
      if (!opts.webhook) throw new Error('Select an existing webhook in Bota Platform and provide --webhook <id>. Automatic webhook selection is unavailable.');
      const globalOpts = program.opts();
      const result = await callMcpTool(getApiUrl(globalOpts['apiUrl'] as string | undefined), getApiKey(), 'trigger_webhook_event', { webhook_id: opts.webhook, event_type: event });
      if (globalOpts['json']) {
        try { printJson(JSON.parse(result)); } catch { printJson(result); }
        return;
      }
      ok(`Triggered ${event} on webhook ${opts.webhook}`);
      console.log(result);
    });
}
