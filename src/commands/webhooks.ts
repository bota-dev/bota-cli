import { Command } from 'commander';

export const WEBHOOK_MANAGEMENT_UNAVAILABLE = 'Webhook management is available in Bota Platform. The public API does not expose webhook registration/list/detail/deletion; these CLI operations are unavailable.';

export function registerWebhooks(program: Command): void {
  const webhooks = program.command('webhooks').description('Webhook management (Bota Platform only)');

  webhooks.command('list')
    .description('Unavailable: list webhook endpoints in Bota Platform')
    .option('--limit <n>', 'Max results', '20')
    .action(() => { throw new Error(WEBHOOK_MANAGEMENT_UNAVAILABLE); });

  webhooks.command('get <id>')
    .description('Unavailable: inspect webhook endpoints in Bota Platform')
    .action(() => { throw new Error(WEBHOOK_MANAGEMENT_UNAVAILABLE); });
}
