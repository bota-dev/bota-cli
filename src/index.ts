import { Command } from 'commander';
import { createRequire } from 'node:module';
import { registerAuth } from './commands/auth.js';
import { registerEndUsers } from './commands/end-users.js';
import { registerDevices } from './commands/devices.js';
import { registerRecordings } from './commands/recordings.js';
import { registerWebhooks } from './commands/webhooks.js';
import { registerListen } from './commands/listen.js';
import { registerTrigger } from './commands/trigger.js';
import { registerMcp } from './commands/mcp.js';
import { registerIntegrations } from './commands/integrations.js';
import { printError } from './output.js';

const program = new Command();
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

program
  .name('bota')
  .description('Bota developer CLI')
  .version(version)
  .option('--api-url <url>', 'Override API base URL')
  .option('--dashboard-url <url>', 'Override dashboard/portal URL')
  .option('--json', 'Output raw JSON');

registerAuth(program);
registerEndUsers(program);
registerDevices(program);
registerRecordings(program);
registerWebhooks(program);
registerListen(program);
registerTrigger(program);
registerMcp(program);
registerIntegrations(program);

program.parseAsync(process.argv).catch((e: unknown) => {
  printError(e, Boolean(program.opts()['json']));
  process.exitCode = 1;
});
