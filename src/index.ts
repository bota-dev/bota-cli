import { Command } from 'commander';
import { registerAuth } from './commands/auth.js';
import { registerEndUsers } from './commands/end-users.js';
import { registerDevices } from './commands/devices.js';
import { registerRecordings } from './commands/recordings.js';
import { registerWebhooks } from './commands/webhooks.js';
import { registerListen } from './commands/listen.js';
import { registerTrigger } from './commands/trigger.js';
import { registerMcp } from './commands/mcp.js';

const program = new Command();

program
  .name('bota')
  .description('Bota developer CLI')
  .version('0.1.0')
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

program.parseAsync(process.argv).catch((e: unknown) => {
  console.error((e as Error).message);
  process.exit(1);
});
