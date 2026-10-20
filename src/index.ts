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
import { registerProfiles, ProfileCommandError } from './commands/profiles.js';
import { resolveEnvironmentProfile } from './profiles.js';
import { readProfileIdentity } from './profile-identity.js';
import { setProfileContext } from './config.js';

const program = new Command();
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

program
  .name('bota')
  .description('Bota developer CLI')
  .version(version)
  .option('--api-url <url>', 'Override API base URL')
  .option('--dashboard-url <url>', 'Override dashboard/portal URL')
  .option('--profile <name>', 'Explicit environment-only profile; verify its origin/project before cloud operations')
  .option('--json', 'Output raw JSON');

const auth = registerAuth(program);
registerProfiles(auth, program);
registerEndUsers(program);
registerDevices(program);
registerRecordings(program);
registerWebhooks(program);
registerListen(program);
registerTrigger(program);
registerMcp(program);
registerIntegrations(program);

program.hook('preAction', async (_command, action) => {
  const options = program.opts();
  if (options['profile'] === undefined) return;
  const route: string[] = [];
  for (let current: Command | null = action; current && current !== program; current = current.parent) route.unshift(current.name());
  if (route[0] === 'auth' && route[1] === 'profiles') throw new ProfileCommandError('profile_selection_not_applicable');
  if (route[0] === 'auth' && (route[1] === 'login' || route[1] === 'logout')) throw new ProfileCommandError('profile_legacy_auth_unavailable');
  // Local manual forwarding and unavailable webhook management need no API
  // identity or credential. Commander handles help before action hooks.
  const cloud = ['end-users', 'devices', 'recordings', 'integrations', 'trigger', 'mcp'].includes(route[0] ?? '')
    || route[0] === 'auth' && route[1] === 'status';
  if (!cloud) return;
  // Preserve the existing fail-before-credentials behavior for unknown modes.
  if (route[0] === 'mcp' && !['legacy', 'hosted'].includes(action.opts()['mode'] as string)) return;
  const context = await resolveEnvironmentProfile({ name: options['profile'] as string,
    apiUrlOverride: options['apiUrl'] as string | undefined, readIdentity: readProfileIdentity });
  setProfileContext(context);
});

program.parseAsync(process.argv).catch((e: unknown) => {
  printError(e, Boolean(program.opts()['json']));
  process.exitCode = 1;
});
