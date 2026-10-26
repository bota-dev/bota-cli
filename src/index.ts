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
import { registerSecureProfiles, SecureProfileCommandError } from './commands/secure-profiles.js';
import * as secureProfileService from './secure-profiles.js';
import { registerDeveloperProfiles } from './commands/developer-profiles.js';
import { developerProfileService } from './developer-profile-production.js';
import { DeveloperProfileError } from './developer-profile-error.js';
import { validateDeveloperDeploymentCommand, withDeveloperDeploymentSelection } from './developer-deployment-selection.js';

const program = new Command();
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

program
  .name('bota')
  .description('Bota developer CLI')
  .version(version)
  .option('--api-url <url>', 'Override API base URL')
  .option('--dashboard-url <url>', 'Reserved compatibility option; browser key export is retired')
  .option('--profile <name>', 'Explicit environment-only profile; verify its origin/project before cloud operations')
  .option('--secure-profile <name>', 'Explicit OS-stored project profile; verify current credentials for every action or MCP request')
  .option('--developer-profile <name>', 'Explicit protected Platform developer session shared by CLI and hosted-mode local MCP')
  .option('--developer-deployment <name>', 'Explicit source-owned developer deployment: dev or prod; omission remains configuration off')
  .option('--json', 'Output raw JSON');

const auth = registerAuth(program);
registerProfiles(auth, program);
registerSecureProfiles(auth, program, secureProfileService);
registerDeveloperProfiles(auth, program, developerProfileService);
registerEndUsers(program);
registerDevices(program);
registerRecordings(program);
registerWebhooks(program);
registerListen(program);
registerTrigger(program);
registerMcp(program);
registerIntegrations(program);

program.hook('preAction', async (_command, action) => {
  validateDeveloperDeploymentCommand(program, action);
  const options = program.opts();
  const secure = options['secureProfile'] !== undefined;
  const developer = options['developerProfile'] !== undefined;
  if (developer && ['profile', 'secureProfile', 'apiUrl', 'dashboardUrl'].some(name => options[name] !== undefined)) throw new DeveloperProfileError('developer_profile_invalid');
  if (secure && options['profile'] !== undefined) throw new ProfileCommandError('profile_selection_not_applicable');
  if (!secure && !developer && options['profile'] === undefined) return;
  const route: string[] = [];
  for (let current: Command | null = action; current && current !== program; current = current.parent) route.unshift(current.name());
  if (route[0] === 'auth' && ['profiles', 'secure-profiles', 'developer-profiles'].includes(route[1] ?? '')) throw new ProfileCommandError('profile_selection_not_applicable');
  if (developer) {
    if (route[0] === 'mcp' && action.opts()['mode'] !== 'hosted') throw new DeveloperProfileError('developer_mcp_hosted_required');
    if (!['end-users', 'devices', 'recordings', 'mcp'].includes(route[0] ?? '') && !(route[0] === 'auth' && ['login', 'logout', 'status'].includes(route[1] ?? '')))
      throw new DeveloperProfileError('developer_profile_invalid');
    return;
  }
  if (route[0] === 'auth' && (route[1] === 'login' || route[1] === 'logout')) throw new ProfileCommandError('profile_legacy_auth_unavailable');
  // Local manual forwarding and unavailable webhook management need no API
  // identity or credential. Commander handles help before action hooks.
  const cloud = ['end-users', 'devices', 'recordings', 'integrations', 'trigger', 'mcp'].includes(route[0] ?? '')
    || route[0] === 'auth' && route[1] === 'status';
  if (!cloud) return;
  // Preserve the existing fail-before-credentials behavior for unknown modes.
  if (route[0] === 'mcp' && !['legacy', 'hosted'].includes(action.opts()['mode'] as string)) return;
  // The secure action wrapper owns the lease through the action. MCP resolves
  // each request separately; startup never captures a stored bearer.
  if (secure) return;
  const context = await resolveEnvironmentProfile({ name: options['profile'] as string,
    apiUrlOverride: options['apiUrl'] as string | undefined, readIdentity: readProfileIdentity });
  setProfileContext(context);
});

const developerArguments = process.argv.some(value => value === 'developer-profiles' || value === '--developer-profile' || value.startsWith('--developer-profile=')
  || value === '--developer-deployment' || value.startsWith('--developer-deployment='))
  || process.argv.includes('auth') && process.argv.includes('login');
const privateArguments = developerArguments || process.argv.some(value => value === 'secure-profiles' || value === '--secure-profile' || value.startsWith('--secure-profile='));
if (privateArguments) program.configureOutput({ outputError: () => printError(developerArguments ? new DeveloperProfileError('developer_profile_invalid') : new SecureProfileCommandError('invalid_secure_profile_command'), Boolean(program.opts()['json'])) });
withDeveloperDeploymentSelection(() => program.opts()['developerDeployment'], () => program.parseAsync(process.argv)).catch((e: unknown) => {
  if (privateArguments && e && typeof e === 'object' && 'code' in e && typeof e.code === 'string' && e.code.startsWith('commander.')) {
    e = developerArguments ? new DeveloperProfileError('developer_profile_invalid') : new SecureProfileCommandError('invalid_secure_profile_command');
  }
  printError(e, Boolean(program.opts()['json']));
  process.exitCode ??= 1;
});
