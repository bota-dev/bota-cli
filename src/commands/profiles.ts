import { Command } from 'commander';
import { enrollEnvironmentProfile, listEnvironmentProfiles, removeEnvironmentProfile } from '../profiles.js';
import { readProfileIdentity } from '../profile-identity.js';
import { printError } from '../output.js';

const commandMessages = {
  profile_selection_not_applicable: 'Use explicit profile names for profile management; omit the global --profile option.',
  profile_legacy_auth_unavailable: 'Profile mode cannot run legacy auth login or logout. Add or remove an explicitly named environment profile instead.',
  invalid_profile_command: 'Invalid profile command. Run bota auth profiles --help; credentials are accepted only from BOTA_API_KEY.',
  profile_api_url_required: 'Profile enrollment requires an explicit --api-url for its trusted API origin.',
} as const;

export class ProfileCommandError extends Error {
  constructor(readonly code: keyof typeof commandMessages) { super(commandMessages[code]); }
}

function printProfileJson(value: unknown): void {
  // Opaque IDs retain their exact values while terminal control characters
  // remain JSON escapes, including C1 and Unicode direction/line controls.
  console.log(JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`));
}

export function registerProfiles(auth: Command, program: Command): void {
  const profiles = new Command('profiles').description('Manage explicitly selected environment-only project profiles')
    .allowExcessArguments(false)
    .configureOutput({ outputError: () => printError(new ProfileCommandError('invalid_profile_command'), Boolean(program.opts()['json'])) });
  auth.addCommand(profiles);
  const show = printProfileJson;
  profiles.command('add <name>').allowExcessArguments(false)
    .description('Save origin/project metadata after verifying BOTA_API_KEY; requires explicit --api-url and never saves the key')
    .requiredOption('--from-env', 'Use only BOTA_API_KEY for enrollment')
    .option('--allow-http-loopback', 'Explicitly permit a literal loopback HTTP API origin')
    .action(async (name: string, options: { allowHttpLoopback?: boolean }) => {
      const apiUrl = program.opts()['apiUrl'] as string | undefined;
      if (apiUrl === undefined) throw new ProfileCommandError('profile_api_url_required');
      show(await enrollEnvironmentProfile({ name, apiUrl,
        allowHttpLoopback: options.allowHttpLoopback, readIdentity: readProfileIdentity }));
    });
  profiles.command('list').allowExcessArguments(false).description('List saved non-secret profile metadata without reading a credential')
    .action(async () => { show(await listEnvironmentProfiles()); });
  profiles.command('remove <name>').allowExcessArguments(false).description('Remove local profile metadata; does not revoke the environment credential')
    .action(async (name: string) => { await removeEnvironmentProfile(name); show({ removed: true }); });
}
