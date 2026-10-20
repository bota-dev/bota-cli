import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { ProjectIdentity } from './client.js';

const CONFIG_DIR = join(homedir(), '.bota');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const DEFAULT_API_URL = 'https://api.bota.dev';

interface ProfileContext {
  apiKey: string;
  apiUrl: string;
  identity: ProjectIdentity;
}

// A selected profile is resolved once before its command. It never reads or
// updates the legacy credential file, and it is not a saved default selection.
let profileContext: Readonly<ProfileContext> | undefined;

export function setProfileContext(context: ProfileContext): void {
  profileContext = Object.freeze({ ...context });
}

export function getProfileContext(): Readonly<ProfileContext> | undefined {
  return profileContext;
}

interface Config {
  apiKey?: string;
  apiUrl?: string;
}

export function readConfig(): Config {
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function writeConfig(config: Config): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

export function getApiKey(): string {
  if (profileContext) return profileContext.apiKey;
  const config = readConfig();
  const key = config.apiKey ?? process.env['BOTA_API_KEY'];
  if (!key) {
    console.error('Not authenticated. Run: bota auth login <key>');
    process.exit(1);
  }
  return key;
}

export function getApiUrl(override?: string): string {
  if (profileContext) return profileContext.apiUrl;
  if (override) return override;
  if (process.env['BOTA_API_URL']) return process.env['BOTA_API_URL'];
  const config = readConfig();
  return config.apiUrl ?? DEFAULT_API_URL;
}

export function getDashboardUrl(apiUrl: string): string {
  // api.bota.dev → platform.bota.dev, api.dev.bota.dev → platform.dev.bota.dev
  try {
    const u = new URL(apiUrl);
    u.hostname = u.hostname.replace(/^api\./, 'platform.');
    return u.origin;
  } catch {
    return 'https://platform.bota.dev';
  }
}
