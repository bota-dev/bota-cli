import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CONFIG_DIR = join(homedir(), '.bota');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const DEFAULT_API_URL = 'https://api.bota.dev';

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
  const config = readConfig();
  const key = config.apiKey ?? process.env['BOTA_API_KEY'];
  if (!key) {
    console.error('Not authenticated. Run: bota auth login <key>');
    process.exit(1);
  }
  return key;
}

export function getApiUrl(override?: string): string {
  if (override) return override;
  if (process.env['BOTA_API_URL']) return process.env['BOTA_API_URL'];
  const config = readConfig();
  return config.apiUrl ?? DEFAULT_API_URL;
}

export function getDashboardUrl(apiUrl: string): string {
  // api.bota.dev → dashboard.bota.dev, api.dev.bota.dev → dashboard.dev.bota.dev
  try {
    const u = new URL(apiUrl);
    u.hostname = u.hostname.replace(/^api\./, 'dashboard.');
    return u.origin;
  } catch {
    return 'https://dashboard.bota.dev';
  }
}
