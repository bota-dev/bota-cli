import { Command } from 'commander';
import { BotaClient } from '../client.js';
import { printTable, printJson, printDetail } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

interface Device {
  id: string;
  name: string;
  model: string;
  status: string;
  battery_level?: number;
  last_seen_at?: string;
  [key: string]: unknown;
}

interface ListResponse {
  data: Device[];
}

export function registerDevices(program: Command): void {
  const devices = program.command('devices').description('Manage devices');

  devices
    .command('list')
    .description('List devices')
    .option('--limit <n>', 'Max results', '20')
    .option('--end-user <eu_...>', 'Filter by end user ID')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.get<ListResponse>('/v1/devices', {
          limit: opts.limit,
          end_user_id: opts.endUser,
        });
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        printTable(
          ['id', 'name', 'model', 'status', 'battery_level', 'last_seen_at'],
          res.data.map(d => [
            d.id,
            d.name,
            d.model,
            d.status,
            d.battery_level !== undefined ? String(d.battery_level) : '',
            d.last_seen_at ?? '',
          ]),
        );
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  devices
    .command('get <id>')
    .description('Get device by ID')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const device = await client.get<Device>(`/v1/devices/${id}`);
        if (globalOpts['json']) {
          printJson(device);
          return;
        }
        printDetail(device as Record<string, unknown>);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  devices
    .command('stats')
    .description('Get fleet stats')
    .action(async () => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const stats = await client.get<Record<string, unknown>>('/v1/devices/stats');
        if (globalOpts['json']) {
          printJson(stats);
          return;
        }
        printDetail(stats);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });
}
