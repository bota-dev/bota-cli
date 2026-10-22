import { withCommandAuth } from '../invocation-auth.js';
import { Command } from 'commander';
import { createCommandClient } from '../client.js';
import { printTable, printJson, printDetail, printPagination, handleCommandFailure } from '../output.js';

interface Device {
  id: string;
  name: string;
  model: string;
  status: string;
  battery_percent?: number | null;
  last_heartbeat_at?: string | null;
  [key: string]: unknown;
}

interface ListResponse {
  data: Device[];
  has_more?: boolean;
  next_cursor?: string;
}

export function registerDevices(program: Command): void {
  const devices = program.command('devices').description('Manage devices');

  devices
    .command('list')
    .description('List devices')
    .option('--limit <n>', 'Max results', '20')
    .option('--cursor <c>', 'Pagination cursor')
    .option('--end-user <eu_...>', 'Filter by end user ID')
    .action(withCommandAuth(program, async (opts) => {
      const globalOpts = program.opts();
      const client = createCommandClient(globalOpts['apiUrl'] as string | undefined);
      try {
        const res = await client.get<ListResponse>('/v1/devices', {
          limit: opts.limit,
          cursor: opts.cursor,
          end_user_id: opts.endUser,
        });
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        printTable(
          ['id', 'name', 'model', 'status', 'battery_percent', 'last_heartbeat_at'],
          res.data.map(d => [
            d.id,
            d.name,
            d.model,
            d.status,
            d.battery_percent != null ? String(d.battery_percent) : '',
            d.last_heartbeat_at ?? '',
          ]),
        );
        printPagination(res);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));

  devices
    .command('get <id>')
    .alias('inspect')
    .description('Get device by ID')
    .action(withCommandAuth(program, async (id: string) => {
      const globalOpts = program.opts();
      const client = createCommandClient(globalOpts['apiUrl'] as string | undefined);
      try {
        const device = await client.get<Device>(`/v1/devices/${id}`);
        if (globalOpts['json']) {
          printJson(device);
          return;
        }
        printDetail(device as Record<string, unknown>);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));

  devices
    .command('stats')
    .description('Get fleet stats')
    .action(withCommandAuth(program, async () => {
      const globalOpts = program.opts();
      const client = createCommandClient(globalOpts['apiUrl'] as string | undefined);
      try {
        const stats = await client.get<Record<string, unknown>>('/v1/devices/stats');
        if (globalOpts['json']) {
          printJson(stats);
          return;
        }
        printDetail(stats);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));
}
