import { Command } from 'commander';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { BotaClient } from '../client.js';
import { info, ok, warn } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

const ALL_EVENTS = [
  'recording.created',
  'recording.uploaded',
  'recording.deleted',
  'recording.integrity_failure',
  'transcription.started',
  'transcription.completed',
  'transcription.failed',
  'summary.started',
  'summary.completed',
  'summary.failed',
  'device.claimed',
  'device.activated',
];

interface Webhook {
  id: string;
  url: string;
}

export function registerListen(program: Command): void {
  program
    .command('listen')
    .description('Forward webhook events to a local URL')
    .requiredOption('--forward-to <url>', 'Local URL to forward events to')
    .option('--event <type>', 'Event type to subscribe to (repeatable)', (v, prev: string[]) => [...prev, v], [] as string[])
    .option('--port <n>', 'Local port to listen on', '4242')
    .option('--tunnel-url <url>', 'Use this public URL instead of localtunnel')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const apiKey = getApiKey();
      const apiUrl = getApiUrl(globalOpts['apiUrl'] as string | undefined);
      const client = new BotaClient({ apiKey, apiUrl });
      const port = parseInt(opts.port, 10);
      const events: string[] = opts.event.length > 0 ? opts.event : ALL_EVENTS;
      const forwardTo: string = opts.forwardTo;

      let publicUrl: string;
      let tunnelClose: (() => void) | undefined;

      if (opts.tunnelUrl) {
        publicUrl = opts.tunnelUrl;
      } else {
        info('Starting tunnel...');
        try {
          const localtunnel = (await import('localtunnel')).default;
          const tunnel = await localtunnel({ port });
          publicUrl = tunnel.url;
          tunnelClose = () => tunnel.close();
          info(`Tunnel: ${publicUrl}`);
        } catch {
          warn('Failed to start localtunnel. Use --tunnel-url to provide your own public URL.');
          process.exit(1);
        }
      }

      const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', async () => {
          const body = Buffer.concat(chunks).toString();
          const timestamp = new Date().toISOString();
          let eventType = req.headers['x-bota-event'] ?? 'unknown';
          if (Array.isArray(eventType)) eventType = eventType[0];

          try {
            const fwdRes = await fetch(forwardTo, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body,
            });
            console.log(`[${timestamp}] ${eventType} → ${fwdRes.ok ? 'forwarded' : `failed (${fwdRes.status})`}`);
            res.writeHead(fwdRes.ok ? 200 : 502);
          } catch (e) {
            console.log(`[${timestamp}] ${eventType} → failed (${(e as Error).message})`);
            res.writeHead(502);
          }
          res.end();
        });
      });

      server.listen(port);

      let webhook: Webhook;
      try {
        webhook = await client.post<Webhook>('/v1/webhooks', { url: publicUrl, events });
      } catch (e) {
        console.error(`Failed to register webhook: ${(e as Error).message}`);
        server.close();
        tunnelClose?.();
        process.exit(1);
      }

      ok(`Listening for events → forwarding to ${forwardTo}`);
      ok(`Webhook registered: ${webhook.id}`);

      const cleanup = async () => {
        info('Shutting down...');
        try {
          await client.delete(`/v1/webhooks/${webhook.id}`);
          ok('Webhook deleted');
        } catch {
          warn('Failed to delete webhook');
        }
        server.close();
        tunnelClose?.();
        process.exit(0);
      };

      process.on('SIGINT', () => { void cleanup(); });
      process.on('SIGTERM', () => { void cleanup(); });
    });
}
