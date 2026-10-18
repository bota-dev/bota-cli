import { Command } from 'commander';
import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import { WEBHOOK_MANAGEMENT_UNAVAILABLE } from './webhooks.js';

export const MAX_WEBHOOK_BYTES = 1024 * 1024;

function parseUrl(value: string, loopback: boolean): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Webhook URL must be a valid HTTP or HTTPS URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Webhook URL must use HTTP or HTTPS without embedded credentials.');
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (loopback && !(hostname === 'localhost' || hostname === '::1' || (isIP(hostname) === 4 && hostname.startsWith('127.')))) {
    throw new Error('--forward-to must be a loopback URL (localhost, 127.0.0.0/8, or [::1]).');
  }
  return url;
}

function reply(res: ServerResponse, status: number): void {
  if (!res.destroyed && !res.writableEnded) { res.writeHead(status); res.end(); }
}

// The lifecycle belongs to the caller so shutdown can join every in-flight fetch.
export function createWebhookForwarder(forwardTo: string): { handler: RequestListener; close: () => Promise<void> } {
  const destination = parseUrl(forwardTo, true);
  const requests = new Set<IncomingMessage>();
  const controllers = new Set<AbortController>();
  const pending = new Set<Promise<void>>();
  let closing = false;
  const handler: RequestListener = (req, res) => {
    if (closing) { reply(res, 503); return; }
    if (req.method !== 'POST') { req.resume(); reply(res, 405); return; }
    requests.add(req);
    res.once('close', () => requests.delete(req));
    let bytes = 0;
    let oversized = false;
    const chunks: Buffer[] = [];
    req.on('error', () => reply(res, 400));
    req.on('data', (chunk: Buffer) => {
      if (oversized || closing) return;
      bytes += chunk.length;
      if (bytes > MAX_WEBHOOK_BYTES) {
        oversized = true;
        chunks.length = 0;
        reply(res, 413);
        console.log('Webhook rejected: body exceeds 1 MiB.');
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (oversized || closing) return;
      const body = Buffer.concat(chunks);
      const headers: Record<string, string> = { 'Content-Type': req.headers['content-type'] ?? 'application/json' };
      for (const name of ['x-bota-signature', 'x-bota-timestamp', 'x-bota-event-id']) {
        const value = req.headers[name];
        if (typeof value === 'string') headers[name] = value;
      }
      const controller = new AbortController();
      controllers.add(controller);
      const timer = setTimeout(() => controller.abort(), 10_000);
      const operation = (async () => {
        try {
          const forwarded = await fetch(destination, { method: 'POST', headers, body: new Uint8Array(body), redirect: 'error', signal: controller.signal });
          reply(res, forwarded.ok ? 200 : 502);
          await forwarded.body?.cancel().catch(() => undefined);
          console.log(forwarded.ok ? 'Webhook forwarded.' : `Webhook forwarding rejected (HTTP ${forwarded.status}).`);
        } catch {
          reply(res, 502);
          console.log(closing ? 'Webhook forwarding cancelled during shutdown.' : 'Webhook forwarding failed.');
        } finally {
          clearTimeout(timer);
          controllers.delete(controller);
        }
      })();
      pending.add(operation);
      void operation.finally(() => pending.delete(operation));
    });
  };
  return {
    handler,
    close: async () => {
      closing = true;
      for (const controller of controllers) controller.abort();
      for (const req of requests) req.destroy();
      await Promise.all(pending);
    },
  };
}

export function registerListen(program: Command): void {
  program.command('listen')
    .description('Forward webhooks through a manually configured tunnel and Platform endpoint')
    .option('--manual', 'Use an existing tunnel and configure the webhook separately in Bota Platform')
    .requiredOption('--forward-to <url>', 'HTTP(S) loopback receiver URL')
    .option('--event <type>', 'Legacy automatic subscription flag (unavailable in manual mode)', (v, prev: string[]) => [...prev, v], [] as string[])
    .option('--port <n>', 'Loopback listener port (0 chooses an available port)', '4242')
    .option('--tunnel-url <url>', 'Existing public tunnel URL (informational; no tunnel is created)')
    .action(async (opts: { manual?: boolean; forwardTo: string; event: string[]; port: string; tunnelUrl?: string }) => {
      if (!opts.manual) throw new Error(`${WEBHOOK_MANAGEMENT_UNAVAILABLE} Use listen --manual with an existing tunnel and a Platform-configured webhook.`);
      if (opts.event.length) throw new Error('--event is unavailable in manual mode. Configure subscribed events in Bota Platform.');
      parseUrl(opts.forwardTo, true);
      if (opts.tunnelUrl) parseUrl(opts.tunnelUrl, false);
      if (!/^\d+$/.test(opts.port) || Number(opts.port) > 65535) throw new Error('--port must be an integer from 0 to 65535.');
      const forwarder = createWebhookForwarder(opts.forwardTo);
      const server = createServer(forwarder.handler);
      server.requestTimeout = 30_000;
      server.headersTimeout = 10_000;
      let stop!: () => void;
      const stopped = new Promise<void>(resolve => { stop = resolve; });
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject);
          server.listen(Number(opts.port), '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
        });
        const address = server.address();
        console.log(`Manual webhook listener: http://127.0.0.1:${typeof address === 'object' && address ? address.port : opts.port}`);
        console.log('Point your existing tunnel at this listener, then configure its public destination and events in Bota Platform.');
        if (opts.tunnelUrl) console.log('Existing tunnel URL supplied; no tunnel or webhook registration was created.');
        console.log('Bodies are limited to 1 MiB. Press Ctrl+C to stop.');
        await stopped;
      } finally {
        process.removeListener('SIGINT', stop);
        process.removeListener('SIGTERM', stop);
        const closed = new Promise<void>(resolve => server.close(() => resolve()));
        await forwarder.close();
        server.closeAllConnections();
        await closed;
        console.log('Manual webhook listener stopped.');
      }
    });
}
