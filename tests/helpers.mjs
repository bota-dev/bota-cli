import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const workspace = dirname(dirname(fileURLToPath(import.meta.url)));

export async function fixture(t, handler) {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const request = { method: req.method, url: req.url, headers: req.headers, body };
    requests.push(request);
    await handler(request, res);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  return { url: `http://127.0.0.1:${server.address().port}`, requests };
}

export function json(res, value, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(value));
}

export async function isolatedEnvironment(t, apiUrl) {
  const home = await mkdtemp(join(tmpdir(), 'bota-cli-contract-'));
  t.after(async () => {
    const location = relative(tmpdir(), home);
    if (location.startsWith('..') || isAbsolute(location)) throw new Error('Unexpected fixture directory');
    await rm(home, { recursive: true, force: true });
  });
  return {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    BOTA_API_KEY: 'sk_test_fixture',
    BOTA_API_URL: apiUrl,
    NO_COLOR: '1',
    FORCE_COLOR: '0',
  };
}

export async function runCli(t, apiUrl, args) {
  const env = await isolatedEnvironment(t, apiUrl);
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--api-url', apiUrl, ...args], {
    cwd: workspace,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const timer = setTimeout(() => child.kill(), 12_000);
  try {
    const [code, signal] = await once(child, 'close');
    return { code, signal, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}
