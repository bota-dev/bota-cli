import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { fixture, isolatedEnvironment, json, runCli, workspace } from './helpers.mjs';

async function startListener(t, apiUrl, destination, extra = []) {
  const env = await isolatedEnvironment(t, apiUrl);
  delete env.BOTA_API_KEY;
  const child = spawn(process.execPath, ['--import', 'tsx', '--import', './tests/fixtures/signal-relay.mjs', 'src/index.ts', '--api-url', apiUrl, 'listen', '--manual', '--forward-to', destination, '--port', '0', ...extra], {
    cwd: workspace, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const exited = once(child, 'close');
  let finished = false;
  void exited.then(() => { finished = true; });
  t.after(async () => {
    if (!finished) child.kill();
    await exited;
  });
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Listener did not start: ${stderr}`)), 10_000);
    const read = () => {
      const match = stdout.match(/Manual webhook listener: (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); child.stdout.off('data', read); resolve(match[1]); }
    };
    child.stdout.on('data', read);
    void exited.then(([code]) => { clearTimeout(timer); reject(new Error(`Listener exited ${code}: ${stderr}`)); });
  });
  return {
    url,
    output: () => ({ stdout, stderr }),
    stop: async signal => {
      // The production SIGINT/SIGTERM handlers run inside the real subprocess.
      child.send(signal);
      const timer = setTimeout(() => child.kill(), 5000);
      try { return await exited; } finally { clearTimeout(timer); }
    },
  };
}

test('manual listen forwards a real signed webhook without API credentials, registration, or tunnel requests', async t => {
  const api = await fixture(t, (_req, res) => json(res, { error: 'must not be called' }, 500));
  const tunnel = await fixture(t, (_req, res) => json(res, { error: 'must not be called' }, 500));
  const body = '{ "type": "unsafe\\nEVENT_SECRET",\n "data": {"name":"音声"} }\n';
  const timestamp = '1792285200';
  const signature = createHmac('sha256', 'fixture-secret').update(`${timestamp}.${body}`).digest('hex');
  const receiver = await fixture(t, (req, res) => {
    assert.equal(req.body, body);
    assert.equal(req.headers['x-bota-signature'], `v1=${createHmac('sha256', 'fixture-secret').update(`${req.headers['x-bota-timestamp']}.${req.body}`).digest('hex')}`);
    assert.equal(req.headers['x-bota-timestamp'], timestamp);
    assert.equal(req.headers['x-bota-event-id'], 'evt_fixture');
    assert.equal(req.headers.authorization, undefined);
    json(res, { accepted: true });
  });
  const listener = await startListener(t, api.url, `${receiver.url}/secret-target?token=TARGET_SECRET`, ['--tunnel-url', `${tunnel.url}/hook?token=TUNNEL_SECRET`]);
  assert.equal((await fetch(listener.url, { method: 'POST', body, headers: { 'Content-Type': 'application/json', 'X-Bota-Signature': `v1=${signature}`, 'X-Bota-Timestamp': timestamp, 'X-Bota-Event-Id': 'evt_fixture', Authorization: 'Bearer AUTH_SECRET' } })).status, 200);
  assert.deepEqual(await listener.stop('SIGINT'), [0, null]);
  assert.equal(receiver.requests.length, 1);
  assert.equal(api.requests.length, 0);
  assert.equal(tunnel.requests.length, 0);
  const { stdout, stderr } = listener.output();
  assert.match(stdout, /Webhook forwarded\./);
  assert.match(stdout, /Manual webhook listener stopped\./);
  assert.doesNotMatch(stdout + stderr, /EVENT_SECRET|TARGET_SECRET|TUNNEL_SECRET|AUTH_SECRET|fixture-secret/);
  await assert.rejects(fetch(listener.url));
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  test(`manual listen joins ${signal} shutdown and aborts an in-flight receiver request`, async t => {
    let received;
    const started = new Promise(resolve => { received = resolve; });
    let disconnected;
    const closed = new Promise(resolve => { disconnected = resolve; });
    const receiver = createServer((req, res) => {
      req.resume();
      res.once('close', disconnected);
      received();
      // Deliberately do not respond: listener shutdown must cancel this fetch.
    });
    receiver.listen(0, '127.0.0.1');
    await once(receiver, 'listening');
    t.after(() => new Promise(resolve => { receiver.closeAllConnections(); receiver.close(resolve); }));
    const api = await fixture(t, (_req, res) => json(res, {}));
    const listener = await startListener(t, api.url, `http://127.0.0.1:${receiver.address().port}`);
    const delivery = fetch(listener.url, { method: 'POST', body: '{}' }).catch(() => undefined);
    await started;
    assert.deepEqual(await listener.stop(signal), [0, null]);
    await delivery;
    await closed;
    assert.match(listener.output().stdout, /cancelled during shutdown/);
    assert.equal(api.requests.length, 0);
    await assert.rejects(fetch(listener.url));
  });
}

test('manual listen rejects unsupported subscriptions, destinations, tunnel URLs, and ports before requests', async t => {
  const api = await fixture(t, (_req, res) => json(res, {}));
  const cases = [
    ['--forward-to', api.url, '--event', 'recording.uploaded'],
    ['--forward-to', 'https://example.com/hook'],
    ['--forward-to', 'http://user:TARGET_SECRET@127.0.0.1/hook'],
    ['--forward-to', 'file:///tmp/hook'],
    ['--forward-to', api.url, '--tunnel-url', 'https://user:TUNNEL_SECRET@example.com'],
    ['--forward-to', api.url, '--port', '65536'],
    ['--forward-to', api.url, '--port', '1.5'],
  ];
  for (const args of cases) {
    const result = await runCli(t, api.url, ['listen', '--manual', ...args]);
    assert.equal(result.code, 1, result.stderr);
    assert.doesNotMatch(result.stdout, /Manual webhook listener:/);
    assert.doesNotMatch(result.stdout + result.stderr, /TARGET_SECRET|TUNNEL_SECRET/);
  }
  assert.equal(api.requests.length, 0);
});
