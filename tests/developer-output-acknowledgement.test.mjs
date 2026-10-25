import assert from 'node:assert/strict';
import test from 'node:test';
import { Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer, createConnection } from 'node:net';
import { acknowledgeDeveloperOutput, writeDeveloperWritableOutput } from '../src/developer-output-acknowledgement.ts';
import { DeveloperProfileError, developerProfileFailure } from '../src/developer-profile-error.ts';

const defer = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
const refused = code => error => {
  assert.equal(developerProfileFailure(error)?.code, code);
  assert.doesNotMatch(error.stack + JSON.stringify(error), /PRIVATE_/); return true;
};

test('pre-aborted output never invokes its writer', async () => {
  const controller = new AbortController(); controller.abort('PRIVATE_ABORT'); let writes = 0;
  await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', async () => { writes++; }, () => {}, controller.signal), refused('developer_cancelled'));
  assert.equal(writes, 0);
});

test('a never-settling acknowledgement refuses at the fixed five-second ceiling', { timeout: 10_000 }, async () => {
  let writes = 0; const start = performance.now();
  await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', () => { writes++; return new Promise(() => {}); }, () => {}), refused('developer_output_failed'));
  assert.equal(writes, 1); assert.ok(performance.now() - start >= 4_900); assert.ok(performance.now() - start < 9_000);
});

test('original guard withdrawal refuses a pending writer without waiting for completion', async () => {
  const started = defer(), held = defer(); let active = true, checks = 0;
  const result = acknowledgeDeveloperOutput('stdout', 'public', async () => { started.resolve(); await held.promise; }, () => {
    checks++; if (!active) throw new DeveloperProfileError('developer_deadline');
  });
  void result.catch(() => {}); await started.promise; active = false;
  await assert.rejects(result, refused('developer_deadline')); assert.ok(checks >= 3);
  held.resolve(); await turn();
});

test('late native callback success cannot change a cancelled acknowledgement', async () => {
  const started = defer(), controller = new AbortController(); let callback, native, success = false;
  const stream = new Writable({ write(_chunk, _encoding, done) { callback = done; started.resolve(); } });
  const result = acknowledgeDeveloperOutput('stdout', 'public', () => { native = writeDeveloperWritableOutput(stream, 'public'); return native; }, () => {}, controller.signal)
    .then(() => { success = true; });
  void result.catch(() => {}); await started.promise; controller.abort('PRIVATE_REASON');
  await assert.rejects(result, refused('developer_cancelled'));
  assert.equal(stream.destroyed, false); assert.equal(stream.listenerCount('error'), 1);
  callback(); await native; await turn(); assert.equal(success, false); assert.equal(stream.listenerCount('error'), 0);
  stream.destroy();
});

test('late native callback failure keeps its error observer through the deferred event', async () => {
  const started = defer(), controller = new AbortController(); let callback, native;
  const stream = new Writable({ write(_chunk, _encoding, done) { callback = done; started.resolve(); } });
  const result = acknowledgeDeveloperOutput('stderr', 'public', () => { native = writeDeveloperWritableOutput(stream, 'public'); return native; }, () => {}, controller.signal);
  void result.catch(() => {}); await started.promise; controller.abort();
  await assert.rejects(result, refused('developer_cancelled')); assert.equal(stream.listenerCount('error'), 1);
  callback(Error('PRIVATE_NATIVE_WRITE')); await assert.rejects(native, refused('developer_output_failed'));
  await turn(); assert.equal(stream.listenerCount('error'), 0);
});

test('ordinary callback error and its deferred event yield only the fixed output failure', async () => {
  const stream = new Writable({ write(_chunk, _encoding, done) { done(Error('PRIVATE_CALLBACK')); } });
  await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', () => writeDeveloperWritableOutput(stream, 'public'), () => {}), refused('developer_output_failed'));
  assert.equal(stream.listenerCount('error'), 0);
});

test('unknown writer rejection, including undefined, is observed and safely projected', async () => {
  for (const value of [undefined, Error('PRIVATE_WRITER')]) {
    await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', async () => { throw value; }, () => {}), refused('developer_operation_failed'));
  }
});

test('proxy signal and writer refuse without private hooks', async () => {
  let hooks = 0; const traps = { get() { hooks++; throw Error('PRIVATE_PROXY'); }, getPrototypeOf() { hooks++; throw Error('PRIVATE_PROXY'); }, apply() { hooks++; throw Error('PRIVATE_PROXY'); } };
  await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', async () => {}, () => {}, new Proxy(new AbortController().signal, traps)), refused('developer_output_failed'));
  await assert.rejects(acknowledgeDeveloperOutput('stdout', 'public', new Proxy(async () => {}, traps), () => {}), refused('developer_output_failed'));
  assert.equal(hooks, 0);
});

test('owned asynchronous native socket write stays observed after cancellation until the peer drains', { timeout: 15_000 }, async () => {
  const accepted = defer(); let peer, native, bytes = 0;
  const server = createServer(socket => { peer = socket; socket.pause(); accepted.resolve(); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const socket = createConnection({ host: '127.0.0.1', port: server.address().port });
  const closed = once(socket, 'close'), controller = new AbortController(), entered = defer();
  const watchdog = setTimeout(() => { socket.destroy(); peer?.destroy(); }, 10_000);
  try {
    await accepted.promise;
    const before = socket.listenerCount('error');
    const result = acknowledgeDeveloperOutput('stdout', 'public', () => {
      native = writeDeveloperWritableOutput(socket, 'x'.repeat(16 * 1024 * 1024)); entered.resolve(); return native;
    }, () => {}, controller.signal);
    void result.catch(() => {}); await entered.promise; controller.abort();
    await assert.rejects(result, refused('developer_cancelled'));
    assert.equal(socket.destroyed, false); assert.equal(socket.listenerCount('error'), before + 1);
    const ended = once(peer, 'end'); peer.on('data', chunk => { bytes += chunk.length; }); peer.resume();
    await native; assert.equal(socket.listenerCount('error'), before); socket.end(); await ended; await closed;
    assert.equal(bytes, 16 * 1024 * 1024);
  } finally {
    clearTimeout(watchdog);
    socket.destroy(); peer?.destroy(); await closed;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('owned child asynchronous stdout pipe stays observed after refusal and joins after reader resumes', {
  timeout: 20_000, skip: process.platform === 'win32' ? 'Windows process pipes use synchronous writes; JavaScript timers cannot interrupt them.' : false,
}, async () => {
  const module = new URL('../src/developer-output-acknowledgement.ts', import.meta.url).href;
  const errorModule = new URL('../src/developer-profile-error.ts', import.meta.url).href;
  const source = `
    import { acknowledgeDeveloperOutput, writeDeveloperWritableOutput } from ${JSON.stringify(module)};
    import { developerProfileFailure } from ${JSON.stringify(errorModule)};
    const controller = new AbortController(), before = process.stdout.listenerCount('error'); let native, success = false;
    const timer = setTimeout(() => controller.abort(), 150);
    try {
      await acknowledgeDeveloperOutput('stdout', 'public', () => {
        native = writeDeveloperWritableOutput(process.stdout, 'x'.repeat(16 * 1024 * 1024)); return native;
      }, () => {}, controller.signal); success = true;
    } catch (error) {
      if (developerProfileFailure(error)?.code !== 'developer_cancelled') throw error;
      process.stderr.write('ACK_REFUSED\\n');
    } finally { clearTimeout(timer); }
    if (success || process.stdout.listenerCount('error') !== before + 1 || process.stdout.destroyed) throw Error('Unexpected output acknowledgement');
    await native;
    if (process.stdout.listenerCount('error') !== before) throw Error('Unjoined write observer');
    process.stderr.write('NATIVE_JOINED_NO_SUCCESS\\n');
  `;
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => /^(PATH|SYSTEMROOT|WINDIR|COMSPEC|PATHEXT|TEMP|TMP)$/i.test(name)));
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source], { cwd: new URL('..', import.meta.url), env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = once(child, 'close'); let stderr = '', bytes = 0; const refusedAck = defer();
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr += chunk; if (stderr.includes('ACK_REFUSED\n')) refusedAck.resolve(); });
  const timeout = setTimeout(() => { refusedAck.resolve(); child.kill(); }, 15_000);
  try {
    await Promise.race([refusedAck.promise, closed]);
    assert.match(stderr, /ACK_REFUSED/); assert.doesNotMatch(stderr, /NATIVE_JOINED/);
    child.stdout.on('data', chunk => { bytes += chunk.length; }); child.stdout.resume();
    const [code, signal] = await closed; assert.equal(code, 0, stderr); assert.equal(signal, null);
    assert.equal(bytes, 16 * 1024 * 1024); assert.match(stderr, /NATIVE_JOINED_NO_SUCCESS/);
  } finally {
    clearTimeout(timeout);
    if (child.exitCode === null && child.signalCode === null) child.kill();
    child.stdout.resume(); await closed;
  }
});
