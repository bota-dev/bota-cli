import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawnSync } from 'node:child_process';
import { Writable } from 'node:stream';
import test from 'node:test';
import { readSecureKey, SecureKeyInputError } from '../src/secure-key-input.ts';

const key = 'rk_SECURE_INPUT_CANARY';
class Input extends EventEmitter {
  constructor(tty = false, raw = false) { super(); this.isTTY = tty; this.isRaw = raw; this.paused = true; this.rawCalls = []; }
  isPaused() { return this.paused; }
  resume() { this.paused = false; return this; }
  pause() { this.paused = true; if (this.pauseError) throw Error(key); return this; }
  setRawMode(value) { this.rawCalls.push(value); this.isRaw = value; if (this.rawErrorAt === this.rawCalls.length) throw Error(key); return this; }
}
class Output extends EventEmitter {
  constructor(tty = true) { super(); this.isTTY = tty; this.text = ''; }
  write(value, callback) { if (this.writeError) throw Error(key); this.text += value; queueMicrotask(() => callback?.()); return true; }
}
function safeCode(code) {
  return error => { assert.ok(error instanceof SecureKeyInputError); assert.equal(error.code, code);
    assert.doesNotMatch(String(error), /CANARY/); assert.equal(error.cause, undefined); return true; };
}
function run(chunks, options = {}) {
  const input = options.input ?? new Input();
  const result = readSecureKey({ mode: 'stdin', input, ...options });
  queueMicrotask(() => { for (const chunk of chunks) input.emit('data', chunk); input.emit('end'); });
  return result;
}
function clean(input, output) {
  for (const event of ['data', 'end', 'error', 'close']) assert.equal(input.listenerCount(event), 0, event);
  if (output) assert.equal(output.listenerCount('error'), 0);
}

test('piped key supports exact bytes and exactly one optional LF or CRLF across chunks', async () => {
  for (const chunks of [[key], [key, '\n'], [key, '\r', '\n'], ['x'.repeat(2560)], ['x'.repeat(2560), '\r\n']]) {
    const input = new Input();
    assert.equal(await run(chunks, { input }), chunks[0]);
    assert.equal(input.paused, true); clean(input);
  }
});

test('stdin rejects empty, multi-line, controls, Unicode and overflow without reflecting input', async () => {
  for (const value of ['', '\n', `${key}\r`, `${key}\n\n`, `${key}\r\n\r\n`, `${key}\nSECOND`,
    `${key} `, `${key}\t`, `${key}\0`, `${key}\x1b`, `${key}\x7f`, `${key}é`, 'x'.repeat(2561), 'x'.repeat(30000)]) {
    const input = new Input();
    await assert.rejects(run([Buffer.from(value)], { input }), safeCode('secure_key_invalid')); clean(input);
  }
  await assert.rejects(run([Buffer.from([0xff])]), safeCode('secure_key_invalid'));
});

test('stdin validates all chunks through EOF and cannot accept a valid prefix before later secret data', async () => {
  for (const chunks of [[key, '\n', 'EXTRA'], ['x'.repeat(2560), 'x', 'x'], [key, '\n', Buffer.alloc(5000)]]) {
    await assert.rejects(run(chunks), safeCode('secure_key_invalid'));
  }
});

test('interactive and pipe modes cannot silently change one another', async () => {
  const tty = new Input(true), output = new Output();
  await assert.rejects(readSecureKey({ mode: 'stdin', input: tty }), safeCode('secure_key_stdin_required'));
  await assert.rejects(readSecureKey({ mode: 'prompt', input: new Input(), output }), safeCode('secure_key_tty_required'));
  await assert.rejects(readSecureKey({ mode: 'prompt', input: tty, output: new Output(false) }), safeCode('secure_key_tty_required'));
  const noRaw = new Input(true); noRaw.setRawMode = undefined;
  await assert.rejects(readSecureKey({ mode: 'prompt', input: noRaw, output }), safeCode('secure_key_tty_required'));
  assert.deepEqual(tty.rawCalls, []); assert.equal(output.text, '');
});

test('hidden prompt writes only to error terminal and restores prior raw/pause state after Enter', async () => {
  for (const priorRaw of [false, true]) {
    const input = new Input(true, priorRaw), output = new Output();
    const promise = readSecureKey({ mode: 'prompt', input, output });
    assert.equal(input.isRaw, true);
    input.emit('data', Buffer.from(`${key}X\x7f\r`));
    assert.equal(await promise, key);
    assert.deepEqual(input.rawCalls, [true, priorRaw]); assert.equal(input.isRaw, priorRaw); assert.equal(input.paused, true);
    assert.equal(output.text, 'API key (input hidden): \n'); assert.doesNotMatch(output.text, /CANARY|X/); clean(input, output);
  }
});

test('a fresh terminal with flowing:null and isPaused:false is paused after input so the CLI can exit', async () => {
  const input = new Input(true), output = new Output(); input.readableFlowing = null; input.paused = false;
  const promise = readSecureKey({ mode: 'prompt', input, output }); input.emit('data', Buffer.from(`${key}\r`));
  assert.equal(await promise, key); assert.equal(input.paused, true); assert.equal(input.isRaw, false); clean(input, output);
});

test('prompt rejects multiline paste, invalid controls and oversized key; still restores raw state', async () => {
  for (const value of [`${key}\r\nSECOND`, `${key}\n\n`, `${key} \r`, `${key}é\r`, `${key}\x04`, 'x'.repeat(2561)]) {
    const input = new Input(true), output = new Output();
    const promise = readSecureKey({ mode: 'prompt', input, output }); input.emit('data', Buffer.from(value));
    await assert.rejects(promise, safeCode('secure_key_invalid'));
    assert.equal(input.isRaw, false); assert.deepEqual(input.rawCalls, [true, false]); clean(input, output);
  }
});

test('prompt cancellation, input failure, close, EOF and deadline all join terminal restoration', async () => {
  for (const failure of ['interrupt', 'abort', 'error', 'close', 'end', 'timeout', 'output-error']) {
    const input = new Input(true), output = new Output(), controller = new AbortController();
    const promise = readSecureKey({ mode: 'prompt', input, output, signal: controller.signal, timeoutMs: 10 });
    if (failure === 'interrupt') input.emit('data', Buffer.from([3]));
    else if (failure === 'abort') controller.abort(Error(key));
    else if (failure === 'error') input.emit('error', Error(key));
    else if (failure === 'output-error') output.emit('error', Error(key));
    else if (failure !== 'timeout') input.emit(failure);
    const code = failure === 'interrupt' || failure === 'abort' ? 'secure_key_cancelled'
      : failure === 'timeout' ? 'secure_key_timeout' : failure === 'end' ? 'secure_key_invalid' : 'secure_key_unavailable';
    await assert.rejects(promise, safeCode(code));
    assert.equal(input.isRaw, false); assert.deepEqual(input.rawCalls, [true, false]); clean(input, output);
  }
});

test('aborted input never changes raw mode; timeout and stream errors remove owned pipe listeners', async () => {
  const controller = new AbortController(); controller.abort();
  const tty = new Input(true), output = new Output();
  await assert.rejects(readSecureKey({ mode: 'prompt', input: tty, output, signal: controller.signal }), safeCode('secure_key_cancelled'));
  assert.deepEqual(tty.rawCalls, []);
  for (const event of ['timeout', 'error', 'close']) {
    const input = new Input(); const promise = readSecureKey({ mode: 'stdin', input, timeoutMs: 10 });
    if (event !== 'timeout') input.emit(event, Error(key));
    await assert.rejects(promise, safeCode(event === 'timeout' ? 'secure_key_timeout' : 'secure_key_unavailable'));
    clean(input); assert.equal(input.paused, true);
  }
});

test('host failures at raw activation, restoration, prompt write and pause stay private and attempt restoration once', async () => {
  for (const failure of ['activate', 'restore', 'write', 'pause']) {
    const input = new Input(true), output = new Output();
    if (failure === 'activate') input.rawErrorAt = 1;
    if (failure === 'restore') input.rawErrorAt = 2;
    if (failure === 'write') output.writeError = true;
    if (failure === 'pause') input.pauseError = true;
    const promise = readSecureKey({ mode: 'prompt', input, output });
    if (failure === 'restore' || failure === 'pause') input.emit('data', Buffer.from(`${key}\r`));
    await assert.rejects(promise, safeCode('secure_key_unavailable'));
    assert.deepEqual(input.rawCalls, [true, false]); clean(input, output);
  }
});

test('delayed prompt or newline write failures are joined before key return under the private output error guard', async () => {
  for (const failedWrite of [1, 2]) {
    const input = new Input(true); let writes = 0;
    const output = new Writable({ write(_chunk, _encoding, done) {
      const current = ++writes;
      setImmediate(() => done(current === failedWrite ? Error(key) : undefined));
    } });
    output.isTTY = true;
    const promise = readSecureKey({ mode: 'prompt', input, output });
    input.emit('data', Buffer.from(`${key}\r`));
    await assert.rejects(promise, safeCode('secure_key_unavailable'));
    assert.equal(input.isRaw, false); assert.equal(input.paused, true); clean(input, output);
  }
});

test('explicit environment enrollment uses an own data property, validates full native capacity and never invokes accessors', async () => {
  assert.equal(await readSecureKey({ mode: 'environment', env: { BOTA_API_KEY: key } }), key);
  assert.equal(await readSecureKey({ mode: 'environment', env: { BOTA_API_KEY: 'x'.repeat(2560) } }), 'x'.repeat(2560));
  for (const env of [{}, Object.create({ BOTA_API_KEY: key }), { BOTA_API_KEY: '' }, { BOTA_API_KEY: `${key}\n` }, { BOTA_API_KEY: 'x'.repeat(2561) },
    Object.defineProperty({}, 'BOTA_API_KEY', { get() { assert.fail('Environment accessor was invoked'); } })]) {
    await assert.rejects(readSecureKey({ mode: 'environment', env }), safeCode('secure_key_invalid'));
  }
});

test('invalid budgets and unsupported modes fail without starting stream input', async () => {
  const input = new Input();
  for (const timeoutMs of [0, -1, 300001, 1.5, NaN, Infinity]) {
    await assert.rejects(readSecureKey({ mode: 'stdin', input, timeoutMs }), safeCode('secure_key_unavailable')); clean(input);
  }
  await assert.rejects(readSecureKey({ mode: 'other', input }), safeCode('secure_key_unavailable')); clean(input);
  for (const flag of ['readableEnded', 'destroyed']) {
    const ended = new Input(); ended[flag] = true;
    await assert.rejects(readSecureKey({ mode: 'stdin', input: ended }), safeCode('secure_key_unavailable')); clean(ended);
  }
});

test('a real child process reads only its piped synthetic key and refuses prompt startup on stdio', () => {
  const source = new URL('../src/secure-key-input.ts', import.meta.url).href;
  const script = `import {readSecureKey} from ${JSON.stringify(source)};
    try { const key = await readSecureKey({mode:process.argv[1],timeoutMs:1000}); console.log(JSON.stringify({length:key.length})); }
    catch(error) { console.error(JSON.stringify({code:error.code})); process.exitCode=1; }`;
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'ComSpec', 'PATH', 'PATHEXT', 'TEMP', 'TMP']
    .filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
  for (const [mode, input, expected] of [['stdin', `${key}\r\n`, { length: key.length }],
    ['stdin', `${key}\nSECOND`, { code: 'secure_key_invalid' }], ['stdin', 'x'.repeat(2560), { length: 2560 }],
    ['stdin', 'x'.repeat(100000), { code: 'secure_key_invalid' }], ['prompt', `${key}\n`, { code: 'secure_key_tty_required' }]]) {
    const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script, mode],
      { cwd: new URL('..', import.meta.url), input, encoding: 'utf8', env, timeout: 5000, windowsHide: true });
    assert.equal(child.error, undefined); assert.equal(child.signal, null);
    assert.equal(child.status, Object.hasOwn(expected, 'length') ? 0 : 1);
    assert.deepEqual(JSON.parse(child.stdout || child.stderr), expected);
    assert.doesNotMatch(child.stdout + child.stderr, /CANARY/);
  }
});
