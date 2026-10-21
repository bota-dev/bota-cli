import type { ReadStream, WriteStream } from 'node:tty';

const MAX_KEY_BYTES = 2560;
const DEFAULT_TIMEOUT_MS = 30_000;
const messages = {
  secure_key_invalid: 'Provide one printable ASCII API key of 1 to 2560 bytes.',
  secure_key_tty_required: 'Secure key prompting requires an interactive input and error terminal.',
  secure_key_stdin_required: 'Use --key-stdin with a pipe, or --key-prompt in an interactive terminal.',
  secure_key_unavailable: 'The secure key input could not be read safely.',
  secure_key_cancelled: 'Secure key input was cancelled.',
  secure_key_timeout: 'Secure key input timed out.',
} as const;

export class SecureKeyInputError extends Error {
  declare readonly code: keyof typeof messages;
  constructor(code: keyof typeof messages) {
    const safeCode = Object.hasOwn(messages, code) ? code : 'secure_key_unavailable';
    super(messages[safeCode]); this.name = 'SecureKeyInputError';
    Object.defineProperty(this, 'code', { value: safeCode, enumerable: true });
  }
}

export interface SecureKeyInputOptions {
  readonly mode: 'stdin' | 'prompt' | 'environment';
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  /** Explicit test ports. The CLI always supplies its current process streams. */
  readonly input?: NodeJS.ReadableStream & Partial<Pick<ReadStream, 'isTTY' | 'isRaw' | 'setRawMode' | 'isPaused' | 'readableFlowing' | 'readableEnded' | 'destroyed'>>;
  readonly output?: NodeJS.WritableStream & Partial<Pick<WriteStream, 'isTTY'>>;
  readonly env?: Record<string, unknown>;
}

function fail(code: keyof typeof messages): never { throw new SecureKeyInputError(code); }

function checkedKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[\x21-\x7e]{1,2560}$/.test(value)) fail('secure_key_invalid');
  return value;
}

/** Never reads a key argument, silently selects an environment key, or echoes input.
 * Private byte buffers are cleared; JavaScript strings cannot promise erasure. */
export async function readSecureKey(options: SecureKeyInputOptions): Promise<string> {
  if (options.signal?.aborted) fail('secure_key_cancelled');
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) fail('secure_key_unavailable');
  if (options.mode === 'environment') {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(options.env ?? process.env, 'BOTA_API_KEY');
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('secure_key_invalid');
      return checkedKey(descriptor.value);
    } catch (error) {
      if (error instanceof SecureKeyInputError) throw error;
      return fail('secure_key_unavailable');
    }
  }
  if (options.mode !== 'stdin' && options.mode !== 'prompt') fail('secure_key_unavailable');
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stderr;
  const prompt = options.mode === 'prompt';
  if (prompt && (!input.isTTY || typeof input.setRawMode !== 'function' || !output.isTTY)) fail('secure_key_tty_required');
  if (!prompt && input.isTTY) fail('secure_key_stdin_required');
  if (input.readableEnded || input.destroyed) fail('secure_key_unavailable');
  const bytes = Buffer.alloc(MAX_KEY_BYTES + 2);
  let length = 0;
  let originalRaw = false;
  let changedRaw = false;
  let wasPaused = true;
  let cleanupFailed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeListeners: (() => void) | undefined;
  let outputListenerInstalled = false;
  let rejectOutput: (() => void) | undefined;
  const pendingWrites: Promise<void>[] = [];
  const outputError = () => { cleanupFailed = true; rejectOutput?.(); };
  const writeOutput = (text: string) => {
    pendingWrites.push(new Promise<void>(resolve => {
      let settled = false;
      const finish = (error?: Error | null) => {
        if (settled) return;
        settled = true;
        if (error) outputError();
        // Writable reports a failed write through its callback and an error
        // event. Join the event turn while the private error guard remains.
        setImmediate(resolve);
      };
      try { output.write(text, finish); }
      catch { outputError(); finish(); }
    }));
  };
  try {
    // A fresh Node terminal has readableFlowing:null while isPaused() is false.
    // Resuming it and checking only isPaused() would keep stdin alive forever.
    wasPaused = input.readableFlowing === undefined ? input.isPaused?.() ?? true : input.readableFlowing !== true;
    if (prompt) {
      output.on('error', outputError); outputListenerInstalled = true;
      originalRaw = input.isRaw === true;
      // Even a throwing host call may have changed terminal mode. Always join
      // restoration once it was attempted, without retrying an uncertain restore.
      changedRaw = true;
      input.setRawMode!(true);
    }
    return await new Promise<string>((resolve, reject) => {
      let settled = false;
      const finish = (code?: keyof typeof messages) => {
        if (settled) return;
        settled = true;
        if (code) { reject(new SecureKeyInputError(code)); return; }
        try { resolve(checkedKey(bytes.subarray(0, length).toString('ascii'))); }
        catch (error) { reject(error); }
      };
      const data = (chunk: unknown) => {
        if (settled) return;
        try {
          if (!(chunk instanceof Uint8Array) && typeof chunk !== 'string') { finish('secure_key_invalid'); return; }
          // Bound before copying or encoding a possibly oversized producer chunk.
          if (chunk.length > MAX_KEY_BYTES + 2) { finish('secure_key_invalid'); return; }
          const source = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
          if (source.byteLength > MAX_KEY_BYTES + 2) { finish('secure_key_invalid'); return; }
          for (let index = 0; index < source.length; index++) {
            const byte = source[index]!;
            if (prompt) {
              if (byte === 3) { finish('secure_key_cancelled'); return; }
              if (byte === 8 || byte === 127) { if (length) bytes[--length] = 0; continue; }
              if (byte === 10 || byte === 13) {
                if (byte === 13 && source[index + 1] === 10) index++;
                if (index !== source.length - 1) { finish('secure_key_invalid'); return; }
                finish(); return;
              }
              if (byte < 0x21 || byte > 0x7e || length >= MAX_KEY_BYTES) { finish('secure_key_invalid'); return; }
            } else if (length >= bytes.length) { finish('secure_key_invalid'); return; }
            bytes[length++] = byte;
          }
        } catch { finish('secure_key_unavailable'); }
      };
      const end = () => {
        if (prompt) { finish('secure_key_invalid'); return; }
        // A piped key permits exactly one optional LF or CRLF terminator.
        if (length && bytes[length - 1] === 10) {
          bytes[--length] = 0;
          if (length && bytes[length - 1] === 13) bytes[--length] = 0;
        }
        for (let index = 0; index < length; index++) {
          if (bytes[index]! < 0x21 || bytes[index]! > 0x7e) { finish('secure_key_invalid'); return; }
        }
        finish();
      };
      const error = () => finish('secure_key_unavailable');
      rejectOutput = () => finish('secure_key_unavailable');
      const close = () => finish('secure_key_unavailable');
      const abort = () => finish('secure_key_cancelled');
      removeListeners = () => {
        input.removeListener('data', data); input.removeListener('end', end);
        input.removeListener('error', error); input.removeListener('close', close);
        options.signal?.removeEventListener('abort', abort);
      };
      input.on('data', data); input.once('end', end); input.once('error', error); input.once('close', close);
      options.signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish('secure_key_timeout'), timeoutMs);
      if (options.signal?.aborted) abort();
      else {
        if (prompt) writeOutput('API key (input hidden): ');
        if (cleanupFailed) finish('secure_key_unavailable');
        else input.resume();
      }
    });
  } catch (error) {
    if (error instanceof SecureKeyInputError) throw error;
    return fail('secure_key_unavailable');
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    try { if (wasPaused) input.pause(); } catch { cleanupFailed = true; }
    if (changedRaw) {
      try { input.setRawMode!(originalRaw); } catch { cleanupFailed = true; }
      writeOutput('\n');
    }
    removeListeners?.();
    bytes.fill(0);
    // Terminal mode is already restored even if host write completion is slow.
    // Joining an outstanding OS write may outlast the input deadline.
    await Promise.all(pendingWrites);
    if (outputListenerInstalled) output.removeListener('error', outputError);
    if (cleanupFailed) fail('secure_key_unavailable');
  }
}
