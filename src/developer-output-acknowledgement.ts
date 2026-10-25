import { performance } from 'node:perf_hooks';
import type { Writable } from 'node:stream';
import { types } from 'node:util';
import { DeveloperProfileError, sanitizeDeveloperProfileError } from './developer-profile-error.js';

type Channel = 'stdout' | 'stderr';
type Writer = (channel: Channel, text: string) => Promise<void>;
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!;
const add = EventTarget.prototype.addEventListener, remove = EventTarget.prototype.removeEventListener;
const now = performance.now.bind(performance);
const maximumAcknowledgementMs = 5_000, guardIntervalMs = 25;

/** Bound asynchronous acknowledgement, not emission of bytes already queued.
 * The caller's original guard remains authoritative; this ceiling cannot extend
 * it. A late writer result is observed but cannot regain publication authority.
 * Timers require the writer/event loop to return control. Synchronous process
 * I/O (including Windows pipes and regular files) is not interruptible here. */
export async function acknowledgeDeveloperOutput(channel: Channel, text: string, write: Writer,
  check: () => void, signal?: AbortSignal): Promise<void> {
  if (!['stdout', 'stderr'].includes(channel) || typeof text !== 'string'
    || typeof write !== 'function' || types.isProxy(write) || typeof check !== 'function' || types.isProxy(check))
    throw new DeveloperProfileError('developer_output_failed');
  if (signal !== undefined) {
    try { if (types.isProxy(signal)) throw undefined; aborted.call(signal); }
    catch { throw new DeveloperProfileError('developer_output_failed'); }
  }
  const deadline = now() + maximumAcknowledgementMs;
  const active = () => {
    check();
    if (signal && aborted.call(signal)) throw new DeveloperProfileError('developer_cancelled');
    if (now() >= deadline) throw new DeveloperProfileError('developer_output_failed');
  };
  try { active(); } catch (error) { throw sanitizeDeveloperProfileError(error); }
  await new Promise<void>((resolve, reject) => {
    let live = true, entered = false;
    const settle = (failure?: { error: unknown }) => {
      if (!live) return;
      try { active(); } catch (error) { failure = { error }; }
      live = false; clearTimeout(timer); clearInterval(guard);
      if (signal) remove.call(signal, 'abort', interrupted);
      if (failure) reject(sanitizeDeveloperProfileError(failure.error, false, entered)); else resolve();
    };
    const pulse = () => { if (!live) return; try { active(); } catch (error) { settle({ error }); } };
    const interrupted = () => settle({ error: new DeveloperProfileError('developer_cancelled') });
    const timer = setTimeout(() => settle({ error: new DeveloperProfileError('developer_output_failed') }), maximumAcknowledgementMs);
    const guard = setInterval(pulse, guardIntervalMs);
    if (signal) add.call(signal, 'abort', interrupted, { once: true });
    // Register both observers on an ordinary owned Promise before invoking the
    // trusted writer. Withdrawal never destroys process-global stdout/stderr.
    void Promise.resolve().then(() => { if (!live) return; active(); entered = true; return write(channel, text); })
      .then(() => settle(), error => settle({ error }));
    pulse();
  });
}

/** Trusted native-Writable seam. Its actual callback and ordinary deferred
 * error event own this observer even if acknowledgement was already withdrawn.
 * An indefinitely pending write may retain it; no forced fd/process close is
 * claimed. Tests use owned Writable instances and owned child stdio only. */
export async function writeDeveloperWritableOutput(stream: Writable, text: string): Promise<void> {
  let failed = false;
  const failure = () => { failed = true; };
  stream.on('error', failure);
  try {
    await new Promise<void>(resolve => {
      try { stream.write(text, 'utf8', error => { if (error) failed = true; resolve(); }); }
      catch { failed = true; resolve(); }
    });
    await new Promise<void>(resolve => setImmediate(resolve));
    if (failed) throw new DeveloperProfileError('developer_output_failed');
  } finally { stream.removeListener('error', failure); }
}
