import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';
import { DeveloperProfileError } from './developer-profile-error.js';

type Channel = 'stdout' | 'stderr';
interface Entry { readonly channel: Channel; readonly text: string }
interface OutputScope { live: boolean; bytes: number; readonly maximum: number; readonly entries: Entry[] }
const current = new AsyncLocalStorage<OutputScope>();
function fail(): never { throw new DeveloperProfileError('developer_output_failed'); }

/** Called only by ordinary CLI presentation helpers. MCP protocol writers do
 * not use this module and are never buffered by a process-global override. */
export function captureDeveloperOutput(channel: Channel, text: string): boolean {
  const scope = current.getStore(); if (!scope) return false;
  if (!scope.live || !['stdout', 'stderr'].includes(channel) || typeof text !== 'string') fail();
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > scope.maximum - scope.bytes) fail();
  scope.bytes += bytes; scope.entries.push(Object.freeze({ channel, text })); return true;
}

export interface CapturedDeveloperOutput<T> {
  readonly value: T;
  /** Invoke only after action, family lease and runtime cleanup have joined.
   * The original invocation guard must remain live through publication. */
  publish(check: () => void, write: (channel: Channel, text: string) => Promise<void>): Promise<void>;
}
export async function bufferDeveloperCommandOutput<T>(action: () => Promise<T>, maximumBytes: number): Promise<CapturedDeveloperOutput<T>> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 64 * 1024 * 1024
    || typeof action !== 'function' || types.isProxy(action) || current.getStore()) fail();
  const scope: OutputScope = { live: true, bytes: 0, maximum: maximumBytes, entries: [] };
  let value: T;
  try { value = await current.run(scope, action); }
  catch (error) { scope.entries.length = 0; throw error; }
  finally { scope.live = false; }
  let claimed = false;
  return Object.freeze({ value,
    async publish(check: () => void, write: (channel: Channel, text: string) => Promise<void>): Promise<void> {
      if (claimed || typeof check !== 'function' || types.isProxy(check) || typeof write !== 'function' || types.isProxy(write)) fail();
      claimed = true;
      try {
        check();
        for (const entry of scope.entries) { check(); await write(entry.channel, entry.text); check(); }
        check();
      } catch { fail(); }
      finally { scope.entries.length = 0; scope.bytes = 0; }
    } });
}
