/** Context-bound project-key identity read; no browser, discovery or retries. */
import { parseProjectIdentity, type ProjectIdentity } from './client.js';
import { NativeProfileTransactionError, type NativeOperationContext } from './native-profile-transaction.js';
import { normalizeProfileOrigin } from './profiles.js';

const MAX_IDENTITY_BYTES = 64 * 1024;
const IDENTITY_TIMEOUT_MS = 30_000;
function failed(): never { throw new NativeProfileTransactionError('profile_identity_failed'); }
function active(context: NativeOperationContext): void {
  if (!context || !(context.signal instanceof AbortSignal) || !context.budget
    || typeof context.budget.assertActive !== 'function' || context.signal.aborted) failed();
  context.budget.assertActive();
}

export async function readSecureProfileIdentity(apiOrigin: string, key: string,
  context: NativeOperationContext): Promise<ProjectIdentity> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let response: Response | undefined;
  let listening = false;
  try {
    active(context);
    // The profile/engine admits literal loopback explicitly. This transport
    // still requires a normalized origin and never accepts paths/credentials.
    if (normalizeProfileOrigin(apiOrigin, true) !== apiOrigin || typeof key !== 'string'
      || !/^[\x21-\x7e]{1,2560}$/.test(key)) failed();
    context.signal.addEventListener('abort', abort, { once: true }); listening = true;
    if (context.signal.aborted) abort();
    timer = setTimeout(abort, IDENTITY_TIMEOUT_MS);
    timer.unref();
    response = await fetch(`${apiOrigin}/v1/auth/identity`, {
      method: 'GET', headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
    });
    active(context);
    if (controller.signal.aborted || response.status !== 200 || !response.body) failed();
    const length = response.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || BigInt(length) > BigInt(MAX_IDENTITY_BYTES))) failed();
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    for (;;) {
      active(context);
      const chunk = await reader.read();
      active(context);
      if (controller.signal.aborted) failed();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_IDENTITY_BYTES) failed();
      chunks.push(chunk.value);
    }
    const body = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    const identity = parseProjectIdentity(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)));
    const strings = [identity.project_id, identity.organization_id, identity.key_id, ...(identity.scopes ?? [])];
    if (strings.some(value => value.includes(key))) failed();
    active(context);
    if (controller.signal.aborted) failed();
    return identity;
  } catch { return failed(); }
  finally {
    controller.abort();
    if (timer !== undefined) clearTimeout(timer);
    if (listening) context.signal.removeEventListener('abort', abort);
    try { if (reader) await reader.cancel(); else await response?.body?.cancel(); } catch { /* Fixed failure only. */ }
    try { reader?.releaseLock(); } catch { /* Cleanup never reflects native errors. */ }
  }
}
