import { parseProjectIdentity, type ProjectIdentity } from './client.js';
import { ProfileError } from './profiles.js';

const MAX_IDENTITY_BYTES = 64 * 1024;
const IDENTITY_TIMEOUT_MS = 30_000;

// Profile selection validates the trusted origin before resolving the key.
// This transport adds no discovery, browser flow, fallback or automatic retry.
export async function readProfileIdentity(apiUrl: string, key: string,
  options: { timeoutMs?: number } = {}): Promise<ProjectIdentity> {
  const timeoutMs = options.timeoutMs ?? IDENTITY_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > IDENTITY_TIMEOUT_MS) {
    throw new ProfileError('profile_identity_failed');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const response = await fetch(`${apiUrl}/v1/auth/identity`, {
      method: 'GET', headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
    });
    if (response.status !== 200 || !response.body) {
      await response.body?.cancel();
      throw new ProfileError('profile_identity_failed');
    }
    const length = response.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || BigInt(length) > BigInt(MAX_IDENTITY_BYTES))) {
      await response.body.cancel();
      throw new ProfileError('profile_identity_failed');
    }
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const chunk = await reader.read();
      if (controller.signal.aborted) throw new ProfileError('profile_identity_failed');
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_IDENTITY_BYTES) throw new ProfileError('profile_identity_failed');
      chunks.push(chunk.value);
    }
    const body = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    const identity = parseProjectIdentity(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)));
    const strings = [identity.project_id, identity.organization_id, identity.key_id, ...(identity.scopes ?? [])];
    if (!key || strings.some(value => value.includes(key))) throw new ProfileError('profile_identity_failed');
    if (controller.signal.aborted) throw new ProfileError('profile_identity_failed');
    return identity;
  } catch {
    // No reflected server message, credential, URL, parser detail or cause.
    throw new ProfileError('profile_identity_failed');
  } finally {
    controller.abort();
    clearTimeout(timer);
    try { await reader?.cancel(); } catch { /* Fixed failure is already selected. */ }
    try { reader?.releaseLock(); } catch { /* Do not replace a fixed diagnostic. */ }
  }
}
