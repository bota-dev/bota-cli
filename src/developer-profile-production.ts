import open from 'open';
import { getSelectedDeveloperDeployment } from './developer-deployment-selection.js';
import { createWindowsDelegatedNativeRuntime } from './delegated-native-runtime.js';
import { createDeveloperProfileServiceForTrustedPorts } from './developer-profile-service.js';
import { DeveloperProfileError } from './developer-profile-error.js';

const nativeFetch = globalThis.fetch.bind(globalThis);
/** Native writable completion plus its ordinary deferred error event are joined.
 * No global stdout replacement, endpoint input or credential input is exposed. */
export async function writeDeveloperCommandOutput(channel: 'stdout' | 'stderr', text: string): Promise<void> {
  const stream = channel === 'stdout' ? process.stdout : process.stderr; let failed = false;
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
/** Factory construction performs no filesystem/OS, browser or network action.
 * Every operation resolves trusted build configuration before native startup. */
export const developerProfileService = createDeveloperProfileServiceForTrustedPorts({
  getDeployment: getSelectedDeveloperDeployment,
  createRuntime: createWindowsDelegatedNativeRuntime,
  fetch: nativeFetch,
  async openBrowser(url, context) {
    context.budget.assertActive();
    if (context.signal.aborted) throw new DeveloperProfileError('developer_cancelled');
    try { await open(url, { wait: false }); }
    catch { throw new DeveloperProfileError('developer_enrollment_unknown', true, true); }
    context.budget.assertActive();
  },
  writeOutput: writeDeveloperCommandOutput,
});
