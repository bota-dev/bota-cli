import open from 'open';
import { getSelectedDeveloperDeployment } from './developer-deployment-selection.js';
import { createWindowsDelegatedNativeRuntime } from './delegated-native-runtime.js';
import { createDeveloperProfileServiceForTrustedPorts } from './developer-profile-service.js';
import { DeveloperProfileError } from './developer-profile-error.js';
import { writeDeveloperWritableOutput } from './developer-output-acknowledgement.js';

const nativeFetch = globalThis.fetch.bind(globalThis);
/** Keep observing native completion even after the caller withdraws its bounded
 * acknowledgement. No global stream replacement or destruction is performed. */
export async function writeDeveloperCommandOutput(channel: 'stdout' | 'stderr', text: string): Promise<void> {
  await writeDeveloperWritableOutput(channel === 'stdout' ? process.stdout : process.stderr, text);
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
