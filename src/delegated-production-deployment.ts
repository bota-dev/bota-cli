import type { DelegatedLoginDeployment } from './delegated-login.js';
import { DeveloperProfileError } from './developer-profile-error.js';

/** The production selector has no environment, discovery, profile or URL
 * override. Activation requires a reviewed build-bound deployment/client cohort
 * after the server, ingress and Platform consent path qualify together. */
export function getProductionDeveloperDeployment(): DelegatedLoginDeployment {
  throw new DeveloperProfileError('developer_configuration_unavailable');
}
