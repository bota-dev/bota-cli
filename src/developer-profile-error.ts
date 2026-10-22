import { types } from 'node:util';

const messages = {
  developer_configuration_unavailable: 'Platform developer login is not configured for this build.',
  developer_profile_invalid: 'The developer profile selection is invalid or incompatible with this command.',
  developer_profile_missing: 'The selected developer profile does not exist.',
  developer_profile_exists: 'The developer profile name is already reserved. Inspect its state before continuing.',
  developer_profile_disabled: 'The selected developer profile cannot perform this operation.',
  developer_recovery_required: 'The developer profile requires explicit recovery before it can be used.',
  developer_enrollment_unknown: 'Developer enrollment may be incomplete. Keep its protected recovery state and recover the selected profile explicitly.',
  developer_operation_failed: 'The developer operation failed. Inspect the selected profile before retrying.',
  developer_cancelled: 'The developer operation was cancelled.',
  developer_deadline: 'The developer operation deadline expired.',
  developer_output_failed: 'Developer command output could not be published.',
  developer_login_scope_required: 'Select the requested read scopes explicitly before Platform login.',
  developer_mcp_hosted_required: 'A developer profile requires the explicit MCP option --mode hosted.',
} as const;
export type DeveloperProfileFailureCode = keyof typeof messages;
export interface DeveloperProfileFailure {
  readonly code: DeveloperProfileFailureCode;
  readonly message: string;
  readonly recovery_required: boolean;
  readonly operation_may_have_executed: boolean;
}
const genuine = new WeakMap<object, DeveloperProfileFailure>();
export class DeveloperProfileError extends Error {
  readonly code: DeveloperProfileFailureCode;
  readonly recovery_required: boolean;
  readonly operation_may_have_executed: boolean;
  constructor(code: DeveloperProfileFailureCode = 'developer_operation_failed', recoveryRequired = false, operationMayHaveExecuted = false) {
    const selected = typeof code === 'string' && Object.hasOwn(messages, code) ? code : 'developer_operation_failed';
    super(messages[selected]); this.name = 'DeveloperProfileError'; this.code = selected;
    this.recovery_required = recoveryRequired === true; this.operation_may_have_executed = operationMayHaveExecuted === true;
    genuine.set(this, Object.freeze({ code: selected, message: messages[selected],
      recovery_required: this.recovery_required, operation_may_have_executed: this.operation_may_have_executed }));
  }
}
/** Never project an exception's mutable message, prototype, getters or cause. */
export function developerProfileFailure(value: unknown): DeveloperProfileFailure | undefined {
  return value && typeof value === 'object' && !types.isProxy(value) ? genuine.get(value) : undefined;
}
export function sanitizeDeveloperProfileError(value: unknown, recoveryRequired = false, operationMayHaveExecuted = false): DeveloperProfileError {
  const known = developerProfileFailure(value);
  return new DeveloperProfileError(known?.code, recoveryRequired || known?.recovery_required,
    operationMayHaveExecuted || known?.operation_may_have_executed);
}
