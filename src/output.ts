import chalk from 'chalk';
import Table from 'cli-table3';
import { types } from 'node:util';
import { isSecureInvocation } from './config.js';
import { NativeProfileTransactionError } from './native-profile-transaction.js';
import { captureDeveloperOutput } from './developer-command-output.js';
import { developerProfileFailure } from './developer-profile-error.js';

function line(channel: 'stdout' | 'stderr', value: string): void {
  if (captureDeveloperOutput(channel, value + '\n')) return;
  if (channel === 'stdout') console.log(value); else console.error(value);
}

export function printTable(headers: string[], rows: string[][]): void {
  const table = new Table({
    head: headers.map(h => chalk.cyan(h)),
  });
  for (const row of rows) {
    table.push(row);
  }
  line('stdout', table.toString());
}

export function printJson(data: unknown): void {
  line('stdout', JSON.stringify(data, null, 2));
}

export function printPagination(page: { has_more?: boolean; next_cursor?: string }): void {
  if (page.has_more && page.next_cursor) {
    line('stderr', `More results available. Continue with --cursor ${page.next_cursor}`);
  }
}

export interface ErrorDetails {
  readonly message: string; readonly status?: number; readonly code?: string | number; readonly param?: string;
  readonly request_id?: string; readonly retry_after?: string; readonly rate_limit?: Record<string, string>;
  readonly recovery_required?: boolean; readonly operation_may_have_executed?: boolean;
}
export function errorDetails(error: unknown): ErrorDetails {
  const developer = developerProfileFailure(error);
  if (developer) return developer;
  if (isSecureInvocation() && !(error instanceof NativeProfileTransactionError)) {
    error = new NativeProfileTransactionError('profile_operation_failed', false, true);
  }
  const message = error instanceof Error ? error.message : String(error);
  const detail = error as { status?: number; code?: unknown; param?: string; requestId?: string; retryAfter?: string; rateLimit?: Record<string, string> } | null;
  return {
    message,
    ...(typeof detail?.status === 'number' && { status: detail.status }),
    ...((typeof detail?.code === 'string' || typeof detail?.code === 'number') && { code: detail.code }),
    ...(typeof detail?.param === 'string' && { param: detail.param }),
    ...(typeof detail?.requestId === 'string' && { request_id: detail.requestId }),
    ...(typeof detail?.retryAfter === 'string' && { retry_after: detail.retryAfter }),
    ...(detail?.rateLimit && { rate_limit: detail.rateLimit }),
    ...(error instanceof NativeProfileTransactionError && {
      recovery_required: error.recovery_required, operation_may_have_executed: error.operation_may_have_executed,
    }),
  };
}

export function printError(error: unknown, json = false): void {
  const detail = errorDetails(error);
  if (!json) {
    line('stderr', detail.message);
    const diagnostics = [
      ...(detail.status !== undefined ? [`HTTP ${detail.status}`] : []),
      ...(detail.code !== undefined ? [`code: ${detail.code}`] : []),
      ...(detail.param !== undefined ? [`parameter: ${detail.param}`] : []),
      ...(detail.request_id !== undefined ? [`request ID: ${detail.request_id}`] : []),
      ...(detail.retry_after !== undefined ? [`Retry-After: ${detail.retry_after}`] : []),
      ...Object.entries(detail.rate_limit ?? {}).map(([name, value]) => `${name}: ${value}`),
    ];
    if (diagnostics.length) line('stderr', diagnostics.join('; '));
    return;
  }
  line('stderr', JSON.stringify({ error: detail }));
}

/** Selected secure commands finish at the provider's joined cleanup boundary.
 * Printing inside an action would duplicate a later deadline/cleanup failure.
 * Compatibility commands retain their existing renderer and exit behavior. */
export function handleCommandFailure(error: unknown, json = false,
  compatibilityError: (error: unknown) => unknown = value => value): void {
  if (isSecureInvocation()) {
    const known = error && typeof error === 'object' && !types.isProxy(error)
      && error instanceof NativeProfileTransactionError ? error : undefined;
    if (known) {
      throw new NativeProfileTransactionError(Object.getOwnPropertyDescriptor(known, 'code')?.value,
        Object.getOwnPropertyDescriptor(known, 'recovery_required')?.value === true,
        Object.getOwnPropertyDescriptor(known, 'operation_may_have_executed')?.value === true);
    }
    throw new NativeProfileTransactionError('profile_operation_failed', false, true);
  }
  printError(compatibilityError(error), json);
  process.exitCode = 1;
}

export function printDetail(obj: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(obj)) {
    const paddedKey = chalk.cyan(key.padEnd(20));
    line('stdout', `${paddedKey} ${value}`);
  }
}

export function ok(msg: string): void {
  line('stdout', `${chalk.green('✓')} ${msg}`);
}

export function info(msg: string): void {
  line('stdout', `${chalk.blue('→')} ${msg}`);
}

export function warn(msg: string): void {
  line('stdout', `${chalk.yellow('⚠')} ${msg}`);
}
