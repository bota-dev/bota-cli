import chalk from 'chalk';
import Table from 'cli-table3';
import { types } from 'node:util';
import { isSecureInvocation } from './config.js';
import { NativeProfileTransactionError } from './native-profile-transaction.js';

export function printTable(headers: string[], rows: string[][]): void {
  const table = new Table({
    head: headers.map(h => chalk.cyan(h)),
  });
  for (const row of rows) {
    table.push(row);
  }
  console.log(table.toString());
}

export function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function printPagination(page: { has_more?: boolean; next_cursor?: string }): void {
  if (page.has_more && page.next_cursor) {
    console.error(`More results available. Continue with --cursor ${page.next_cursor}`);
  }
}

export function errorDetails(error: unknown) {
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
    console.error(detail.message);
    const diagnostics = [
      ...(detail.status !== undefined ? [`HTTP ${detail.status}`] : []),
      ...(detail.code !== undefined ? [`code: ${detail.code}`] : []),
      ...(detail.param !== undefined ? [`parameter: ${detail.param}`] : []),
      ...(detail.request_id !== undefined ? [`request ID: ${detail.request_id}`] : []),
      ...(detail.retry_after !== undefined ? [`Retry-After: ${detail.retry_after}`] : []),
      ...Object.entries(detail.rate_limit ?? {}).map(([name, value]) => `${name}: ${value}`),
    ];
    if (diagnostics.length) console.error(diagnostics.join('; '));
    return;
  }
  console.error(JSON.stringify({ error: detail }));
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
    console.log(`${paddedKey} ${value}`);
  }
}

export function ok(msg: string): void {
  console.log(`${chalk.green('✓')} ${msg}`);
}

export function info(msg: string): void {
  console.log(`${chalk.blue('→')} ${msg}`);
}

export function warn(msg: string): void {
  console.log(`${chalk.yellow('⚠')} ${msg}`);
}
