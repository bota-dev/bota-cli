import chalk from 'chalk';
import Table from 'cli-table3';

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
