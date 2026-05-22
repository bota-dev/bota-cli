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
