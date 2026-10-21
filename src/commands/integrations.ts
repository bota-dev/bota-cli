import { withCommandAuth } from '../invocation-auth.js';
import { Command } from 'commander';
import type { Readable } from 'node:stream';
import { BotaClient, IntegrationError, integrationId, integrationProvider, safeIntegrationError } from '../client.js';
import { getApiKey, getApiUrl } from '../config.js';
import { printDetail, printError, printJson, printTable, handleCommandFailure } from '../output.js';

export const MAX_INTEGRATION_KEY_BYTES = 16 * 1024;

export function readIntegrationKey(input: Readable & { isTTY?: boolean } = process.stdin): Promise<string> {
  if (input.isTTY) return Promise.reject(new IntegrationError('integration_key_input_required'));
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    const finish = (error?: IntegrationError) => {
      clearTimeout(timer);
      input.removeListener('data', data);
      input.removeListener('end', end);
      input.removeListener('error', failed);
      if (error) { for (const chunk of chunks) chunk.fill(0); input.destroy(); reject(error); return; }
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        const key = text.replace(/\r?\n$/, '');
        if (!key || /[\s\u0000-\u001f\u007f]/u.test(key)) throw new IntegrationError('integration_key_input_invalid');
        resolve(key);
      } catch { reject(new IntegrationError('integration_key_input_invalid')); }
      finally { for (const chunk of chunks) chunk.fill(0); }
    };
    const data = (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > MAX_INTEGRATION_KEY_BYTES) { finish(new IntegrationError('integration_key_input_too_large')); return; }
      chunks.push(buffer);
    };
    const end = () => finish();
    const failed = () => finish(new IntegrationError('integration_key_input_invalid'));
    const timer = setTimeout(() => finish(new IntegrationError('integration_key_input_timeout')), 30_000);
    input.on('data', data).once('end', end).once('error', failed);
  });
}

export function registerIntegrations(program: Command): void {
  // An independent output configuration avoids changing existing command errors.
  const integrations = new Command('integrations').description('Manage project ASR/LLM integrations without displaying provider keys')
    .allowExcessArguments(false)
    .configureOutput({ outputError: () => printError(new Error('Invalid integration command. Run bota integrations --help; keys are accepted only via --key-stdin.'), Boolean(program.opts()['json'])) });
  program.addCommand(integrations);
  const client = () => new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(program.opts()['apiUrl'] as string | undefined) });
  const run = async (operation: () => Promise<void>): Promise<void> => {
    try { await operation(); }
    catch (error) { handleCommandFailure(error, Boolean(program.opts()['json']), safeIntegrationError); }
  };
  const show = (value: Record<string, unknown> | object) => {
    if (program.opts()['json']) printJson(value); else printDetail(value as Record<string, unknown>);
  };
  integrations.command('list').description('List safe integration metadata').action(withCommandAuth(program, () => run(async () => {
    const page = await client().listIntegrations();
    if (program.opts()['json']) printJson(page);
    else printTable(['id', 'provider_type', 'provider_name', 'is_enabled', 'has_error', 'last_used_at'], page.data.map(item => [item.id, item.provider_type, item.provider_name, String(item.is_enabled), String(item.has_error), item.last_used_at ?? '']));
  })));
  integrations.command('get <type> <provider>').description('Get safe integration metadata').action(withCommandAuth(program, (type: string, provider: string) => run(async () => {
    show(await client().getIntegration(integrationProvider(type, provider), provider));
  })));
  integrations.command('set <type> <provider>').description('Create or replace a provider credential; the backend enables the integration')
    .requiredOption('--key-stdin', 'Read one provider key line from piped stdin (16 KiB, 30-second EOF deadline)')
    .action(withCommandAuth(program, (type: string, provider: string) => run(async () => {
      const providerType = integrationProvider(type, provider);
      const key = await readIntegrationKey();
      show(await client().setIntegration(providerType, provider, key));
    })));
  integrations.command('rotate <id>').description('Replace a provider credential by integration UUID')
    .requiredOption('--key-stdin', 'Read one provider key line from piped stdin (16 KiB, 30-second EOF deadline)')
    .action(withCommandAuth(program, (id: string) => run(async () => {
      integrationId(id);
      const key = await readIntegrationKey();
      show(await client().rotateIntegration(id, key));
    })));
  for (const [name, enabled] of [['enable', true], ['disable', false]] as const) {
    integrations.command(`${name} <id>`).description(`${name} an integration by UUID`).action(withCommandAuth(program, (id: string) => run(async () => {
      show(await client().setIntegrationEnabled(id, enabled));
    })));
  }
  integrations.command('delete <id>').description('Delete an integration by UUID').action(withCommandAuth(program, (id: string) => run(async () => {
    await client().deleteIntegration(id); show({ deleted: true });
  })));
  integrations.command('delete-provider <type> <provider>').description('Delete an integration by provider').action(withCommandAuth(program, (type: string, provider: string) => run(async () => {
    await client().deleteIntegrationByProvider(integrationProvider(type, provider), provider); show({ deleted: true });
  })));
  integrations.command('test <type> <provider>').description('Explicitly check the stored credential with its provider (may consume provider capacity)').action(withCommandAuth(program, (type: string, provider: string) => run(async () => {
    const result = await client().testIntegration(integrationProvider(type, provider), provider);
    show(result);
    if (!result.success) process.exitCode = 1;
  })));
}
