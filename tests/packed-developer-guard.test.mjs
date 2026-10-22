import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

const execute = promisify(execFile);
const guard = resolve(dirname(fileURLToPath(import.meta.url)), '../scripts/packed-developer-guard.mjs');
async function probe(source) {
  const temporary = await mkdtemp(join(tmpdir(), 'bota-cli-release-guard-'));
  const directory = join(temporary, 'developer-guards'), modules = join(temporary, 'consumer/node_modules');
  await mkdir(directory); await mkdir(modules, { recursive: true });
  const report = join(directory, 'probe-' + randomUUID() + '.json'), entry = join(temporary, 'entry.mjs');
  await writeFile(entry, source);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATHEXT|SYSTEMROOT|WINDIR|COMSPEC|SYSTEMDRIVE|PATH)$/i.test(key)));
  Object.assign(env, { TEMP: temporary, TMP: temporary, NO_COLOR: '1', FORCE_COLOR: '0',
    BOTA_PACKED_GUARD_DIRECTORY: directory, BOTA_PACKED_GUARD_REPORT: report, BOTA_PACKED_GUARD_MODULES: modules });
  try {
    const result = await execute(process.execPath, ['--import', pathToFileURL(guard).href, entry], { env, timeout: 15_000, maxBuffer: 1024 * 1024 });
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    const value = JSON.parse(await readFile(report, 'utf8'));
    assert.equal(value.installed_before_entrypoint, true); assert.equal(value.exit_code, 0);
    return value.effects;
  } finally { await rm(temporary, { recursive: true, force: true }); }
}
test('packed guard permits inert module evaluation and records zero effect attempts', async () => {
  const effects = await probe("import assert from 'node:assert/strict'; assert.equal(1, 1);");
  assert.ok(Object.values(effects).every(value => value === 0));
});
const cases = [
  ['process_spawn', "const {spawn}=await import('node:child_process'); spawn(null);"],
  ['process_control', 'process.kill(process.pid, 0);'],
  ['worker_spawn', "const {Worker}=await import('node:worker_threads'); new Worker(undefined);"],
  ['network_request', 'await fetch();'],
  ['network_request', "const http=await import('node:http'); http.request('invalid');"],
  ['network_request', "const net=await import('node:net'); new net.Socket().connect({port:-1});"],
  ['network_listen', "const net=await import('node:net'); new net.Server().listen(-1);"],
  ['native_module', "await import('node:sqlite');"],
  ['native_module', "const {createRequire}=await import('node:module'); createRequire(import.meta.url)('node:sqlite');"],
  ['native_module', "const {createRequire}=await import('node:module'); createRequire(import.meta.url).resolve('koffi');"],
  ['filesystem_read', "const fs=await import('node:fs'); fs.readdirSync(process.env.TEMP + '/never-native');"],
  ['filesystem_write', "const fs=await import('node:fs'); fs.writeFileSync(process.env.TEMP + '/never-write', 'synthetic');"],
  ['filesystem_write', "const fs=await import('node:fs/promises'); await fs.mkdir(process.env.TEMP + '/never-mkdir');"],
];
for (const [index, [kind, source]] of cases.entries()) test(`packed guard blocks ${kind} before delegation (${index + 1})`, async () => {
  const effects = await probe(`let refused=false; try { ${source} } catch(error) { if(error?.code!=='BOTA_PACKED_DEVELOPER_TRIPWIRE') throw error; refused=true; } if(!refused) throw Error('Tripwire was not installed.');`);
  assert.equal(effects[kind], 1); assert.equal(Object.values(effects).reduce((sum, value) => sum + value, 0), 1);
});
