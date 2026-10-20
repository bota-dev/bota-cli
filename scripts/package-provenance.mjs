import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const json = async path => JSON.parse(await readFile(join(root, path), 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const pkg = await json('package.json');
const lock = await json('package-lock.json');
const metafile = await json('dist/metafile-esm.json');
const bundled = new Set();
for (const input of Object.keys(metafile.inputs)) {
  const pieces = input.replaceAll('\\', '/').split('node_modules/');
  if (pieces.length > 1) {
    const parts = pieces.at(-1).split('/');
    bundled.add(parts[0].startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]);
  }
}
let notices = 'Third-party notices only; this file grants no license for Bota CLI source.\n';
for (const name of [...bundled].sort()) {
  const directory = join(root, 'node_modules', name);
  const dependency = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
  const licenses = (await readdir(directory)).filter(name => /^(licen[sc]e|copying)(?:$|[._-])/i.test(name));
  if (!licenses.length) throw new Error(`Bundled dependency ${name} requires its license notice.`);
  notices += `\n${dependency.name}@${dependency.version} (${dependency.license ?? 'license unresolved'})\n`;
  for (const license of licenses.sort()) notices += `${await readFile(join(directory, license), 'utf8')}\n`;
}
if (!bundled.size) notices += '\nNo third-party JavaScript is bundled. External runtime dependencies retain their own distributed license files.\n';
await writeFile(join(root, 'dist/THIRD_PARTY_NOTICES.txt'), notices);

const inputs = [];
async function collect(path) {
  for (const entry of await readdir(join(root, path), { withFileTypes: true })) {
    const relative = `${path}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error('Release inputs cannot contain symbolic links.');
    if (entry.isDirectory()) await collect(relative);
    else if (entry.isFile()) inputs.push(relative);
  }
}
for (const directory of ['src', 'scripts', '.github/workflows']) await collect(directory);
inputs.push('package.json', 'package-lock.json', 'tsconfig.json', 'tsup.config.ts', 'README.md');
let sourceLicense = null;
try { sourceLicense = { identifier: pkg.license ?? null, sha256: digest(await readFile(join(root, 'LICENSE'))) }; inputs.push('LICENSE'); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const hashes = {};
for (const path of inputs.sort()) hashes[path] = digest(await readFile(join(root, path)));
const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const sourceLicenseResolved = Boolean(sourceLicense?.identifier && sourceLicense.identifier !== 'UNLICENSED');
const provenance = {
  schema_version: 1,
  package: { name: pkg.name, version: pkg.version, node: pkg.engines.node },
  source: { repository: 'https://github.com/bota-dev/bota-cli', commit: git(['rev-parse', 'HEAD']), dirty: Boolean(git(['status', '--porcelain', '--untracked-files=all'])) },
  source_license: sourceLicense,
  publication_blockers: !sourceLicenseResolved ? ['CLI source license decision is unresolved.'] : [],
  inputs: hashes,
  inputs_sha256: digest(JSON.stringify(hashes)),
  bundle_sha256: digest(await readFile(join(root, 'dist/index.js'))),
  notices_sha256: digest(notices),
  bundled_dependencies: [...bundled].sort(),
  locked_runtime_dependencies: Object.fromEntries(Object.keys(pkg.dependencies).sort().map(name => {
    const installed = lock.packages[`node_modules/${name}`];
    if (pkg.dependencies[name] !== installed?.version) throw new Error(`Runtime dependency ${name} must match its qualified lock version.`);
    return [name, { version: installed.version, integrity: installed.integrity, license: installed.license }];
  })),
  build: { node: process.version, npm: process.env.npm_config_user_agent?.match(/^npm\/([\d.]+)/)?.[1] ?? null },
};
await writeFile(join(root, 'dist/release.json'), `${JSON.stringify(provenance, null, 2)}\n`);
console.log(`Prepared ${pkg.name}@${pkg.version}; source license ${sourceLicenseResolved ? 'recorded' : 'UNRESOLVED (publication blocked)'}.`);
