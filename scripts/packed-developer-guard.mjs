/** Test-only preload for the packed configuration-off probes. Never shipped.
 * This is a tripwire instrument, not an adversarial JavaScript sandbox. */
import fs from 'node:fs';
import childProcess from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import dgram from 'node:dgram';
import dns from 'node:dns';
import workers from 'node:worker_threads';
import cluster from 'node:cluster';
import Module, { registerHooks, syncBuiltinESMExports } from 'node:module';
import { dirname, basename, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = process.env.BOTA_PACKED_GUARD_DIRECTORY;
const report = process.env.BOTA_PACKED_GUARD_REPORT;
const modules = process.env.BOTA_PACKED_GUARD_MODULES;
if (!directory || !report || !modules || !process.env.TEMP || !isAbsolute(directory) || !isAbsolute(report) || !isAbsolute(modules)
  || resolve(directory) !== resolve(process.env.TEMP, 'developer-guards') || dirname(resolve(report)) !== resolve(directory)
  || !/^probe-[0-9a-f-]{36}\.json$/.test(basename(report))
  || resolve(modules) !== resolve(process.env.TEMP, 'consumer', 'node_modules')) throw Error('Packed guard configuration refused.');
const entry = resolve(process.argv[1]);
// open's existing is-wsl/container imports inspect these public Linux startup
// facts. They are not user/native-store paths and are read-only exceptions.
const startupMetadata = new Set(process.platform === 'linux' ? ['/proc/version', '/proc/sys/fs/binfmt_misc/WSLInterop',
  '/run/WSL', '/run/.containerenv', '/.dockerenv', '/proc/self/cgroup'] : []);
let startupMetadataReads = 0;
const originalOpenSync = fs.openSync, originalWriteSync = fs.writeSync, originalCloseSync = fs.closeSync;
const effects = { process_spawn: 0, process_control: 0, worker_spawn: 0, network_request: 0,
  network_listen: 0, native_module: 0, filesystem_read: 0, filesystem_write: 0 };
const refusal = kind => {
  effects[kind]++;
  const error = new Error('Packed developer probe refused an effect.');
  error.code = 'BOTA_PACKED_DEVELOPER_TRIPWIRE';
  throw error;
};
const replace = (owner, name, kind) => { if (typeof owner?.[name] === 'function') owner[name] = function() { return refusal(kind); }; };
process.once('exit', code => {
  const body = JSON.stringify({ schema_version: 1,
  instrument: 'packed-developer-default-off-v1', installed_before_entrypoint: true, exit_code: code, effects,
  permitted_linux_startup_metadata_reads: startupMetadataReads,
  limits: ['Instrument-owned report write, Node module-loader reads and six exact public Linux is-wsl/container metadata paths are permitted.',
    'Not an adversarial sandbox: direct internal bindings, previously captured runtime internals, process.exit and OS/runtime startup effects are not qualified.',
    'No actual credential/native-store/ACL qualification; assertions concern guarded attempts only.'] }) + '\n';
  const descriptor = originalOpenSync(report, 'wx', 0o600);
  try { originalWriteSync(descriptor, body); } finally { originalCloseSync(descriptor); }
});

const isNative = value => {
  const name = value.replaceAll('\\', '/').toLowerCase();
  return name === 'node:sqlite' || name === 'koffi' || name.startsWith('koffi/') || name.startsWith('@koromix/koffi')
    || /\/node_modules\/(?:koffi|@koromix\/koffi[^/]*)(?:\/|$)/.test(name) || /\.node(?:$|[?#])/.test(name);
};
// Synchronous hooks cover ESM, require and createRequire before resolution/load.
registerHooks({ resolve(specifier, context, next) {
  if (isNative(specifier)) return refusal('native_module');
  return next(specifier, context);
}, load(url, context, next) {
  if (isNative(url)) return refusal('native_module');
  return next(url, context);
} });
for (const name of ['_load', '_resolveFilename']) {
  const original = Module[name];
  Module[name] = function(specifier, ...args) {
    if (typeof specifier === 'string' && isNative(specifier)) return refusal('native_module');
    return Reflect.apply(original, this, [specifier, ...args]);
  };
}
Module._extensions['.node'] = () => refusal('native_module');
replace(process, 'dlopen', 'native_module');
replace(process, 'kill', 'process_control'); replace(process, 'abort', 'process_control');
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) replace(childProcess, name, 'process_spawn');
replace(cluster, 'fork', 'process_spawn'); replace(workers, 'Worker', 'worker_spawn');
globalThis.fetch = () => refusal('network_request');
if (typeof globalThis.WebSocket === 'function') globalThis.WebSocket = class { constructor() { refusal('network_request'); } };
for (const owner of [http, https]) for (const name of ['request', 'get']) replace(owner, name, 'network_request');
for (const name of ['connect', 'createConnection']) replace(net, name, 'network_request');
replace(net.Socket.prototype, 'connect', 'network_request'); replace(net.Server.prototype, 'listen', 'network_listen');
replace(tls, 'connect', 'network_request'); replace(http2, 'connect', 'network_request');
replace(dgram, 'createSocket', 'network_request');
for (const owner of [dns, dns.promises]) for (const name of Object.keys(owner)) {
  if (/^(?:lookup|resolve|reverse)/.test(name)) replace(owner, name, 'network_request');
}
for (const prototype of [dns.Resolver?.prototype, dns.promises.Resolver?.prototype]) for (const name of Object.getOwnPropertyNames(prototype ?? {})) {
  if (/^(?:lookup|resolve|reverse)/.test(name)) replace(prototype, name, 'network_request');
}

const allowedRead = value => {
  try {
    const path = resolve(value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString('utf8') : value);
    if (startupMetadata.has(path)) { startupMetadataReads++; return true; }
    const child = relative(resolve(modules), path);
    return path === entry || child !== '' && !isAbsolute(child) && child !== '..' && !child.startsWith('..' + sep);
  } catch { return false; }
};
const wrapRead = (owner, name) => {
  const original = owner[name]; if (typeof original !== 'function') return;
  const guarded = function(path, ...args) { if (!allowedRead(path)) return refusal('filesystem_read'); return Reflect.apply(original, this, [path, ...args]); };
  // Node's CJS resolver uses realpathSync.native when available.
  if (typeof original.native === 'function') guarded.native = function(path, ...args) {
    if (!allowedRead(path)) return refusal('filesystem_read'); return Reflect.apply(original.native, this, [path, ...args]);
  };
  owner[name] = guarded;
};
for (const owner of [fs, fs.promises]) {
  for (const name of ['readFile', 'readFileSync', 'readdir', 'readdirSync', 'opendir', 'opendirSync', 'stat', 'statSync',
    'lstat', 'lstatSync', 'access', 'accessSync', 'exists', 'existsSync', 'realpath', 'realpathSync', 'readlink', 'readlinkSync', 'createReadStream']) wrapRead(owner, name);
  for (const name of ['write', 'writeSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'mkdir', 'mkdirSync',
    'mkdtemp', 'mkdtempSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'unlink', 'unlinkSync', 'rename', 'renameSync',
    'copyFile', 'copyFileSync', 'cp', 'cpSync', 'link', 'linkSync', 'symlink', 'symlinkSync', 'truncate', 'truncateSync',
    'ftruncate', 'ftruncateSync', 'chmod', 'chmodSync', 'fchmod', 'fchmodSync', 'chown', 'chownSync', 'fchown', 'fchownSync',
    'lchown', 'lchownSync', 'utimes', 'utimesSync', 'futimes', 'futimesSync', 'lutimes', 'lutimesSync', 'createWriteStream', 'watch', 'watchFile']) replace(owner, name, 'filesystem_write');
  for (const name of ['open', 'openSync']) {
    const original = owner[name]; if (typeof original !== 'function') continue;
    owner[name] = function(path, flags, ...args) {
      if (!['r', 'rs', 'sr', fs.constants.O_RDONLY].includes(flags)) return refusal('filesystem_write');
      if (!allowedRead(path)) return refusal('filesystem_read'); return Reflect.apply(original, this, [path, flags, ...args]);
    };
  }
}
syncBuiltinESMExports();
