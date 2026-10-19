// Test-only child-process preload. Preserve the relative ordering of independent
// timers while reducing the production 30-second request budget to 1.5 seconds.
// No production environment switch or transport implementation is replaced.
const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (callback, delay, ...args) =>
  originalSetTimeout(callback, delay === 30_000 ? 1_500 : delay, ...args);
if (process.send) process.send('hosted-mcp-deadline-clock-ready');
