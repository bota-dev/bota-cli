import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  splitting: false,
  metafile: true,
  banner: { js: '#!/usr/bin/env node' },
});
