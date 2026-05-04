import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  platform: 'node',
  target: 'node18',
  clean: true,
  banner: '#!/usr/bin/env node',
});
