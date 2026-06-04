import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [
    {
      name: 'js-to-ts',
      enforce: 'pre',
      async resolveId(source, importer) {
        if (importer && source.startsWith('.') && source.endsWith('.js')) {
          const resolved = await this.resolve(source.replace(/\.js$/, '.ts'), importer, {
            skipSelf: true,
          });
          if (resolved) return resolved;
        }
        return null;
      },
    },
  ],
  resolve: {
    alias: {
      // @temporalio/common is a peer dep not directly installed in worker —
      // point vitest at the copy hoisted under @temporalio/activity.
      '@temporalio/common': resolve(
        __dirname,
        '../../node_modules/.pnpm/@temporalio+activity@1.17.2/node_modules/@temporalio/common',
      ),
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
