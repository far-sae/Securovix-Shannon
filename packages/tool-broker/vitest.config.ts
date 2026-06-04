import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    {
      name: 'js-to-ts',
      enforce: 'pre',
      async resolveId(source, importer) {
        if (importer && source.startsWith('.') && source.endsWith('.js')) {
          const resolved = await this.resolve(source.replace(/\.js$/, '.ts'), importer, { skipSelf: true });
          if (resolved) return resolved;
        }
        return null;
      },
    },
  ],
  test: { include: ['src/**/*.test.ts'], environment: 'node' },
});
