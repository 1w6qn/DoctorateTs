import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // 测试期间日志落盘到 tmp/（gitignored），避免污染 logs/
    env: { LOG_DIR: 'tmp/test-logs' },
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json', 'lcov'],
      include: ['app/**/*.ts'],
      exclude: ['app/excel/**', 'app/config/**', 'app/assets.ts', 'app/updater.ts'],
      thresholds: {
        lines: 5,
        functions: 5,
        branches: 3,
        statements: 5,
      },
    },
  },
  resolve: {
    alias: {
      '@game': path.resolve(__dirname, 'app/game'),
      '@excel': path.resolve(__dirname, 'app/excel'),
      '@utils': path.resolve(__dirname, 'app/utils'),
    },
  },
});