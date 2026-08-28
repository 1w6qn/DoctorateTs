import { defineConfig } from 'vitest/config';
import path from 'path';
import { fileURLToPath } from 'node:url';

// 以 .mts 显式声明 ESM，规避 Vite 8 的 configLoader:'native' 把本项目（type: commonjs）
// 下的 .ts 配置误判为 CommonJS 加载——该误判会导致套件注册失败（所有测试弃跑）。
const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
      exclude: ['app/game/excel/**', 'app/core/config/**', 'app/ops/assets/**'],
      thresholds: {
        // 实测全局 ~51% 行 / 47% 函数 / 41% 分支——阈值低于现值留缓冲（D2）
        lines: 40,
        functions: 35,
        branches: 25,
        statements: 40,
      },
    },
  },
  resolve: {
    alias: {
      '@game': path.resolve(__dirname, 'app/game'),
      '@excel': path.resolve(__dirname, 'app/game/excel'),
      '@utils': path.resolve(__dirname, 'app/core/utils'),
      '@capture': path.resolve(__dirname, 'app/ops/capture'),
      '@logs': path.resolve(__dirname, 'app/core/logs'),
      '@plugin': path.resolve(__dirname, 'app/ops/plugin'),
      '@asset': path.resolve(__dirname, 'app/ops/assets/asset-registry'),
      '@core': path.resolve(__dirname, 'app/core'),
      '@ops': path.resolve(__dirname, 'app/ops'),
    },
  },
});