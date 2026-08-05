import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { verifyLocalData, main } from '../../../scripts/update-data';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'doctorate-offline-test-'));
const PROJECT_ROOT = process.cwd();

beforeAll(() => {
  // 构造一个只有部分文件的模拟项目目录
  mkdirSync(join(TEMP_DIR, 'data'), { recursive: true });
  writeFileSync(join(TEMP_DIR, 'data/config.json'), '{}');
  writeFileSync(join(TEMP_DIR, 'data/appConfig.json'), '{}');
});

afterAll(() => {
  rmSync(TEMP_DIR, { recursive: true, force: true });
});

describe('verifyLocalData', () => {
  it('项目根目录数据完整时应该返回空数组', () => {
    const missing = verifyLocalData(PROJECT_ROOT);
    expect(missing).toEqual([]);
  });

  it('空目录应该返回全部必需数据文件', () => {
    const emptyDir = mkdtempSync(join(tmpdir(), 'doctorate-offline-empty-'));
    try {
      const missing = verifyLocalData(emptyDir);
      expect(missing.length).toBeGreaterThan(0);
      expect(missing).toContain('data/config.json');
      expect(missing).toContain('data/excel/character_table.json');
      expect(missing).toContain('data/shop/LowGoodList.json');
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  it('部分文件存在时应该只返回缺失文件', () => {
    const missing = verifyLocalData(TEMP_DIR);
    expect(missing).not.toContain('data/config.json');
    expect(missing).not.toContain('data/appConfig.json');
    expect(missing).toContain('data/excel/character_table.json');
    expect(missing).toContain('data/user/users.json');
  });
});

describe('main 离线模式', () => {
  it('离线模式下本地数据完整时应该返回 0', async () => {
    const code = await main(false, true);
    expect(code).toBe(0);
  });
});
