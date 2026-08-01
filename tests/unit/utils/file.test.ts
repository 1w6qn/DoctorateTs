import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { exists, size, readJson, readJsonSync, writeJson } from '@utils/file';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'doctorate-test-'));

beforeAll(() => {
  writeFileSync(join(TEMP_DIR, 'test.json'), JSON.stringify({ name: 'test', value: 42 }));
  writeFileSync(join(TEMP_DIR, 'invalid.json'), 'not valid json');
});

afterAll(() => {
  rmSync(TEMP_DIR, { recursive: true, force: true });
});

describe('exists', () => {
  it('当文件存在时应该返回 true', async () => {
    const result = await exists(join(TEMP_DIR, 'test.json'));
    expect(result).toBe(true);
  });

  it('当文件不存在时应该返回 false', async () => {
    const result = await exists(join(TEMP_DIR, 'nonexistent.json'));
    expect(result).toBe(false);
  });

  it('当路径为空字符串时应该返回 false', async () => {
    const result = await exists('');
    expect(result).toBe(false);
  });
});

describe('size', () => {
  it('应该正确返回文件大小', async () => {
    const filePath = join(TEMP_DIR, 'test.json');
    const result = await size(filePath);
    expect(result).toBeGreaterThan(0);
    const expected = JSON.stringify({ name: 'test', value: 42 }).length;
    expect(result).toBe(expected);
  });

  it('当文件不存在时应该抛出错误', async () => {
    await expect(size(join(TEMP_DIR, 'nonexistent.json'))).rejects.toThrow();
  });
});

describe('readJson', () => {
  it('应该正确读取和解析 JSON 文件', async () => {
    const result = await readJson<{ name: string; value: number }>(join(TEMP_DIR, 'test.json'));
    expect(result).toEqual({ name: 'test', value: 42 });
  });

  it('当文件不存在时应该抛出错误', async () => {
    await expect(readJson(join(TEMP_DIR, 'nonexistent.json'))).rejects.toThrow();
  });

  it('当 JSON 格式无效时应该抛出错误', async () => {
    await expect(readJson(join(TEMP_DIR, 'invalid.json'))).rejects.toThrow();
  });

  it('应该支持泛型类型', async () => {
    const result = await readJson<{ name: string }>(join(TEMP_DIR, 'test.json'));
    expect(result.name).toBe('test');
  });
});

describe('readJsonSync', () => {
  it('应该正确同步读取和解析 JSON 文件', () => {
    const result = readJsonSync<{ name: string; value: number }>(join(TEMP_DIR, 'test.json'));
    expect(result).toEqual({ name: 'test', value: 42 });
  });

  it('当文件不存在时应该抛出错误', () => {
    expect(() => readJsonSync(join(TEMP_DIR, 'nonexistent.json'))).toThrow();
  });

  it('当 JSON 格式无效时应该抛出错误', () => {
    expect(() => readJsonSync(join(TEMP_DIR, 'invalid.json'))).toThrow();
  });
});

describe('writeJson', () => {
  it('应该正确写入 JSON 文件', async () => {
    const filePath = join(TEMP_DIR, 'output.json');
    const data = { message: 'hello', count: 1 };
    await writeJson(filePath, data);
    const result = await readJson(filePath);
    expect(result).toEqual(data);
  });

  it('应该格式化写入（4 空格缩进）', async () => {
    const filePath = join(TEMP_DIR, 'formatted.json');
    const data = { a: 1, b: 2 };
    await writeJson(filePath, data);
    const fs = await import('fs');
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('    ');
  });

  it('应该能覆盖已存在的文件', async () => {
    const filePath = join(TEMP_DIR, 'test.json');
    const newData = { overwritten: true };
    await writeJson(filePath, newData);
    const result = await readJson(filePath);
    expect(result).toEqual(newData);
  });

  it('应该能写入空对象', async () => {
    const filePath = join(TEMP_DIR, 'empty.json');
    await writeJson(filePath, {});
    const result = await readJson(filePath);
    expect(result).toEqual({});
  });
});