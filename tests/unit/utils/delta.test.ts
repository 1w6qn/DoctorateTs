import { describe, it, expect } from 'vitest';
import { patchesToObject } from '@utils/delta';
import type { Patch } from 'immer';

describe('patchesToObject', () => {
  it('应该正确处理 replace 操作', () => {
    const patches: Patch[] = [
      { op: 'replace', path: ['name'], value: 'newName' },
    ];
    const origin = { name: 'oldName', age: 20 };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ name: 'newName' });
    expect(result.deleted).toEqual({});
  });

  it('应该正确处理 remove 操作', () => {
    const patches: Patch[] = [
      { op: 'remove', path: ['tempField'] },
    ];
    const origin = { name: 'test', tempField: 'value' };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({});
    expect(result.deleted).toEqual({ tempField: null });
  });

  it('应该正确处理 add 操作', () => {
    const patches: Patch[] = [
      { op: 'add', path: ['newField'], value: 'added' },
    ];
    const origin = { name: 'test' };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ newField: 'added' });
    expect(result.deleted).toEqual({});
  });

  it('应该处理嵌套路径的修改', () => {
    const patches: Patch[] = [
      { op: 'replace', path: ['player', 'stats', 'hp'], value: 100 },
    ];
    const origin = { player: { stats: { hp: 50, mp: 30 } } };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ player: { stats: { hp: 100 } } });
  });

  it('应该处理嵌套路径的删除', () => {
    const patches: Patch[] = [
      { op: 'remove', path: ['player', 'tempBuff'] },
    ];
    const origin = { player: { name: 'test', tempBuff: 'expired' } };
    const result = patchesToObject(patches, origin);
    expect(result.deleted).toEqual({ player: { tempBuff: null } });
  });

  it('应该处理多个 patch 操作', () => {
    const patches: Patch[] = [
      { op: 'replace', path: ['gold'], value: 1000 },
      { op: 'replace', path: ['level'], value: 5 },
      { op: 'remove', path: ['expiredItem'] },
    ];
    const origin = { gold: 500, level: 3, expiredItem: 'old' };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ gold: 1000, level: 5 });
    expect(result.deleted).toEqual({ expiredItem: null });
  });

  it('应该处理空的 patch 数组', () => {
    const patches: Patch[] = [];
    const origin = { name: 'test' };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({});
    expect(result.deleted).toEqual({});
  });

  it('应该处理数组路径（遇到数组时设置整个数组作为值）', () => {
    const patches: Patch[] = [
      { op: 'replace', path: ['items', 0], value: 'newItem' },
    ];
    const origin = { items: ['oldItem', 'keepItem'] };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ items: ['oldItem', 'keepItem'] });
  });

  it('应该处理深层嵌套的添加操作', () => {
    const patches: Patch[] = [
      { op: 'add', path: ['config', 'newOption', 'key'], value: 'val' },
    ];
    const origin = { config: {} };
    const result = patchesToObject(patches, origin);
    expect(result.modified).toEqual({ config: { newOption: { key: 'val' } } });
  });
});