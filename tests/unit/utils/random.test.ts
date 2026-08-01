import { describe, it, expect } from 'vitest';
import { randomInt, randomChoice, randomChoices, randomSample, divmod } from '@utils/random';

describe('randomInt', () => {
  it('应该生成 min 和 max 之间的随机整数（包含边界）', () => {
    const min = 1;
    const max = 10;
    for (let i = 0; i < 100; i++) {
      const val = randomInt(min, max);
      expect(val).toBeGreaterThanOrEqual(min);
      expect(val).toBeLessThanOrEqual(max);
      expect(Number.isInteger(val)).toBe(true);
    }
  });

  it('当 min 等于 max 时应该返回该值', () => {
    expect(randomInt(5, 5)).toBe(5);
    expect(randomInt(0, 0)).toBe(0);
    expect(randomInt(-3, -3)).toBe(-3);
  });

  it('应该支持负数范围', () => {
    for (let i = 0; i < 100; i++) {
      const val = randomInt(-10, -1);
      expect(val).toBeGreaterThanOrEqual(-10);
      expect(val).toBeLessThanOrEqual(-1);
    }
  });
});

describe('randomChoice', () => {
  it('应该从数组中随机选择一个元素', () => {
    const arr = [1, 2, 3, 4, 5];
    for (let i = 0; i < 100; i++) {
      const choice = randomChoice(arr);
      expect(arr).toContain(choice);
    }
  });

  it('单元素数组应该总是返回该元素', () => {
    const arr = ['only'];
    for (let i = 0; i < 10; i++) {
      expect(randomChoice(arr)).toBe('only');
    }
  });

  it('应该能处理不同类型的数组', () => {
    const strArr = ['a', 'b', 'c'];
    expect(strArr).toContain(randomChoice(strArr));

    const objArr = [{ id: 1 }, { id: 2 }, { id: 3 }];
    const result = randomChoice(objArr);
    expect(objArr).toContain(result);
  });

  it('空数组应该返回 undefined', () => {
    expect(randomChoice([])).toBeUndefined();
  });
});

describe('randomChoices', () => {
  it('应该按照权重选择指定数量的元素', () => {
    const arr = ['a', 'b', 'c'];
    const weights = [1, 1, 1];
    const k = 3;
    const result = randomChoices(arr, weights, k);
    expect(result).toHaveLength(k);
    result.forEach((item) => {
      expect(arr).toContain(item);
    });
  });

  it('当 k 为 0 时应该返回空数组', () => {
    const arr = [1, 2, 3];
    const weights = [1, 1, 1];
    expect(randomChoices(arr, weights, 0)).toEqual([]);
  });

  it('应该支持重复选择（有放回）', () => {
    const arr = ['a'];
    const weights = [1];
    const k = 5;
    const result = randomChoices(arr, weights, k);
    expect(result).toHaveLength(5);
    result.forEach((item) => expect(item).toBe('a'));
  });

  it('权重越高被选中的概率越大', () => {
    const arr = ['heavy', 'light'];
    const weights = [100, 1];
    let heavyCount = 0;
    const trials = 10000;
    for (let i = 0; i < trials; i++) {
      const result = randomChoices(arr, weights, 1);
      if (result[0] === 'heavy') heavyCount++;
    }
    expect(heavyCount).toBeGreaterThan(trials * 0.9);
  });
});

describe('randomSample', () => {
  it('应该从数组中随机抽取 k 个不重复的元素', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const k = 3;
    const result = randomSample(arr, k);
    expect(result).toHaveLength(k);
    result.forEach((item) => expect(arr).toContain(item));
    const unique = new Set(result);
    expect(unique.size).toBe(k);
  });

  it('当 k 大于数组长度时应该返回整个数组', () => {
    const arr = [1, 2, 3];
    const result = randomSample(arr, 10);
    expect(result).toHaveLength(3);
  });

  it('当 k 为 0 时应该返回空数组', () => {
    const arr = [1, 2, 3];
    expect(randomSample(arr, 0)).toEqual([]);
  });
});

describe('divmod', () => {
  it('应该正确计算正整数的商和余数', () => {
    expect(divmod(10, 3)).toEqual([3, 1]);
    expect(divmod(7, 2)).toEqual([3, 1]);
    expect(divmod(100, 10)).toEqual([10, 0]);
  });

  it('应该正确处理负数（JavaScript % 保留被除数符号）', () => {
    expect(divmod(-7, 2)).toEqual([-4, -1]);
    expect(divmod(7, -2)).toEqual([-4, 1]);
    expect(divmod(-7, -2)).toEqual([3, -1]);
  });

  it('当整除时余数为 0', () => {
    expect(divmod(10, 5)).toEqual([2, 0]);
    expect(divmod(100, 25)).toEqual([4, 0]);
  });

  it('被除数为 0 时商为 0', () => {
    expect(divmod(0, 5)).toEqual([0, 0]);
  });

  it('除数为 1 时商等于被除数', () => {
    expect(divmod(42, 1)).toEqual([42, 0]);
    const result = divmod(-42, 1);
    expect(result[0]).toBe(-42);
    expect(Object.is(result[1], -0)).toBe(true);
  });
});