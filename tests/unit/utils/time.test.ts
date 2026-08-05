import { describe, it, expect } from 'vitest';
import moment from 'moment';
import { now, checkBetween, checkNew } from '@utils/time';

describe('now', () => {
  it('应该返回当前时间戳（秒）', () => {
    const before = Math.floor(Date.now() / 1000);
    const result = now();
    const after = Math.floor(Date.now() / 1000);
    expect(result).toBeGreaterThanOrEqual(before);
    expect(result).toBeLessThanOrEqual(after);
    expect(Number.isInteger(result)).toBe(true);
  });

  it('返回值应该是有效的 Unix 时间戳', () => {
    const result = now();
    expect(result).toBeGreaterThan(0);
    expect(result).toBeLessThanOrEqual(9999999999);
  });

  it('连续调用应该返回递增或相同的值', () => {
    const first = now();
    const second = now();
    expect(second).toBeGreaterThanOrEqual(first);
  });
});

describe('checkBetween', () => {
  it('当时间戳在范围内时应该返回 true', () => {
    const start = 1000;
    const end = 2000;
    expect(checkBetween(1500, start, end)).toBe(true);
    expect(checkBetween(1000, start, end)).toBe(true);
    expect(checkBetween(2000, start, end)).toBe(true);
  });

  it('当时间戳在范围外时应该返回 false', () => {
    const start = 1000;
    const end = 2000;
    expect(checkBetween(999, start, end)).toBe(false);
    expect(checkBetween(2001, start, end)).toBe(false);
    expect(checkBetween(0, start, end)).toBe(false);
    expect(checkBetween(5000, start, end)).toBe(false);
  });

  it('边界值应该返回 true', () => {
    expect(checkBetween(100, 100, 200)).toBe(true);
    expect(checkBetween(200, 100, 200)).toBe(true);
    expect(checkBetween(100, 100, 100)).toBe(true);
  });

  it('当 start 大于 end 时应该正确处理', () => {
    expect(checkBetween(1500, 2000, 1000)).toBe(false);
    expect(checkBetween(1500, 1000, 2000)).toBe(true);
  });

  it('应该处理相同的 start 和 end', () => {
    expect(checkBetween(100, 100, 100)).toBe(true);
    expect(checkBetween(99, 100, 100)).toBe(false);
    expect(checkBetween(101, 100, 100)).toBe(false);
  });
});

describe('checkNew', () => {
  it('当两个时间戳在同一天时应该返回 false', () => {
    const ts1 = moment('2024-01-15T10:00:00').valueOf();
    const ts2 = moment('2024-01-15T14:00:00').valueOf();
    expect(checkNew(ts1, ts2, 'day')).toBe(false);
  });

  it('当两个时间戳在不同天时应该返回 true（考虑 4h delta 偏移）', () => {
    const ts1 = moment('2024-01-15T23:00:00').valueOf();
    const ts2 = moment('2024-01-16T05:00:00').valueOf();
    expect(checkNew(ts1, ts2, 'day')).toBe(true);
  });

  it('当两个时间戳在不同周时应该返回 true', () => {
    const ts1 = moment('2024-01-15').valueOf();
    const ts2 = moment('2024-01-22').valueOf();
    expect(checkNew(ts1, ts2, 'week')).toBe(true);
  });

  it('当两个时间戳在同一周时应该返回 false', () => {
    const ts1 = moment('2024-01-15').valueOf();
    const ts2 = moment('2024-01-16').valueOf();
    expect(checkNew(ts1, ts2, 'week')).toBe(false);
  });

  it('应该使用默认的 delta 参数（4 小时）', () => {
    const ts1 = moment('2024-01-15T20:00:00').valueOf();
    const ts2 = moment('2024-01-16T05:00:00').valueOf();
    expect(checkNew(ts1, ts2, 'day')).toBe(true);
  });

  it('应该接受自定义的 delta 参数', () => {
    const ts1 = moment('2024-01-15T12:00:00').valueOf();
    const ts2 = moment('2024-01-15T13:00:00').valueOf();
    const result = checkNew(ts1, ts2, 'day', 3600000);
    expect(typeof result).toBe('boolean');
  });

  it('当两个时间戳相同时应该返回 false', () => {
    const ts = moment('2024-06-15T12:00:00').valueOf();
    expect(checkNew(ts, ts, 'day')).toBe(false);
  });

  it('应该正确处理月份边界（考虑 4h delta 偏移）', () => {
    const ts1 = moment('2024-01-31T23:00:00').valueOf();
    const ts2 = moment('2024-02-01T05:00:00').valueOf();
    expect(checkNew(ts1, ts2, 'day')).toBe(true);
    expect(checkNew(ts1, ts2, 'month')).toBe(true);
  });

  it('秒级时间戳（now() 返回 unix 秒）在不同天时应该返回 true', () => {
    // 模拟生产场景：秒级时间戳 + 默认 delta（4 小时毫秒）
    const ts1 = 1738216849; // 2025-01-30T14:00:49+08:00
    const ts2 = 1785902603; // 2026-08-05T12:03:23+08:00
    expect(checkNew(ts1, ts2, 'day')).toBe(true);
  });

  it('秒级时间戳在同一天时应该返回 false', () => {
    const ts1 = 1738216849; // 2025-01-30T14:00:49+08:00
    const ts2 = 1738234449; // 2025-01-30T18:54:09+08:00（同日）
    expect(checkNew(ts1, ts2, 'day')).toBe(false);
  });
});