/**
 * resolveGachaRank 保底稀有度解析纯函数测试
 *
 * 由 GachaManager._getRarityRank 拆分出的概率/保底计算，覆盖：
 * - 六星权重修正（非六星连续计数 >50 后每抽 +2%）
 * - 六星命中（rand 注入固定值）
 * - 五星一次性保底（恰达 maxCnt 且未出五星时强制 4）
 * - 非保底权重选择（单权重确定性）
 * - 保底点边界（maxCnt 前/后不触发）
 */
import { describe, it, expect } from "vitest";
import { resolveGachaRank } from "@game/domain/gacha/gacha";

const base = {
  per6Base: 0.02, // totalPercent 为小数概率（0.02 = 2%）
  beforeNonHitCnt: 0,
  nextCnt: 1,
  ranks: [3, 4, 5],
  weights: [0.5, 0.48, 0.02],
};

describe("resolveGachaRank", () => {
  it("未超 50 抽阈值时六星权重不做修正", () => {
    const r = resolveGachaRank({ ...base, beforeNonHitCnt: 49, rand: () => 0.019 });
    expect(r).toBe(5); // per6=0.02，rand=0.019 < 0.02 → 六星
    const r2 = resolveGachaRank({ ...base, beforeNonHitCnt: 49, rand: () => 0.021 });
    expect(r2).not.toBe(5); // rand=0.021 > 0.02 → 非六星
  });

  it("超过 50 抽后每抽 +2% 修正六星权重", () => {
    // beforeNonHitCnt=60 → per6 = 0.02 + 10*0.02 = 0.22
    const r = resolveGachaRank({ ...base, beforeNonHitCnt: 60, rand: () => 0.21 });
    expect(r).toBe(5); // rand=0.21 < 0.22（修正后命中）
    const r2 = resolveGachaRank({ ...base, beforeNonHitCnt: 60, rand: () => 0.23 });
    expect(r2).not.toBe(5); // rand=0.23 > 0.22 → 非六星
  });

  it("rand 高于修正后权重时不中六星，走权重选择", () => {
    const r = resolveGachaRank({
      ...base,
      beforeNonHitCnt: 60,
      rand: () => 0.5, // 0.5 > 0.22 → 非六星
      ranks: [3],
      weights: [1], // 单权重：必选 3（确定性）
    });
    expect(r).toBe(3);
  });

  it("恰达五星保底点且未出五星时强制 4", () => {
    const r = resolveGachaRank({
      ...base,
      nextCnt: 10,
      maxCnt: 10,
      rand: () => 0.99, // 必不中六星
      weights: [1, 0, 0], // 权重只可能选到 3
    });
    expect(r).toBe(4); // 3 < 4 且 atGuarantee → 强制升 4
  });

  it("保底点之前不强制五星", () => {
    const r = resolveGachaRank({
      ...base,
      nextCnt: 9,
      maxCnt: 10,
      rand: () => 0.99,
      weights: [1, 0, 0],
    });
    expect(r).toBe(3); // 非保底点，保持原稀有度
  });

  it("保底点之后（一次性事件已过）不再强制", () => {
    const r = resolveGachaRank({
      ...base,
      nextCnt: 11,
      maxCnt: 10,
      rand: () => 0.99,
      weights: [1, 0, 0],
    });
    expect(r).toBe(3);
  });

  it("抽到五星及以上时不触发五星保底（保持原稀有度）", () => {
    const r = resolveGachaRank({
      ...base,
      nextCnt: 10,
      maxCnt: 10,
      rand: () => 0.99,
      weights: [0, 1, 0], // 权重只可能选到 4
    });
    expect(r).toBe(4); // 已 >=4，不再强制
  });

  it("maxCnt 缺省按 10", () => {
    const r = resolveGachaRank({
      ...base,
      nextCnt: 10,
      rand: () => 0.99,
      weights: [1, 0, 0],
    });
    expect(r).toBe(4);
  });

  it("六星权重基础值兜底 2 时必中六星（详情无六星条目，原实现行为）", () => {
    const r = resolveGachaRank({
      per6Base: 2,
      beforeNonHitCnt: 0,
      nextCnt: 1,
      ranks: [3, 4],
      weights: [0.5, 0.5],
      rand: () => 0.99, // 任意值均 <= 2
    });
    expect(r).toBe(5);
  });
});
