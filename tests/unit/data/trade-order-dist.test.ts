import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 贸易站订单概率配置结构守护（data/building/trade-order-dist.json） */
describe("trade-order-dist.json 结构", () => {
  const cfg = JSON.parse(
    readFileSync(`${__dirname}/../../../data/building/trade-order-dist.json`, "utf-8"),
  ) as {
    warmupAlphaHours: number;
    warmupBetaHours: number;
    goldOrderDistribution: Record<string, { gold: number; weight: number }[]>;
    distAlpha: { gold: number; weight: number }[];
    distBeta: { gold: number; weight: number }[];
    distAlphaAlpha: { gold: number; weight: number }[];
  };

  it("站级分布覆盖 1~3 级且每级权重合计 100", () => {
    expect(Object.keys(cfg.goldOrderDistribution).sort()).toEqual(["1", "2", "3"]);
    for (const lv of ["1", "2", "3"]) {
      const sum = cfg.goldOrderDistribution[lv].reduce((s, e) => s + e.weight, 0);
      expect(sum, `Lv${lv} 权重合计`).toBe(100);
    }
  });

  it("暖机分布权重合计 100", () => {
    for (const dist of [cfg.distAlpha, cfg.distBeta, cfg.distAlphaAlpha]) {
      expect(dist.reduce((s, e) => s + e.weight, 0)).toBe(100);
    }
  });

  it("暖机阈值 β > α > 0", () => {
    expect(cfg.warmupAlphaHours).toBeGreaterThan(0);
    expect(cfg.warmupBetaHours).toBeGreaterThan(cfg.warmupAlphaHours);
  });
});
