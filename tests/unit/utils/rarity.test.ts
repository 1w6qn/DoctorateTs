import { describe, it, expect } from "vitest";
import { rarityToIndex, rarityIndexToString } from "@utils/rarity";

describe("rarityToIndex（RarityRank 字符串枚举转数值索引）", () => {
  it("TIER_N → N-1（maxLevel/evolveGoldCost 表的下标约定）", () => {
    expect(rarityToIndex("TIER_1")).toBe(0);
    expect(rarityToIndex("TIER_2")).toBe(1);
    expect(rarityToIndex("TIER_3")).toBe(2);
    expect(rarityToIndex("TIER_4")).toBe(3);
    expect(rarityToIndex("TIER_5")).toBe(4);
    expect(rarityToIndex("TIER_6")).toBe(5);
  });

  it("数值输入直接透传", () => {
    expect(rarityToIndex(0)).toBe(0);
    expect(rarityToIndex(5)).toBe(5);
  });

  it("非法输入回退 0（不抛错）", () => {
    expect(rarityToIndex(undefined)).toBe(0);
    expect(rarityToIndex("E_NUM")).toBe(0);
    expect(rarityToIndex("")).toBe(0);
  });

  it("rarityIndexToString 与 rarityToIndex 互逆", () => {
    for (let i = 0; i <= 5; i++) {
      expect(rarityToIndex(rarityIndexToString(i))).toBe(i);
    }
    expect(rarityIndexToString(0)).toBe("TIER_1");
    expect(rarityIndexToString(5)).toBe("TIER_6");
  });
});
