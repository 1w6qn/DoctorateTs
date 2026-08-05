import { describe, it, expect } from "vitest";
import { normalizeStageDropInfo } from "@excel/stage_table";

/**
 * 掉落信息归一化单元测试
 * 验证 displayDetailRewards 的 occPercent/dropType 字符串 → 数字映射
 */
describe("normalizeStageDropInfo", () => {
  it("应将 occPercent 字符串映射为数字档位", () => {
    const table: any = {
      stages: {
        main_01: {
          stageDropInfo: {
            displayDetailRewards: [
              { occPercent: "ALWAYS", type: "MATERIAL", id: "30012", dropType: "NORMAL" },
              { occPercent: "USUAL", type: "MATERIAL", id: "30011", dropType: "NORMAL" },
              { occPercent: "OFTEN", type: "MATERIAL", id: "30021", dropType: "ADDITIONAL" },
              { occPercent: "SOMETIMES", type: "MATERIAL", id: "30031", dropType: "ADDITIONAL" },
              { occPercent: "ALMOST", type: "MATERIAL", id: "30041", dropType: "ADDITIONAL" },
            ],
          },
        },
      },
    };
    normalizeStageDropInfo(table);
    const drops = table.stages.main_01.stageDropInfo.displayDetailRewards;
    expect(drops[0].occPercent).toBe(0); // ALWAYS
    expect(drops[1].occPercent).toBe(1); // USUAL
    expect(drops[2].occPercent).toBe(2); // OFTEN
    expect(drops[3].occPercent).toBe(3); // SOMETIMES
    expect(drops[4].occPercent).toBe(4); // ALMOST
  });

  it("应将 dropType 字符串映射为数字", () => {
    const table: any = {
      stages: {
        main_01: {
          stageDropInfo: {
            displayDetailRewards: [
              { occPercent: "ALWAYS", type: "CHAR", id: "char_1", dropType: "ONCE" },
              { occPercent: "ALWAYS", type: "MATERIAL", id: "30012", dropType: "NORMAL" },
              { occPercent: "SOMETIMES", type: "MATERIAL", id: "30011", dropType: "SPECIAL" },
              { occPercent: "SOMETIMES", type: "MATERIAL", id: "30021", dropType: "ADDITIONAL" },
              { occPercent: "ALWAYS", type: "DIAMOND", id: "4002", dropType: "COMPLETE" },
              { occPercent: "ALWAYS", type: "PLOT_ITEM", id: "p1", dropType: "CONDITION_DROP" },
            ],
          },
        },
      },
    };
    normalizeStageDropInfo(table);
    const drops = table.stages.main_01.stageDropInfo.displayDetailRewards;
    expect(drops[0].dropType).toBe(1); // ONCE
    expect(drops[1].dropType).toBe(2); // NORMAL
    expect(drops[2].dropType).toBe(3); // SPECIAL
    expect(drops[3].dropType).toBe(4); // ADDITIONAL
    expect(drops[4].dropType).toBe(8); // COMPLETE
    expect(drops[5].dropType).toBe(8); // CONDITION_DROP
  });

  it("已为数字的值应保持不变（幂等）", () => {
    const table: any = {
      stages: {
        main_01: {
          stageDropInfo: {
            displayDetailRewards: [
              { occPercent: 0, type: "MATERIAL", id: "30012", dropType: 2 },
            ],
          },
        },
      },
    };
    normalizeStageDropInfo(table);
    const drops = table.stages.main_01.stageDropInfo.displayDetailRewards;
    expect(drops[0].occPercent).toBe(0);
    expect(drops[0].dropType).toBe(2);
  });

  it("无掉落信息的关卡应安全跳过", () => {
    const table: any = {
      stages: {
        main_01: { stageDropInfo: null },
        main_02: {},
      },
    };
    expect(() => normalizeStageDropInfo(table)).not.toThrow();
  });
});
