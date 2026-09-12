import { describe, it, expect } from "vitest";
import { normalizeStageDropInfo, type RawDisplayDetailRewards } from "@excel/excel";

/**
 * 掉落明细行夹具视图
 *
 * 在真实 {@link RawDisplayDetailRewards} 之上补充官方行里确实存在的 `type`/`id` 键
 * （`normalizeStageDropInfo` 不读取它们，仅夹具记录）。
 */
interface DisplayDetailRewardFixture extends RawDisplayDetailRewards {
  /** 掉落物类型（MATERIAL/CHAR/…） */
  type?: string;
  /** 掉落物 id */
  id?: string;
}

/**
 * 掉落信息夹具表视图
 *
 * `normalizeStageDropInfo` 的形参把 `stageDropInfo` 声明为可选/可空（真实 StageTable 可缺省），
 * 用例夹具则总是提供 `displayDetailRewards`；本视图按夹具形状声明，读取处只需收窄
 * `stageDropInfo`（字段名/类型仍受真实 `RawDisplayDetailRewards` 约束）。
 */
type StageDropTableFixture = {
  stages: {
    [key: string]: { stageDropInfo?: { displayDetailRewards: DisplayDetailRewardFixture[] } | null };
  };
};

/**
 * 归一化后的掉落明细视图
 *
 * `normalizeStageDropInfo` 保证两个字段都已从字符串档位写成数字；需要把读数交给
 * `toBeLessThan` 等只接受 `number | bigint` 的匹配器时，按该保证声明视图（单向可比：
 * 数字类型可赋给 {@link DisplayDetailRewardFixture} 的联合字段类型）。
 */
type NormalizedRewardsView = { occPercent: number; dropType: number }[];

/**
 * 掉落信息归一化单元测试
 * 验证 displayDetailRewards 的 occPercent/dropType 字符串 → 数字映射
 */
describe("normalizeStageDropInfo", () => {
  it("应将 occPercent 字符串映射为数字档位", () => {
    const table: StageDropTableFixture = {
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
    const drops = table.stages.main_01.stageDropInfo!.displayDetailRewards;
    // 档位按官方 OccPer 声明序单调递减：ALWAYS(0) > ALMOST(1) > USUAL(2) > OFTEN(3) > SOMETIMES(4)
    expect(drops[0].occPercent).toBe(0); // ALWAYS
    expect(drops[1].occPercent).toBe(2); // USUAL
    expect(drops[2].occPercent).toBe(3); // OFTEN
    expect(drops[3].occPercent).toBe(4); // SOMETIMES
    expect(drops[4].occPercent).toBe(1); // ALMOST
  });

  it("档位应按实测掉落率单调递减（ALMOST 最高、SOMETIMES 最低）", () => {
    const table: StageDropTableFixture = {
      stages: {
        main_01: {
          stageDropInfo: {
            displayDetailRewards: [
              { occPercent: "ALMOST", type: "MATERIAL", id: "30041", dropType: "NORMAL" },
              { occPercent: "USUAL", type: "MATERIAL", id: "30013", dropType: "NORMAL" },
              { occPercent: "OFTEN", type: "MATERIAL", id: "30073", dropType: "NORMAL" },
              { occPercent: "SOMETIMES", type: "MATERIAL", id: "30011", dropType: "ADDITIONAL" },
              { occPercent: "NEVER", type: "MATERIAL", id: "30099", dropType: "ADDITIONAL" },
            ],
          },
        },
      },
    };
    normalizeStageDropInfo(table);
    // 归一化后 occPercent/dropType 已由 `normalizeStageDropInfo` 保证为数字；此处按该保证读取
    const d = table.stages.main_01.stageDropInfo!.displayDetailRewards as NormalizedRewardsView;
    expect(d[0].occPercent).toBeLessThan(d[1].occPercent); // ALMOST < USUAL
    expect(d[1].occPercent).toBeLessThan(d[2].occPercent); // USUAL < OFTEN
    expect(d[2].occPercent).toBeLessThan(d[3].occPercent); // OFTEN < SOMETIMES
    expect(d[4].occPercent).toBeGreaterThanOrEqual(5); // NEVER 不产出
  });

  it("应将 dropType 字符串映射为数字", () => {
    const table: StageDropTableFixture = {
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
    const drops = table.stages.main_01.stageDropInfo!.displayDetailRewards;
    expect(drops[0].dropType).toBe(1); // ONCE
    expect(drops[1].dropType).toBe(2); // NORMAL
    expect(drops[2].dropType).toBe(3); // SPECIAL
    expect(drops[3].dropType).toBe(4); // ADDITIONAL
    expect(drops[4].dropType).toBe(8); // COMPLETE
    expect(drops[5].dropType).toBe(8); // CONDITION_DROP
  });

  it("已为数字的值应保持不变（幂等）", () => {
    const table: StageDropTableFixture = {
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
    const drops = table.stages.main_01.stageDropInfo!.displayDetailRewards;
    expect(drops[0].occPercent).toBe(0);
    expect(drops[0].dropType).toBe(2);
  });

  it("无掉落信息的关卡应安全跳过", () => {
    const table: StageDropTableFixture = {
      stages: {
        main_01: { stageDropInfo: null },
        main_02: {},
      },
    };
    expect(() => normalizeStageDropInfo(table)).not.toThrow();
  });
});
