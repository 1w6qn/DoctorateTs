import { describe, it, expect, vi } from "vitest";

// 回归：黑流树海网格生成——林间空地填充格按数量规则生成（修复：生成数据中
// 「林间空地」规则 nodeType 为 null，距离/数量规则解析跳过 → 填充格永无林间空地）
const excelMock = vi.hoisted(() => ({
  // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
  getItem(id: string) { return this.ItemTable?.items?.[id]; },
  itemName(id: string): string { return this.getItem(id)?.name ?? id; },
  makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
  charData(charId: string) { return this.CharacterTable?.[charId]; },
  stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        stages: {
          ro6_n_1_1: { id: "ro6_n_1_1" },
          ro6_n_2_1: { id: "ro6_n_2_1" },
          ro6_n_3_1: { id: "ro6_n_3_1" },
          ro6_n_4_1: { id: "ro6_n_4_1" },
          ro6_n_5_1: { id: "ro6_n_5_1" },
          ro6_e_3_1: { id: "ro6_e_3_1" },
          ro6_b_3: { id: "ro6_b_3" },
          ro6_b_5: { id: "ro6_b_5" },
        },
        items: {},
        relics: {},
        variationData: {},
      },
    },
    modules: {
      rogue_6: {
        moduleTypes: ["GRID_ZONE", "SCRAP"],
        scrap: { scrapItemToType: {} },
      },
    },
    consts: {},
  },
  CharacterTable: {},
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

const GLADE = 268435456;

function makePlayer(): any {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: {
      missions: { DAILY: {}, ACTIVITY: {} },
      missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme: "rogue_6",
    mode: "NORMAL",
    modeGrade: 0,
  } as any;
  return player;
}

describe("黑流树海网格生成：林间空地填充", () => {
  it("Ⅲ/Ⅴ 层生成填充林间空地（数量规则下限 ≥5/≥10，断言至少出现）", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2._module.create();
    const gz = rlv2._module.gridZone;
    for (const zone of [3, 5]) {
      gz.generate([zone]);
      const nodes = Object.values(gz.zones[`zone_${zone}`].nodes) as any[];
      const glades = nodes.filter((n) => n.content?.kind === GLADE);
      // 起点占 1 个 GLADE；填充林间空地必须 ≥1（修复前填充为 0，仅起点）
      expect(glades.length, `zone ${zone} 林间空地上限`).toBeGreaterThan(1);
    }
  });

  it("多轮生成：林间空地数量受数量规则上限约束（Ⅰ 层 ≤3+起点）", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2._module.create();
    const gz = rlv2._module.gridZone;
    for (let i = 0; i < 5; i++) {
      gz.generate([1]);
      const nodes = Object.values(gz.zones["zone_1"].nodes) as any[];
      const glades = nodes.filter((n) => n.content?.kind === GLADE).length;
      // Ⅰ 层数量规则 [0,3] + 起点 1
      expect(glades).toBeLessThanOrEqual(4);
    }
  });
});
