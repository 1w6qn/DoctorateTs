import { describe, it, expect, vi } from "vitest";

// nodesInfo.json 路径修复验证：map.ts 读取 data/rlv2/nodesInfo.json（官方关卡列表），
// 修复前 __dirname 3 级路径指向 app/data/ 导致 _nodesInfo 恒为 null（旧主题走 stages.filter 回退）
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    RoguelikeTopicTable: {
      details: {
        // mock stages 故意只有 1 个——若 nodesInfo 加载成功，生成节点会使用官方列表（ro1_n_1_* 等）
        rogue_1: {
          stages: { ro1_n_1_1: { id: "ro1_n_1_1" }, ro1_b_1: { id: "ro1_b_1" } },
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initialHp: 8, initialGold: 8, initialPopulation: 6, initialSquadCapacity: 6, initialBandRelic: [], initialRecruitGroup: [] }],
          items: {},
          relics: {},
        },
      },
      modules: {
        rogue_1: { moduleTypes: [] },
      },
      consts: {},
    },
    CharacterTable: {},
    GameDataConst: { maxLevel: [[], [], [], [], [], []] },
  },
}));

import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_1: {} } as any,
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme: "rogue_1",
    mode: "NORMAL",
    modeGrade: 0,
    outer: { support: false },
  } as any;
  return player;
}

describe("rlv2 nodesInfo.json 加载（路径修复）", () => {
  it("map manager 成功加载官方关卡列表（_nodesInfo 非 null）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const map = (player.rlv2 as any)._map;
    expect(map._nodesInfo).toBeTruthy();
    // 官方列表结构：themes.rogue_1.zones["1"].Normal/Emergency/Boss
    const z1 = map._nodesInfo.themes["rogue_1"].zones["1"];
    expect(z1.Normal.length).toBeGreaterThan(1);
    expect(z1.Normal[0]).toBe("ro1_n_1_1");
    expect(z1.Boss).toContain("ro1_b_1");
  });

  it("rogue_1 生成区域节点使用官方关卡列表（stage 来自 nodesInfo 而非 mock stages 回退）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const map = (player.rlv2 as any)._map;
    // 固定 Math.random：zone_1 节点少（2-4 个），战斗节点出现是概率性的，
    // 用节点多的 zone_3（奇数层层尾必 boss）保证确定性
    const spy = vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      await (player.rlv2 as any)._trigger.emit("rlv2:zone:new", [3]);
      const zone3 = map.zones[3];
      expect(zone3).toBeTruthy();
      // 层尾 boss 节点：官方 Boss 列表（ro1_b_*）
      const bossNode = Object.values(zone3.nodes).find(
        (n: any) => n.zone_end && n.stage,
      ) as any;
      expect(bossNode?.stage).toMatch(/^ro1_b_\d+$/);
      // 全部带 stage 的节点均属于官方 nodesInfo zones["3"] 列表（Normal/Emergency/Boss），
      // 而非 mock stages 过滤回退（mock 只有 ro1_n_3_1 一个）
      const z3info = map._nodesInfo.themes["rogue_1"].zones["3"];
      const allowed = new Set<string>([
        ...z3info.Normal,
        ...z3info.Emergency,
        ...(z3info.Boss || []),
      ]);
      expect(allowed.size).toBeGreaterThan(1); // 官方列表多个成员（非 mock 单关卡）
      const staged = Object.values(zone3.nodes).filter(
        (n: any) => n.stage,
      ) as any[];
      expect(staged.length).toBeGreaterThan(0);
      for (const n of staged) {
        expect(allowed.has(String(n.stage))).toBe(true);
      }
    } finally {
      spy.mockRestore();
    }
  });
});
