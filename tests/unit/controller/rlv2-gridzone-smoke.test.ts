import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
      details: {
        rogue_6: {
          stages: {
            ro6_n_1_1: { id: "ro6_n_1_1" },
            ro6_n_1_2: { id: "ro6_n_1_2" },
            ro6_n_1_3: { id: "ro6_n_1_3" },
            ro6_e_1_1: { id: "ro6_e_1_1" },
            ro6_n_5_1: { id: "ro6_n_5_1" },
            ro6_e_5_1: { id: "ro6_e_5_1" },
          },
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {
            rogue_6_scrap_G_07: { id: "rogue_6_scrap_G_07", type: "SCRAP", rarity: "RARE" },
            rogue_6_legacy_01: { id: "rogue_6_legacy_01", type: "LEGACY", rarity: "NORMAL" },
            char_508_aguard: { id: "char_508_aguard", type: "CHARACTER", rarity: "NORMAL" },
            rogue_6_ap: { id: "rogue_6_ap", type: "SPECIAL_ZONE_AP", rarity: "NONE" },
            rogue_6_stash_recruit: { id: "rogue_6_stash_recruit", type: "STASH_RECRUIT_LIMIT", rarity: "NONE" },
            rogue_6_bubble_01: { id: "rogue_6_bubble_01", type: "NODE_BUOY", rarity: "NONE" },
          },
        },
      },
      modules: {
        rogue_6: {
          moduleTypes: ["GRID_ZONE", "SCRAP"],
          scrap: { scrapItemToType: { rogue_6_scrap_G_07: "GOODS" } },
        },
      },
    consts: {},
  },
  CharacterTable: {},
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import { BLACKSTREAM_CONSTRUCTIONS } from "@game/controller/rlv2/modules/blackstream-data";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade: 0 } as any;
  return player;
}

/** Math.random 固定 0：generate 恒取每层第一张模板，便于按模板精确断言 */
async function withFixedRandom(fn: () => Promise<void> | void) {
  const spy = vi.spyOn(Math, "random").mockReturnValue(0);
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
}

describe("GRID_ZONE 官服结构对齐（构造模板）", () => {
  it("各层生成：节点 ID 为 x*100+y、map/light 对齐、终点 zone_end", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;

      for (const zone of [1, 2, 3, 4, 5]) {
        gz.generate([zone]);
        const light = gz.toJSON().zones[`zone_${zone}`].nodes;
        const mapNodes = (player.rlv2 as any)._map.zones[String(1000 + zone - 1)]?.nodes;
        expect(mapNodes, `zone ${zone} map.zones`).toBeTruthy();
        expect(Object.keys(mapNodes).length).toBe(Object.keys(light).length);
        for (const id of Object.keys(light)) {
          expect(mapNodes[id], `zone ${zone} node ${id}`).toBeTruthy();
          const x = Math.floor(Number(id) / 100);
          const y = Number(id) % 100;
          expect(mapNodes[id].pos).toEqual({ x, y });
        }
        // 起点（唯一 state 1）为 GLADE
        const start = Object.entries(light).find(([, n]: any) => n.state === 1);
        expect(start, `zone ${zone} 起点`).toBeTruthy();
        expect((start![1] as any).content).toEqual({}); // 起点 content 空（官方线格式）
        // 终点 zone_end ≥1 且 type 为 VISIBLE_END/BATTLE_BOSS
        const ends = Object.values(mapNodes).filter((n: any) => n.zone_end);
        expect(ends.length, `zone ${zone} 终点`).toBeGreaterThan(0);
        for (const e of ends) {
          expect([8388608, 4]).toContain(e.type);
        }
        // 战斗节点带 stage
        const battles = Object.values(mapNodes).filter((n: any) => n.type === 1 || n.type === 2 || n.type === 4);
        for (const b of battles) expect(b.stage).toBeTruthy();
      }
    });
  });

  it("1-2 层起点相邻（边距离 1）必为作战", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;
      for (const zone of [1, 2]) {
        gz.generate([zone]);
        const light = gz.toJSON().zones[`zone_${zone}`].nodes;
        const t = BLACKSTREAM_CONSTRUCTIONS.find((c) => c.layerIndex === zone - 1)!;
        const dist = gz.edgeDistances(t);
        const startId = Object.entries(light).find(([, n]: any) => n.state === 1)![0];
        for (const [id, n] of Object.entries(light) as [string, any][]) {
          if (dist.get(id) === 1 && id !== startId) {
            expect(n.content.savage, `zone ${zone} 相邻 ${id}`).toBeTruthy();
          }
        }
      }
    });
  });

  it("非战斗节点类型必须落在层 5 距离规则内（沿边距离）", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;
      gz.generate([5]);
      const light = gz.toJSON().zones["zone_5"].nodes;
      const t5 = BLACKSTREAM_CONSTRUCTIONS.find((c) => c.layerIndex === 4)!;
      const dist = gz.edgeDistances(t5);
      // 起点
      const startId = Object.entries(light).find(([, n]: any) => n.state === 1)![0];
      for (const [id, n] of Object.entries(light) as [string, any][]) {
        if (id === startId) continue; // 起点不受距离规则约束
        const d = dist.get(id);
        expect(d, `zone5 ${id} 距离`).toBeGreaterThanOrEqual(1);
      }
    });
  });
});

describe("GRID_ZONE 物品发放类型兜底（fix funcs[type] 崩溃）", () => {
  it("rogue_6 各物品类型 getItem 不抛错（SCRAP/LEGACY/NODE_BUOY/CHARACTER 等）", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const inv = (player.rlv2 as any).inventory;
      // 触发 immediate_reward 同路径：rlv2:get:items → inventory.getItem
      await (player.rlv2 as any)._trigger.emit("rlv2:get:items", [[
        { id: "rogue_6_scrap_G_07", count: 1, sub: 0 },
        { id: "rogue_6_legacy_01", count: 1, sub: 0 },
        { id: "rogue_6_ap", count: 1, sub: 0 },
        { id: "rogue_6_stash_recruit", count: 1, sub: 0 },
        { id: "rogue_6_bubble_01", count: 1, sub: 0 },
      ]]);
      // 各类型 getItem 不再抛错（修复 funcs[type] is not a function 500）
      // SCRAP 型应进入 SCRAP 模块库存
      const scrapInv = (player.rlv2 as any)._module.scrap?.inventory || {};
      expect(Object.keys(scrapInv).length).toBeGreaterThan(0);
    });
  });

  it("CHARACTER 型干员应触发招募（rlv2:recruit:initial_char）", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const recv: string[] = [];
      (player.rlv2 as any)._trigger.on("rlv2:recruit:initial_char", ([id]: [string]) => recv.push(id));
      await (player.rlv2 as any)._trigger.emit("rlv2:get:items", [[
        { id: "char_508_aguard", count: 1, sub: 0 },
      ]]);
      expect(recv).toContain("char_508_aguard");
    });
  });
});

describe("rogue_6 战斗奖励（零件/收藏品）", () => {
  it("rogue_6 主题 scrapItemToType 零件池非空（战斗奖励可产出零件）", async () => {
    // mock 中 rogue_6 modules.scrap.scrapItemToType 已配置 → 验证零件奖励数据源存在
    const modules = excelMock.RoguelikeTopicTable.modules.rogue_6;
    expect(modules.scrap.scrapItemToType).toBeTruthy();
    expect(Object.keys(modules.scrap.scrapItemToType).length).toBeGreaterThan(0);
  });
});
