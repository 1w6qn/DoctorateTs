import { describe, it, expect, vi, beforeEach } from "vitest";

// 官方 excel mock：rogue_4 difficulties（scoreFactor）+ items + relics
vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_4: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          difficulties: [
            { modeDifficulty: "NORMAL", grade: 0, scoreFactor: 1, name: "直面魂灵" },
            { modeDifficulty: "NORMAL", grade: 5, scoreFactor: 1.25, name: "直面魂灵" },
            { modeDifficulty: "MONTH_TEAM", grade: 0, scoreFactor: 0, name: "讲述者列表" },
          ],
          items: {},
          relics: {},
          detailConst: { playerLevelTable: { 2: { exp: 10 } } },
        },
      },
      modules: { rogue_4: { fragment: null } },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer(opts: { pointOwned?: number; zone?: number } = {}) {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: {
      outer: {
        rogue_4: {
          buff: { pointOwned: opts.pointOwned ?? 0, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme: "rogue_4", mode: "NORMAL", modeGrade: 0, predefined: null, start: Date.now() / 1000 } as any;
  return player;
}

/** 构造标准结算现场：2 层 + 5 步 + 3 普通战 + 1 精英 + 1 boss + 2 招募 + 4 物品 → raw=187 */
function setupSettleScene(player: PlayerDataManager, opts: { zone?: number; mode?: string; modeGrade?: number } = {}) {
  const rlv2 = player.rlv2 as any;
  const zone = opts.zone ?? 2;
  rlv2.current.game.mode = opts.mode ?? "NORMAL";
  rlv2.current.game.modeGrade = opts.modeGrade ?? 0;
  rlv2._status.cursor.zone = zone;
  // 地图：zone 1（rest 等非战斗）+ zone 2（战斗节点）
  rlv2._map.zones = {
    1: { id: "zone_1", nodes: {
      "0": { type: 0, pos: { x: 0, y: 0 } }, "100": { type: 16, pos: { x: 1, y: 0 } }, // REST
    } },
    2: { id: "zone_2", nodes: {
      "0": { type: 0, pos: { x: 0, y: 0 } },
      "100": { type: 1, pos: { x: 1, y: 0 } }, "101": { type: 1, pos: { x: 1, y: 1 } }, "102": { type: 1, pos: { x: 1, y: 2 } }, // 普通×3
      "200": { type: 2, pos: { x: 2, y: 0 } }, // 精英×1
      "300": { type: 4, pos: { x: 3, y: 0 } }, // boss×1
    } },
  };
  // trace：7 步（zone1 的 REST + zone2 的 起点/普通×3/精英/boss）
  rlv2._status.trace = [
    { zone: 1, position: { x: 1, y: 0 } },
    { zone: 2, position: { x: 0, y: 0 } },
    { zone: 2, position: { x: 1, y: 0 } },
    { zone: 2, position: { x: 1, y: 1 } },
    { zone: 2, position: { x: 1, y: 2 } },
    { zone: 2, position: { x: 2, y: 0 } },
    { zone: 2, position: { x: 3, y: 0 } },
  ];
  // 招募：2 张已完成的券
  rlv2.inventory._recruit.tickets = {
    t_0: { index: "t_0", state: 3, result: { charId: "char_001" } },
    t_1: { index: "t_1", state: 3, result: { charId: "char_002" } },
    t_2: { index: "t_2", state: 1, list: [] }, // 未完成
  };
  // 物品：4 个收藏品 + 1 个战术道具
  rlv2.inventory._relic.relics = {
    r_0: { id: "rogue_4_relic_a01", count: 1 },
    r_1: { id: "rogue_4_relic_a02", count: 1 },
    r_2: { id: "rogue_4_relic_a03", count: 1 },
    r_3: { id: "rogue_4_relic_a04", count: 1 },
  };
  rlv2.inventory.exploreTool = { e_1: { id: "rogue_4_explore_tool_1", count: 1 } };
  rlv2._status.toEnding = "normal";
  rlv2._status.property.level = 1;
  rlv2._status.property.hp = { current: 10, max: 10 };
}

describe("rlv2 结算探索分数与魂灵书签", () => {
  it("标准结算（2 层/7 步/3 普通/1 精英/1 boss/2 招募/5 物品）×1 = 196 分", async () => {
    const player = makePlayer();
    setupSettleScene(player);
    await (player.rlv2 as any).gameSettle();
    const buff = player._playerdata.rlv2.outer.rogue_4.buff;
    expect(buff.score).toBe(196);
    expect(buff.pointOwned).toBe(196); // 1:1 书签
  });

  it("难度倍率生效：modeGrade 5 → scoreFactor 1.25 → floor(196×1.25)=245", async () => {
    const player = makePlayer();
    setupSettleScene(player, { modeGrade: 5 });
    await (player.rlv2 as any).gameSettle();
    const buff = player._playerdata.rlv2.outer.rogue_4.buff;
    expect(buff.score).toBe(245);
    expect(buff.pointOwned).toBe(245);
  });

  it("超过 7 层按 7 层档位（650）", async () => {
    const player = makePlayer();
    setupSettleScene(player, { zone: 9 });
    // 9 层 → 档位 650（其他项：7+30+20+30+4+25=116）
    await (player.rlv2 as any).gameSettle();
    const buff = player._playerdata.rlv2.outer.rogue_4.buff;
    expect(buff.score).toBe(650 + 116);
  });

  it("MONTH_TEAM 模式倍率为 0（不加分）", async () => {
    const player = makePlayer();
    setupSettleScene(player, { mode: "MONTH_TEAM" });
    await (player.rlv2 as any).gameSettle();
    const buff = player._playerdata.rlv2.outer.rogue_4.buff;
    expect(buff.score).toBe(0);
    expect(buff.pointOwned).toBe(0);
  });

  it("主题无 outer.buff（从未玩过）应自动创建不崩", async () => {
    const pd: any = mockPlayerData({
      pushFlags: { status: 123456 } as any,
      rlv2: { outer: {}, current: {}, pinned: {} } as any,
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
      mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
    });
    const player = new PlayerDataManager(pd._playerdata);
    player.rlv2.current.game = { theme: "rogue_4", mode: "NORMAL", modeGrade: 0, predefined: null, start: Date.now() / 1000 } as any;
    setupSettleScene(player);
    await (player.rlv2 as any).gameSettle();
    const buff = player._playerdata.rlv2.outer.rogue_4.buff;
    expect(buff).toBeDefined();
    expect(buff.score).toBe(196);
  });
});
