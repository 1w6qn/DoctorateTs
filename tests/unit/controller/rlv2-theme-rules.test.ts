import { describe, it, expect, vi, beforeEach } from "vitest";
import { enablePatches } from "immer";

enablePatches();

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_1: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          stages: {
            ro1_n_1_1: { id: "ro1_n_1_1" },
            ro1_n_2_1: { id: "ro1_n_2_1" },
            ro1_n_3_1: { id: "ro1_n_3_1" },
            ro1_n_4_1: { id: "ro1_n_4_1" },
            ro1_n_5_1: { id: "ro1_n_5_1" },
            ro1_n_6_1: { id: "ro1_n_6_1" },
            ro1_e_1_1: { id: "ro1_e_1_1" },
            ro1_e_2_1: { id: "ro1_e_2_1" },
            ro1_e_3_1: { id: "ro1_e_3_1" },
            ro1_e_4_1: { id: "ro1_e_4_1" },
            ro1_e_5_1: { id: "ro1_e_5_1" },
            ro1_e_6_1: { id: "ro1_e_6_1" },
            ro1_b_1: { id: "ro1_b_1" },
            ro1_b_2: { id: "ro1_b_2" },
            ro1_b_3: { id: "ro1_b_3" },
          },
          items: {
            rogue_1_relic_m16: { id: "rogue_1_relic_m16", type: "RELIC", usage: "让探索走向不同的结局" },
            rogue_1_gold: { id: "rogue_1_gold", type: "GOLD" },
          },
          relics: {},
          choices: {
            choice_startbuff_1: { id: "choice_startbuff_1" },
            choice_startbuff_2: { id: "choice_startbuff_2" },
            choice_startbuff_3: { id: "choice_startbuff_3" },
            choice_startbuff_4: { id: "choice_startbuff_4" },
            choice_startbuff_5: { id: "choice_startbuff_5" },
            choice_startbuff_6: { id: "choice_startbuff_6" },
          },
          detailConst: { playerLevelTable: { 2: { exp: 10 } } },
        },
        rogue_6: {
          init: [{ modeGrade: 15, predefinedId: null, modeId: "NORMAL" }],
          stages: {
            ro6_n_1_1: { id: "ro6_n_1_1" },
            ro6_n_2_1: { id: "ro6_n_2_1" },
            ro6_n_3_1: { id: "ro6_n_3_1" },
            ro6_n_4_1: { id: "ro6_n_4_1" },
            ro6_n_5_1: { id: "ro6_n_5_1" },
            ro6_n_6_1: { id: "ro6_n_6_1" },
            ro6_e_1_1: { id: "ro6_e_1_1" },
            ro6_e_2_1: { id: "ro6_e_2_1" },
            ro6_e_3_1: { id: "ro6_e_3_1" },
            ro6_e_4_1: { id: "ro6_e_4_1" },
            ro6_e_5_1: { id: "ro6_e_5_1" },
            ro6_e_6_1: { id: "ro6_e_6_1" },
          },
          items: {
            rogue_6_legacy_01: { id: "rogue_6_legacy_01", type: "LEGACY", name: "襁褓中的猫", usage: "下次探索时，初始可额外获得5源石锭" },
            rogue_6_legacy_02: { id: "rogue_6_legacy_02", type: "LEGACY", name: "襁褓中的狗", usage: "下次探索时，初始可额外获得1点希望" },
            rogue_6_gold: { id: "rogue_6_gold", type: "GOLD" },
          },
          relics: {},
          choices: {},
          bandRef: {},
          detailConst: { playerLevelTable: { 2: { exp: 10 } } },
        },
      },
      modules: { rogue_1: { moduleTypes: [] }, rogue_6: { moduleTypes: [] } },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: { rogue_1: { outbuff: {}, modebuff: {} }, rogue_6: { outbuff: {}, modebuff: {} } },
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import { RoguelikePendingEvent } from "@game/controller/rlv2/events";

function makePlayer(theme: string, opts: { lastZone?: number; legacy?: string[]; relic?: string[] } = {}) {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: {
        [theme]: {
          record: { last: 0, lastZone: opts.lastZone ?? 0, legacy: opts.legacy ?? [], stageCnt: {}, bandCnt: {}, bandGrade: {} },
          collect: { band: {} },
          buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme,
    mode: "NORMAL",
    modeGrade: theme === "rogue_6" ? 15 : 0,
    predefined: null,
    start: Date.now(),
  } as any;
  // 初始物品（结局变更/襁褓测试）
  if (opts.relic) {
    (player.rlv2 as any).inventory = {
      relic: opts.relic.reduce((acc: any, id, i) => ({ ...acc, [`r_${i}`]: { instId: `r_${i}`, id } }), {}),
    } as any;
  }
  return player;
}

describe("层数/层尾规则（官方机制对齐）", () => {
  it("maxZone 默认 5 层（无结局变更藏品时封顶 5）", () => {
    const player = makePlayer("rogue_1");
    expect((player.rlv2 as any).maxZone).toBe(5);
  });

  it("持有'让探索走向不同的结局'藏品 → 附加层（maxZone 到 6）", () => {
    const player = makePlayer("rogue_1", { relic: ["rogue_1_relic_m16"] });
    expect((player.rlv2 as any).maxZone).toBe(6);
  });

  it("rogue_1 层 1 尾必为商店、层 3/5 尾必为 boss", () => {
    const player = makePlayer("rogue_1");
    const map = (player.rlv2 as any)._map;
    map.generate([1]);
    let zone1 = map.zones[1].nodes;
    // zone1 尾节点（zone_end）为商店（rogue_1 shopType = 8）
    const z1End = Object.values(zone1).find((n: any) => n.zone_end);
    expect([8, 4096]).toContain(z1End.type);
    map.generate([3]);
    const z3End = Object.values(map.zones[3].nodes).find((n: any) => n.zone_end);
    expect(z3End.type).toBe(4); // BATTLE_BOSS
    map.generate([5]);
    const z5End = Object.values(map.zones[5].nodes).find((n: any) => n.zone_end);
    expect(z5End.type).toBe(4); // BATTLE_BOSS
  });
});

describe("支援选项门槛（上一把到 3 层）", () => {
  it("上一把到 3 层 → 本局 support=true（出现 GAME_INIT_SUPPORT）", async () => {
    const player = makePlayer("rogue_1", { lastZone: 3 });
    await (player.rlv2 as any).createGame({ theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefinedId: null });
    expect((player.rlv2 as any).current.game.outer.support).toBe(true);
  });

  it("上一把未到 3 层 → support=false（无 GAME_INIT_SUPPORT）", async () => {
    const player = makePlayer("rogue_1", { lastZone: 2 });
    await (player.rlv2 as any).createGame({ theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefinedId: null });
    expect((player.rlv2 as any).current.game.outer.support).toBe(false);
  });

  it("GAME_INIT_SUPPORT 为 3 选 1（3 个随机选项）", () => {
    const player = makePlayer("rogue_1");
    const ev = new RoguelikePendingEvent(
      player.rlv2 as any,
      (player.rlv2 as any)._trigger,
      "GAME_INIT_SUPPORT",
      0,
      { step: [2, 3], id: "" },
    );
    const scene = ev.content.initSupport!.scene;
    expect(Object.keys(scene.choices)).toHaveLength(3);
  });
});

describe("襁褓类藏品（下一局增益）", () => {
  it("上一把获得襁褓中的猫 → 本局开局 +5 源石锭", async () => {
    const player = makePlayer("rogue_6", { legacy: ["rogue_6_legacy_01"] });
    // createGame 会跑 status.create（重置 gold 为 init 值）→ legacy 应用在之后
    await (player.rlv2 as any).createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    const gold = (player.rlv2 as any)._status.property.gold;
    // init initialGold（mock 无 → 0）+ legacy +5
    expect(gold).toBeGreaterThanOrEqual(5);
  });

  it("上一把获得襁褓中的狗 → 本局开局 +1 希望", async () => {
    const player = makePlayer("rogue_6", { legacy: ["rogue_6_legacy_02"] });
    await (player.rlv2 as any).createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    expect((player.rlv2 as any)._status.property.population.max).toBeGreaterThanOrEqual(1);
  });
});

describe("结局变更藏品", () => {
  it("持有'让探索走向不同的结局'藏品 → toEnding 切换为 2 号结局", async () => {
    const player = makePlayer("rogue_1", { relic: ["rogue_1_relic_m16"] });
    await (player.rlv2 as any).createGame({ theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefinedId: null });
    expect((player.rlv2 as any)._status.toEnding).toBe("ro1_ending_2");
    expect((player.rlv2 as any)._status.chgEnding).toBe(true);
  });
});
