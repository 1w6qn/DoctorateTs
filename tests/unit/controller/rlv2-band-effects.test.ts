import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// rogue_6 分队专属逻辑：本源研修（本源系希望-2）、多边贸易（零件箱容量+2/+4）、
// 开拓者（进区获加工品）、zone_into_reward 无区域限定不崩
const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        stages: { ro6_n_1_1: { id: "ro6_n_1_1" }, ro6_n_3_1: { id: "ro6_n_3_1" } },
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initialHp: 8, initialGold: 8, initialPopulation: 6, initialSquadCapacity: 6, initialBandRelic: [], initialRecruitGroup: [] }],
        items: {
          rogue_6_gold: { id: "rogue_6_gold", type: "GOLD", rarity: "NONE" },
          rogue_6_max_weight: { id: "rogue_6_max_weight", type: "MAX_WEIGHT", rarity: "NONE" },
          rogue_6_scrap_G_01: { id: "rogue_6_scrap_G_01", type: "SCRAP", rarity: "NORMAL" },
          rogue_6_scrap_G_02: { id: "rogue_6_scrap_G_02", type: "SCRAP", rarity: "NORMAL" },
          rogue_6_scrap_G_08: { id: "rogue_6_scrap_G_08", type: "SCRAP", rarity: "NORMAL" },
          rogue_6_scrap_P_01: { id: "rogue_6_scrap_P_01", type: "SCRAP", rarity: "RARE" },
          rogue_6_relic_cargo_4: { id: "rogue_6_relic_cargo_4", type: "RELIC", rarity: "RARE" },
          rogue_6_relic_cargo_7: { id: "rogue_6_relic_cargo_7", type: "RELIC", rarity: "NORMAL" },
          rogue_6_relic_cargo_8: { id: "rogue_6_relic_cargo_8", type: "RELIC", rarity: "NORMAL" },
          rogue_6_relic_legacy_50: { id: "rogue_6_relic_legacy_50", type: "RELIC", rarity: "RARE" },
          rogue_6_relic_fight_1: { id: "rogue_6_relic_fight_1", type: "RELIC", rarity: "SUPER_RARE" },
          rogue_6_start_6: { id: "rogue_6_start_6", type: "RELIC", rarity: "NORMAL" },
        },
        relics: {
          rogue_6_start_6: {
            id: "rogue_6_start_6",
            buffs: [
              { key: "zone_into_reward", blackboard: [{ key: "id", valueStr: "pool_treasure" }, { key: "count", value: 3 }, { key: "zone", valueStr: "zone_3" }] },
            ],
          },
          rogue_6_relic_cargo_4: { id: "rogue_6_relic_cargo_4", buffs: [] },
          rogue_6_relic_legacy_50: { id: "rogue_6_relic_legacy_50", buffs: [] },
          rogue_6_relic_fight_1: { id: "rogue_6_relic_fight_1", buffs: [] },
          rogue_6_band_14: { id: "rogue_6_band_14", buffs: [{ key: "recruit_cost_sub_profession", blackboard: [{ key: "rarity", valueStr: "TIER_4,TIER_5,TIER_6" }, { key: "sub_profession", valueStr: "primcaster,primprotector,primguard,ritualist" }, { key: "delta", value: -2 }] }] },
          rogue_6_band_19: { id: "rogue_6_band_19", buffs: [{ key: "immediate_reward", blackboard: [{ key: "id", valueStr: "rogue_6_max_weight" }, { key: "count", value: 2 }] }, { key: "shop_recycle_reward", blackboard: [{ key: "id", valueStr: "rogue_6_gold" }, { key: "count", value: 8 }, { key: "sell_count", value: 3 }, { key: "limit", value: 1 }] }] },
          rogue_6_band_20: { id: "rogue_6_band_20", buffs: [{ key: "shop_recycle_reward", blackboard: [{ key: "id", valueStr: "rogue_6_gold" }, { key: "count", value: 8 }, { key: "sell_count", value: 3 }, { key: "limit", value: 1 }] }] },
          rogue_6_band_17: { id: "rogue_6_band_17", buffs: [{ key: "zone_into_reward", blackboard: [{ key: "id", valueStr: "pool_scrap_6" }, { key: "count", value: 1 }] }] },
        },
        recruitTickets: {
          rogue_6_recruit_ticket_caster: { id: "rogue_6_recruit_ticket_caster", professionList: ["CASTER"], rarityList: ["TIER_5"] },
        },
      },
    },
    modules: {
      rogue_6: {
        moduleTypes: ["GRID_ZONE", "SCRAP"],
        scrap: { scrapItemToType: { rogue_6_scrap_G_01: "GOODS", rogue_6_scrap_G_02: "GOODS", rogue_6_scrap_G_08: "GOODS", rogue_6_scrap_P_01: "PASSIVE" } },
      },
    },
    consts: {},
  },
  CharacterTable: {
    char_499_kaitou: { charId: "char_499_kaitou", name: "本源术师A", rarity: "TIER_5", profession: "CASTER", subProfessionId: "primcaster" },
    char_002_amiya: { charId: "char_002_amiya", name: "普通术师", rarity: "TIER_5", profession: "CASTER", subProfessionId: "corecaster" },
  },
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {},
      pinned: {},
    } as any,
    troop: {
      chars: {
        "1": { charId: "char_499_kaitou", instId: 1, rarity: "TIER_5" },
        "2": { charId: "char_002_amiya", instId: 2, rarity: "TIER_5" },
      },
    },
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme: "rogue_6",
    mode: "NORMAL",
    modeGrade: 0,
    outer: { support: false },
  } as any;
  return player;
}

async function withRandom(v: number, fn: () => Promise<void> | void) {
  const spy = vi.spyOn(Math, "random").mockReturnValue(v);
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
}

function holdRelic(player: any, id: string) {
  (player.rlv2 as any).inventory._relic.relics = {
    ...(player.rlv2 as any).inventory._relic.relics,
    [`r_${Object.keys((player.rlv2 as any).inventory._relic.relics).length}`]: {
      index: `r_${Object.keys((player.rlv2 as any).inventory._relic.relics).length}`,
      id,
      count: 1,
      ts: 0,
    },
  };
}

describe("rogue_6 分队专属逻辑", () => {
  it("本源研修（recruit_cost_sub_profession）：本源系干员希望-2，非本源系不变", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    // 玩家主队伍含本源术师（kaitou）与普通术师（amiya）——已由 mockPlayerData 初始化
    // 应用本源研修分队 buff（relic.gain band_14 会走 applyBuffs → _buffs）
    await (player.rlv2 as any)._trigger.emit("rlv2:relic:gain", [
      { id: "rogue_6_band_14", count: 1 },
    ]);
    // 激活术师招募券 → 检查候选希望消耗
    await (player.rlv2 as any)._trigger.emit("rlv2:recruit:gain", [
      "rogue_6_recruit_ticket_caster",
      "initial",
      0,
    ]);
    const tickets = (player.rlv2 as any).inventory.recruit;
    const ticket = Object.values(tickets)[0];
    await (player.rlv2 as any)._trigger.emit("rlv2:recruit:active", [
      ticket.index,
    ]);
    const list = ticket.list;
    const kaitou = list.find((c: any) => c.charId === "char_499_kaitou");
    const amiya = list.find((c: any) => c.charId === "char_002_amiya");
    expect(kaitou).toBeTruthy();
    expect(amiya).toBeTruthy();
    // 本源系（primcaster）：5 星基础 2 希望 - 2 = 0；普通术师（corecaster）：仍 2
    expect(kaitou.population).toBe(0);
    expect(amiya.population).toBe(2);
  });

  it("多边贸易（MAX_WEIGHT）：零件箱容量 +2", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const scrap = (player.rlv2 as any)._module.scrap;
    const before = scrap.limit;
    await (player.rlv2 as any)._trigger.emit("rlv2:get:items", [
      [{ id: "rogue_6_max_weight", count: 2, sub: 0 }],
    ]);
    expect(scrap.limit).toBe(before + 2);
  });

  it("开拓者（zone_into_reward pool_scrap_6）：进入新区域获得 1 件加工品（零件箱+1）", async () => {
    await withRandom(0, async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      await (player.rlv2 as any)._pool.create(); // 建加工品池（真机 createGame 会触发）
      // 应用开拓者分队 buff（zone_into_reward 无区域限定）
      await (player.rlv2 as any)._trigger.emit("rlv2:relic:gain", [
        { id: "rogue_6_band_17", count: 1 },
      ]);
      const scrap = (player.rlv2 as any)._module.scrap;
      const before = Object.keys(scrap.inventory).length;
      // 生成区域 → zone_into_reward 触发（blackboard 无区域限定 → 不崩且发放）
      await (player.rlv2 as any)._trigger.emit("rlv2:zone:new", [1]);
      await new Promise((r) => setTimeout(r, 0)); // 等 get:items 微任务链
      expect(Object.keys(scrap.inventory).length).toBe(before + 1);
    });
  });

  it("zone_into_reward 无 blackboard[2]（区域限定）时 generate 不抛错", async () => {
    await withRandom(0, async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      await (player.rlv2 as any)._trigger.emit("rlv2:relic:gain", [
        { id: "rogue_6_band_17", count: 1 },
      ]);
      const gz = (player.rlv2 as any)._module.gridZone;
      await expect(
        (async () => {
          gz.generate([2]);
        })(),
      ).resolves.toBeUndefined();
    });
  });

  it("pool_scrap_3/6 池已建（GOODS 型加工品）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._pool.create();
    expect((player.rlv2 as any)._pool._pools["pool_scrap_6"].length).toBe(3);
    expect((player.rlv2 as any)._pool._pools["pool_scrap_3"].length).toBe(3);
  });

  it("官方池（路标档案馆 pools/rogue_6）：珍宝池/小礼物/零件池 7-9/额外掉落/Boss", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._pool.create();
    const pools = (player.rlv2 as any)._pool._pools;
    // pool_treasure：PASSIVE 白模零件 + RARE/SUPER_RARE 珍宝藏品
    expect(pools["pool_treasure"]).toContain("rogue_6_scrap_P_01");
    expect(pools["pool_treasure"]).toContain("rogue_6_relic_fight_1");
    expect(pools["pool_treasure"]).not.toContain("rogue_6_relic_cargo_7"); // NORMAL 不入珍宝
    // pool_small_gift：古地树实
    expect(pools["pool_small_gift"]).toEqual(["rogue_6_relic_legacy_50"]);
    // pool_scrap_7/8/9：迷藏/囊中骨/林中小手
    expect(pools["pool_scrap_7"]).toEqual(["rogue_6_relic_cargo_4"]);
    expect(pools["pool_scrap_8"]).toEqual(["rogue_6_relic_cargo_7"]);
    expect(pools["pool_scrap_9"]).toEqual(["rogue_6_relic_cargo_8"]);
    // drop_extra_pool / pool_boss：珍宝藏品级
    expect(pools["drop_extra_pool"]).toContain("rogue_6_relic_fight_1");
    expect(pools["pool_boss"]).toContain("rogue_6_relic_fight_1");
  });

  it("多边贸易（shop_recycle_reward）：同一行商节点卖出 3 件零件 → +8 源石锭（限 1 次）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._trigger.emit("rlv2:relic:gain", [
      { id: "rogue_6_band_19", count: 1 },
    ]);
    // 当前节点设为行商（诡意行商 4096）
    const map = (player.rlv2 as any)._map;
    map.zones["1002"] = {
      id: "zone_3",
      index: 1002,
      nodes: {
        "201": { index: "201", pos: { x: 2, y: 1 }, next: [], type: 4096 },
      },
      variation: [],
    };
    (player.rlv2 as any)._status.cursor.zone = 3;
    (player.rlv2 as any)._status.cursor.position = { x: 2, y: 1 };
    // 零件箱放 4 件零件（非载具）
    const scrap = (player.rlv2 as any)._module.scrap;
    for (let i = 3; i <= 6; i++) {
      scrap.inventory[`s_${i}`] = {
        instId: `s_${i}`,
        id: "rogue_6_scrap_G_01",
        value: 1,
        useCnt: 0,
        ts: 0,
      };
    }
    const goldBefore = (player.rlv2 as any)._status.property.gold;
    // 卖出 3 件 → 第 3 件触发 +8
    await (player.rlv2 as any).loseScrap({ instId: "s_3" });
    await (player.rlv2 as any).loseScrap({ instId: "s_4" });
    expect((player.rlv2 as any)._status.property.gold).toBe(goldBefore);
    await (player.rlv2 as any).loseScrap({ instId: "s_5" });
    expect((player.rlv2 as any)._status.property.gold).toBe(goldBefore + 8);
    // 第 4 件不再触发（限 1 次）
    await (player.rlv2 as any).loseScrap({ instId: "s_6" });
    expect((player.rlv2 as any)._status.property.gold).toBe(goldBefore + 8);
  });

  it("多边贸易升级（band_20）：进入行商节点获得 1 个<枯苔藓球>", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    holdRelic(player, "rogue_6_band_20");
    // 放一个行商节点并移动进入
    const gz = (player.rlv2 as any)._module.gridZone;
    gz.generate([2]);
    (player.rlv2 as any)._status.cursor.zone = 2;
    const gz3 = gz.zones["zone_2"];
    const someId = Object.keys(gz3.nodes)[0];
    gz3.nodes[someId].content = { shop: { goods: [] }, kind: 4096 };
    const scrap = (player.rlv2 as any)._module.scrap;
    const before = Object.keys(scrap.inventory).length;
    await (player.rlv2 as any).gridZoneMoveTo({ route: [someId] });
    await new Promise((r) => setTimeout(r, 0));
    const ids = Object.values(scrap.inventory).map((i: any) => i.id);
    expect(ids).toContain("rogue_6_scrap_G_08");
    expect(Object.keys(scrap.inventory).length).toBe(before + 1);
  });

  it("startbuff_12（进入血色空脉 zone_3 获得 3 个随机收藏品）：zone_into_reward 按 valueStr 区域匹配发 pool_treasure", async () => {
    await withRandom(0, async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      await (player.rlv2 as any)._pool.create();
      // 获得襁褓巨龙（start_6，zone_into_reward pool_treasure ×3 zone_3）
      await (player.rlv2 as any)._trigger.emit("rlv2:relic:gain", [
        { id: "rogue_6_start_6", count: 1 },
      ]);
      const gz = (player.rlv2 as any)._module.gridZone;
      const scrap = (player.rlv2 as any)._module.scrap;
      const scrapBefore = Object.keys(scrap.inventory).length;
      // 进入 zone_3（匹配 valueStr "zone_3"，zone:new → map.generate 发 pool_treasure ×3）
      const relicBefore = Object.keys((player.rlv2 as any).inventory.relic).length;
      await (player.rlv2 as any)._trigger.emit("rlv2:zone:new", [3]);
      await new Promise((r) => setTimeout(r, 0));
      // pool_treasure = 白模零件(P_01) + 珍宝藏品(cargo_4/legacy_50/fight_1) → 抽 3 件入库（scrap 或 relic）
      const scrapGain = Object.keys(scrap.inventory).length - scrapBefore;
      const relicGain = Object.keys((player.rlv2 as any).inventory.relic).length - relicBefore;
      expect(scrapGain + relicGain).toBe(3);
      // 进入 zone_2（不匹配 zone_3）→ 无奖励
      const s2 = Object.keys(scrap.inventory).length + Object.keys((player.rlv2 as any).inventory.relic).length;
      await (player.rlv2 as any)._trigger.emit("rlv2:zone:new", [2]);
      await new Promise((r) => setTimeout(r, 0));
      const s3 = Object.keys(scrap.inventory).length + Object.keys((player.rlv2 as any).inventory.relic).length;
      expect(s3).toBe(s2);
    });
  });
});
