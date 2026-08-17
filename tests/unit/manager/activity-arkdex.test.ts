/**
 * 奇象巡展 ARKDEX 寻迹玩法单测：属性克制/六维换算、扫描结算（成功/失败）、
 * 道具购买（扣券/库存/每日重置）与使用、交换、保护区解锁。2026-08-17。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventBus } from "@game/model/events";
import { mockPlayerData } from "../../helpers";
import {
  ARKDEX_PROPS,
  arkdexDamageScale,
  arkdexSixStatsToCombat,
  arkhubScanSucceed,
  arkhubScanFail,
  arkhubBuyProp,
  arkhubUseProp,
  arkhubSetTrade,
  arkhubDoTrade,
  arkhubUnlockArea,
  ARKDEX_BAG_MAX,
  arkdexCreature,
  arkdexCreatures,
  arkdexAdvantageName,
  arkdexDamageScaleById,
  arkdexModeRules,
  arkdexEnemySquad,
  arkdexConst,
} from "@game/manager/activity/arkdex";

function hubPlayer(overrides: Record<string, any> = {}) {
  const bus = new EventBus();
  const player = mockPlayerData({
    status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
    activity: {
      ARK_HUB: {
        act1arkhub: {
          coin: 500,
          dex: {},
          scanBag: [],
          scanSeq: 0,
          props: {},
          trade: { wantSpecies: null, offerNumIds: [] },
          unlockedAreas: {},
          ...overrides,
        },
      },
    },
    tshop: { shop_act1arkhub: { coin: 500 } },
  });
  (player as any)._trigger = bus;
  return player;
}

function hubOf(player: any): any {
  return player._playerdata.activity.ARK_HUB.act1arkhub;
}

describe("属性克制与六维换算", () => {
  it("克制环：奇术→本能→百变→奇术，克制 130%/被克 70%/同级 100%", () => {
    expect(arkdexDamageScale("奇术", "本能")).toBe(1.3);
    expect(arkdexDamageScale("本能", "百变")).toBe(1.3);
    expect(arkdexDamageScale("百变", "奇术")).toBe(1.3);
    expect(arkdexDamageScale("本能", "奇术")).toBe(0.7);
    expect(arkdexDamageScale("百变", "本能")).toBe(0.7);
    expect(arkdexDamageScale("奇术", "百变")).toBe(0.7);
    expect(arkdexDamageScale("奇术", "奇术")).toBe(1.0);
  });

  it("六维换算：进攻×20/守备×2/耐久×100/法抗×0.5/攻速=间隔倒数×10", () => {
    const c = arkdexSixStatsToCombat({ atk: 10, def: 5, hp: 8, mag: 20, atkSpeed: 5, moveSpeed: 1.1 });
    expect(c.attack).toBe(200);
    expect(c.defense).toBe(10);
    expect(c.maxHp).toBe(800);
    expect(c.magicResist).toBe(10);
    expect(c.attackInterval).toBeCloseTo(2); // 10/5
    expect(c.moveSpeed).toBe(1.1);
  });
});

describe("扫描结算", () => {
  it("扫描成功：发 15 券 + 币同步 + 数据库收录 + 扫描仪入袋 + 计数事件", async () => {
    const player = hubPlayer();
    const seen: string[] = [];
    const bus = player._trigger as EventBus;
    bus.on("ArkhubCreatureCollection", (args: any[]) => {
      seen.push(`m:${args[0].collectionKey}:${args[0].count}`);
    });
    bus.on("ActivityArkhubAlterCollect", (args: any[]) => {
      seen.push(`alter:${args[0].alterCount}`);
    });

    const ok = await arkhubScanSucceed(player as any, {
      creatureNumIds: [5001, 5002, 5001, 5003],
      alterOf: { 5003: 5001 },
      active: { 5002: true },
    });
    expect(ok).toBe(true);

    const hub = hubOf(player);
    expect(hub.coin).toBe(515);
    expect((player._playerdata as any).tshop.shop_act1arkhub.coin).toBe(515);
    // dex：3 种（5001/5002/5003），5003 为亚种，5002 活动频繁
    expect(Object.keys(hub.dex)).toHaveLength(3);
    expect(hub.dex["5003"].isAlter).toBe(true);
    expect(hub.dex["5003"].alterOf).toBe(5001);
    expect(hub.dex["5002"].active).toBe(true);
    // 扫描仪：4 个体（重复种类也入袋）
    expect(hub.scanBag).toHaveLength(4);
    expect(hub.scanSeq).toBe(4);
    expect(hub.scanBag[0].fav).toBe(false);
    // 计数：种类 3、活动频繁 1、亚种 1
    expect(hub.creatureCollected).toBe(3);
    expect(hub.activeCreatureCollected).toBe(1);
    expect(hub.alterCollected).toBe(1);
    // 事件：collection1=3、collection2=1（活动频繁）、镀层 alter=1
    expect(seen).toContain("m:arkhubMissionCollection1:3");
    expect(seen).toContain("m:arkhubMissionCollection2:1");
    expect(seen).toContain("alter:1");
  });

  it("扫描失败：无任何奖励与收录", async () => {
    const player = hubPlayer();
    const ok = await arkhubScanSucceed(player as any, { creatureNumIds: [] });
    expect(ok).toBe(false);
    const hub = hubOf(player);
    expect(hub.coin).toBe(500);
    expect(Object.keys(hub.dex)).toHaveLength(0);
    expect(hub.scanBag).toHaveLength(0);
    await arkhubScanFail(player as any); // 占位函数不抛
  });

  it("扫描仪内存上限 400：满员后不再入袋", async () => {
    const player = hubPlayer({ scanBag: Array.from({ length: ARKDEX_BAG_MAX }, (_, i) => ({ id: i + 1, numId: 5000 })), scanSeq: ARKDEX_BAG_MAX });
    await arkhubScanSucceed(player as any, { creatureNumIds: [5001, 5002] });
    const hub = hubOf(player);
    expect(hub.scanBag).toHaveLength(ARKDEX_BAG_MAX);
    expect(hub.scanSeq).toBe(ARKDEX_BAG_MAX);
  });
});

describe("巡展道具", () => {
  it("购买：扣券 + 道具箱 +生效次数；券不足失败", async () => {
    const player = hubPlayer({ coin: 100 });
    const ok = await arkhubBuyProp(player as any, 5004, 2); // 标准诱引剂 40×2
    expect(ok).toBe(true);
    const hub = hubOf(player);
    expect(hub.coin).toBe(20);
    expect(hub.props["5004"]).toEqual({ count: 2, uses: 2 });

    // 券不足（只剩 20，专业 60）
    const ok2 = await arkhubBuyProp(player as any, 5005);
    expect(ok2).toBe(false);
    expect(hubOf(player).coin).toBe(20);
  });

  it("购买：每日库存限购（稀有诱引剂 2），跨日重置", async () => {
    const player = hubPlayer({ coin: 10000 });
    expect((await arkhubBuyProp(player as any, 5006, 2))).toBe(true); // 稀有 250×2 库存 2
    expect((await arkhubBuyProp(player as any, 5006))).toBe(false); // 库存售罄
    // 模拟跨日：直接改 propSoldToday 日期
    await (player as any).update(async (draft: any) => {
      draft.activity.ARK_HUB.act1arkhub.propSoldToday = { date: "Sun Aug 16 2026", sold: {} };
    });
    expect((await arkhubBuyProp(player as any, 5006))).toBe(true);
  });

  it("使用：消耗 1 次生效次数；次数耗尽不可用", async () => {
    const player = hubPlayer({ props: { "5004": { count: 1, uses: 1 } } });
    expect(await arkhubUseProp(player as any, 5004)).toBe(true);
    expect(hubOf(player).props["5004"].uses).toBe(0);
    expect(await arkhubUseProp(player as any, 5004)).toBe(false);
    expect(await arkhubUseProp(player as any, 9999)).toBe(false); // 未知道具
  });
});

describe("数据集换与保护区", () => {
  it("设置交换需求：同时 1 条、可清除", async () => {
    const player = hubPlayer();
    await arkhubSetTrade(player as any, 5001, [5002, 5003]);
    expect(hubOf(player).trade).toEqual({ wantSpecies: 5001, offerNumIds: [5002, 5003] });
    await arkhubSetTrade(player as any, null);
    expect(hubOf(player).trade).toEqual({ wantSpecies: null, offerNumIds: [] });
  });

  it("发起交换：发 ArkhubCreatureExchange 事件（任务 16）", async () => {
    const player = hubPlayer();
    const seen: string[] = [];
    (player._trigger as EventBus).on("ArkhubCreatureExchange", (args: any[]) => seen.push(args[0].activityId));
    await arkhubDoTrade(player as any);
    expect(seen).toEqual(["act1arkhub"]);
  });

  it("保护区解锁：unlockedAreas 标记", async () => {
    const player = hubPlayer();
    await arkhubUnlockArea(player as any, 1);
    expect(hubOf(player).unlockedAreas["1"]).toBe(1);
  });

  it("道具表完整性：16 种道具含价格与类型（arkdexModule.itemEffectData）", () => {
    expect(Object.keys(ARKDEX_PROPS)).toHaveLength(16);
    expect(ARKDEX_PROPS[5004]).toMatchObject({ price: 40, type: "lure" });
    expect(ARKDEX_PROPS[5006]).toMatchObject({ price: 250, type: "lure" });
    expect(ARKDEX_PROPS[5015]).toMatchObject({ price: 60, type: "pheromone" });
    expect(ARKDEX_PROPS[5016]).toMatchObject({ price: 60, type: "pheromone" });
    expect(ARKDEX_PROPS[5011]).toMatchObject({ price: 60, type: "lure" });
    // 5006 稀有诱引剂每日库存 2（官服价格表 avail），其余 5
    expect(ARKDEX_PROPS[5006].dailyStock).toBe(2);
  });
});

describe("arkdexModule 数据访问（data/arkhub/arkdex.json 实锤数据）", () => {
  it("生物数据：37 种，含名称/珍奇度/属性/六维/亚种关联", () => {
    const creatures = arkdexCreatures();
    expect(creatures.length).toBe(37);
    const c1 = arkdexCreature(19001)!;
    expect(c1.name).toBe("星术绒绒");
    expect(c1.rarity).toBe(3);
    expect(c1.advantageType).toBe("arkdex_advantage_A");
    expect(c1.alterNumId).toBe(19002); // 19002 是 19001 的亚种
    expect(c1.hp).toBeGreaterThan(0);
    expect(c1.atk).toBeGreaterThan(0);
    expect(arkdexCreature(99999)).toBeUndefined();
  });

  it("属性克制：id 映射 + damageScaleMap（克 1.3 / 被克 0.7）", () => {
    expect(arkdexAdvantageName(19001)).toBe("奇术");
    expect(arkdexDamageScaleById("arkdex_advantage_A", "arkdex_advantage_B")).toBe(1.3);
    expect(arkdexDamageScaleById("arkdex_advantage_B", "arkdex_advantage_C")).toBe(1.3);
    expect(arkdexDamageScaleById("arkdex_advantage_C", "arkdex_advantage_A")).toBe(1.3);
    expect(arkdexDamageScaleById("arkdex_advantage_B", "arkdex_advantage_A")).toBe(0.7);
    expect(arkdexDamageScaleById("arkdex_advantage_A", "arkdex_advantage_A")).toBe(1.0);
  });

  it("对决模式规则：快速 2人1轮 / 常规 2人3轮 / 多人 4人1轮", () => {
    const solo = arkdexModeRules("arkdex_singleRound_Solo");
    expect(solo.numPlayers).toBe(2);
    expect(solo.rounds).toBe(1);
    expect(solo.npcCount).toBe(1);
    const bo3 = arkdexModeRules("arkdex_BO3_Solo");
    expect(bo3.rounds).toBe(3);
    const m4 = arkdexModeRules("arkdex_4Player_Solo");
    expect(m4.numPlayers).toBe(4);
    expect(m4.npcCount).toBe(3);
    const match = arkdexModeRules("arkdex_singleRound_Match");
    expect(match.isMatching).toBe(true);
  });

  it("NPC 对决策略敌队：strategy_group_intro = 19005×2 + 19003（苍苔策略组）", () => {
    const squad = arkdexEnemySquad("strategy_group_intro");
    expect(squad.length).toBeGreaterThanOrEqual(3);
    expect(squad[0].creatureNumId).toBe(19005);
    expect(squad.every((e) => e.traitMask > 0)).toBe(true);
    expect(arkdexEnemySquad("no_such_group")).toEqual([]);
  });

  it("ARKDEX 常量：bag 上限 400 / 队伍 3 只 / 稀有度上限 7", () => {
    expect(arkdexConst("arkdexCreatureBagMaxNum")).toBe(400);
    expect(arkdexConst("teamSize")).toBe(3);
    expect(arkdexConst("maxTeamRarityCount")).toBe(7);
  });
});
