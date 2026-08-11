import { describe, it, expect, vi, beforeEach } from "vitest";
import { enablePatches } from "immer";

enablePatches();

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_3: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {} }],
          milestones: [
            { id: "bp_level_1", level: 1, tokenNum: 200, itemID: "4001", itemType: "GOLD", itemCount: 100 },
            { id: "bp_level_2", level: 2, tokenNum: 400, itemID: "30155", itemType: "MATERIAL", itemCount: 2 },
          ],
          taskData: {
            rogue_3_task_001: { taskId: "rogue_3_task_001", rewardSceneId: "scene_ro3_taskreward1_enter" },
          },
          choices: {
            choice_ro3_taskreward1_1: { id: "choice_ro3_taskreward1_1", nextSceneId: null },
            choice_ro3_taskreward1_2: { id: "choice_ro3_taskreward1_2", nextSceneId: null },
          },
          items: {
            rogue_3_gold: { id: "rogue_3_gold", type: "GOLD", rarity: "NONE" },
            rogue_3_relic_a01: { id: "rogue_3_relic_a01", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_3_relic_a02: { id: "rogue_3_relic_a02", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_3_relic_b01: { id: "rogue_3_relic_b01", type: "RELIC", rarity: "RARE", canSacrifice: true, value: 12 },
          },
          recruitTickets: {},
        },
        rogue_2: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {} }],
          items: { rogue_2_gold: { id: "rogue_2_gold", type: "GOLD", rarity: "NONE" } },
        },
        rogue_1: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {}, initialBandRelic: ["rogue_1_band_1", "rogue_1_band_2"] }],
          items: {
            rogue_1_gold: { id: "rogue_1_gold", type: "GOLD", rarity: "NONE" },
            rogue_1_hp: { id: "rogue_1_hp", type: "HP", rarity: "NONE" },
            rogue_1_squad_capacity: { id: "rogue_1_squad_capacity", type: "SQUAD_CAPACITY", rarity: "NONE" },
          },
          relics: {
            rogue_1_band_1: { id: "rogue_1_band_1", buffs: [{ key: "level_life_point_add", blackboard: [{ key: "value", value: 4 }] }] },
            rogue_1_band_2: {
              id: "rogue_1_band_2",
              buffs: [
                { key: "immediate_reward", blackboard: [{ key: "id", valueStr: "rogue_1_squad_capacity" }, { key: "count", value: 2 }] },
                { key: "level_char_limit_add", blackboard: [{ key: "value", value: 2 }] },
              ],
            },
          },
          bandRef: {
            rogue_1_band_1: { itemId: "rogue_1_band_1", bandLevel: 0, normalBandId: "rogue_1_band_1" },
            rogue_1_band_2: { itemId: "rogue_1_band_2", bandLevel: 0, normalBandId: "rogue_1_band_2" },
          },
        },
      },
      modules: {
        rogue_3: {},
        rogue_1: {},
        rogue_2: {
          dice: {
            dice: { rogue_2_dice_1: { diceFaceCount: 6 } },
            diceEvents: {
              rogue_2_diceEve_1: { showType: "VIRTUE" },
              rogue_2_diceEve_2: { showType: "KEY" },
            },
          },
        },
      },
      customizeData: {},
    },
    CharacterTable: {},
    GameDataConst: { maxLevel: [[], [], [], [], [], []] },
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer(outer: any = {}) {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_3: outer } as any,
      current: {},
      pinned: {},
    } as any,
    inventory: {} as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

describe("rlv2 完整机制（2026-08-10 补全）", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer({
      bank: { show: true, current: 10, record: 10, reward: {}, totalPut: 10 },
      bp: { point: 500, reward: {} },
      buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
    });
    // 模拟进行中的游戏
    (player.rlv2 as any).current.game = { theme: "rogue_3", mode: "NORMAL", modeGrade: 0 } as any;
  });

  describe("battlePassGetReward（战令领奖）", () => {
    it("应发放里程碑物品并标记已领", async () => {
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      const ret = await (player.rlv2 as any).battlePassGetReward("rogue_3", ["bp_level_1", "bp_level_2"]);
      expect(ret.items).toEqual([
        { type: "GOLD", id: "4001", count: 100 },
        { type: "MATERIAL", id: "30155", count: 2 },
      ]);
      expect(player._playerdata.rlv2.outer.rogue_3.bp.reward.bp_level_1).toBe(1);
      expect(player._playerdata.rlv2.outer.rogue_3.bp.reward.bp_level_2).toBe(1);
      const itemsGet = emitSpy.mock.calls.filter((c: any) => c[0] === "items:get");
      expect(itemsGet).toHaveLength(1);
    });

    it("重复领取应跳过（已领标记）", async () => {
      (player.rlv2 as any).outer.rogue_3.bp.reward.bp_level_1 = 1;
      const ret = await (player.rlv2 as any).battlePassGetReward("rogue_3", ["bp_level_1"]);
      expect(ret.items).toEqual([]);
    });
  });

  describe("bankPut / bankWithdraw（银行）", () => {
    it("bankPut 应增加 current/totalPut 并刷新 record", async () => {
      await (player.rlv2 as any).bankPut();
      const bank = player._playerdata.rlv2.outer.rogue_3.bank;
      expect(bank.current).toBe(11);
      expect(bank.totalPut).toBe(11);
      expect(bank.record).toBe(11);
      expect((player.rlv2 as any)._status.status.bankPut).toBe(1);
    });

    it("bankWithdraw 应减少 current 并增加金币", async () => {
      const goldBefore = (player.rlv2 as any)._status.property.gold;
      await (player.rlv2 as any).bankWithdraw({ count: 4 });
      expect(player._playerdata.rlv2.outer.rogue_3.bank.current).toBe(6);
      expect((player.rlv2 as any)._status.property.gold).toBe(goldBefore + 4);
    });

    it("bankWithdraw 超额应钳制到 bank.current", async () => {
      await (player.rlv2 as any).bankWithdraw({ count: 999 });
      expect(player._playerdata.rlv2.outer.rogue_3.bank.current).toBe(0);
    });
  });

  describe("nodeMission（节点任务）", () => {
    it("confirm 应置 state=2 并生成任务奖励 SCENE", async () => {
      (player.rlv2 as any)._status.nodeMission = {
        id: "rogue_3_task_001",
        state: 1,
        tip: true,
        progress: [2, 4],
      };
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      await (player.rlv2 as any).nodeMissionConfirm();
      expect((player.rlv2 as any)._status.nodeMission.state).toBe(2);
      const sceneCalls = emitSpy.mock.calls.filter(
        (c: any) => c[0] === "rlv2:event:create" && c[1][0] === "SCENE",
      );
      expect(sceneCalls).toHaveLength(1);
      const scene = sceneCalls[0][1][1] as any;
      expect(scene.scene.id).toBe("scene_ro3_taskreward1_enter");
      expect(scene.scene.choices).toHaveProperty("choice_ro3_taskreward1_1");
      expect((player.rlv2 as any)._status.state).toBe("PENDING");
    });

    it("giveUp 应置 state=3 并回到 WAIT_MOVE", async () => {
      (player.rlv2 as any)._status.nodeMission = { id: "t1", state: 1, tip: true, progress: [] };
      await (player.rlv2 as any).nodeMissionGiveUp();
      expect((player.rlv2 as any)._status.nodeMission.state).toBe(3);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });

    it("closeTip 应置 tip=false", async () => {
      (player.rlv2 as any)._status.nodeMission = { id: "t1", state: 1, tip: true, progress: [] };
      await (player.rlv2 as any).nodeMissionCloseTip();
      expect((player.rlv2 as any)._status.nodeMission.tip).toBe(false);
    });
  });

  describe("readEndingChange / confirmZoneReward / confirmTraderReturn", () => {
    it("readEndingChange 应清 chgEnding 并回到 WAIT_MOVE", async () => {
      (player.rlv2 as any)._status.chgEnding = true;
      await (player.rlv2 as any).readEndingChange();
      expect((player.rlv2 as any)._status.chgEnding).toBe(false);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });

    it("confirmZoneReward 应发放 zoneReward 物品并清空", async () => {
      (player.rlv2 as any)._status.zoneReward = {
        z0: { id: "rogue_3_gold", count: 5, instId: "" },
      };
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      await (player.rlv2 as any).confirmZoneReward();
      const getItems = emitSpy.mock.calls.filter((c: any) => c[0] === "rlv2:get:items");
      expect(getItems).toHaveLength(1);
      expect(getItems[0][1][0][0]).toEqual({ id: "rogue_3_gold", count: 5 });
      expect((player.rlv2 as any)._status.zoneReward).toBeUndefined();
    });

    it("confirmTraderReturn 应发放 traderReturn 物品并清空", async () => {
      (player.rlv2 as any)._status.traderReturn = {
        t0: { id: "rogue_3_gold", count: 3, instId: "" },
      };
      await (player.rlv2 as any).confirmTraderReturn();
      expect((player.rlv2 as any)._status.traderReturn).toBeUndefined();
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });
  });

  describe("expeditionChoice / assist / shopBattle", () => {
    it("expeditionChoice 应写入 troop.expedition", async () => {
      (player.rlv2 as any).troop.expedition = [];
      const ret = await (player.rlv2 as any).expeditionChoice({ choice: "7,8", leave: 0 });
      expect(ret.result).toBe(1);
      expect((player.rlv2 as any).troop.expedition).toEqual(["7", "8"]);
    });

    it("getTicketAssistList 应关闭助战标记", async () => {
      player.rlv2.inventory!.recruit["t_0"] = {
        index: "t_0",
        id: "rogue_3_recruit_ticket_pioneer",
        state: 1,
        list: [],
        result: null,
        ts: 0,
        from: "initial",
        mustExtra: 0,
        needAssist: true,
      } as any;
      await (player.rlv2 as any).getTicketAssistList({ ticketIndex: "t_0", profession: "PIONEER" });
      expect(player.rlv2.inventory!.recruit["t_0"].needAssist).toBe(false);
    });

    it("shopBattleStart 应生成 BATTLE 事件", async () => {
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      await (player.rlv2 as any).shopBattleStart();
      const battleCalls = emitSpy.mock.calls.filter(
        (c: any) => c[0] === "rlv2:event:create" && c[1][0] === "BATTLE",
      );
      expect(battleCalls).toHaveLength(1);
      expect((battleCalls[0][1][1] as any).state).toBe(0);
    });
  });

  describe("rerollNode / upgradeNode / stash / exploreTool", () => {
    it("rerollNode 应消费刷新次数并重掷节点类型", async () => {
      (player.rlv2 as any)._status.cursor = { zone: 1, position: null };
      (player.rlv2 as any)._map.zones = {
        1: { id: "zone_1", nodes: { "200": { index: "200", pos: { x: 2, y: 0 }, type: 1, refresh: { usedCount: 0, count: 1, cost: 1 } } } },
      } as any;
      await (player.rlv2 as any).rerollNode({ nodeIndex: "200" });
      const node = (player.rlv2 as any)._map.zones[1].nodes["200"];
      expect(node.refresh.usedCount).toBe(1);
      expect(node.type).toBeGreaterThanOrEqual(1);
    });

    it("upgradeNode 应转发到 nodeUpgrade 模块", async () => {
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      await (player.rlv2 as any).upgradeNode({ nodeType: "REST" });
      const calls = emitSpy.mock.calls.filter((c: any) => c[0] === "rlv2:node:upgrade");
      expect(calls).toHaveLength(1);
      expect(calls[0][1]).toEqual(["REST"]);
    });

    it("stashRecruitTicket 应关闭票（state=3）", async () => {
      player.rlv2.inventory!.recruit["t_0"] = {
        index: "t_0", id: "t1", state: 1, list: [{}], result: null, ts: 0, from: "battle", mustExtra: 0, needAssist: false,
      } as any;
      await (player.rlv2 as any).stashRecruitTicket({ index: "t_0" });
      expect(player.rlv2.inventory!.recruit["t_0"].state).toBe(3);
      expect(player.rlv2.inventory!.recruit["t_0"].list).toHaveLength(0);
    });
  });
});

/** 等待构造期 rlv2:init（未 await）完成，避免异步重置状态 */
async function readyPlayer(theme: string) {
  const player = makePlayer();
  (player.rlv2 as any).current.game = { theme, mode: "NORMAL", modeGrade: 0 } as any;
  await new Promise((r) => setTimeout(r, 0));
  await (player.rlv2 as any)._pool.create();
  return player;
}

describe("真实机制补全（2026-08-10 第二轮）", () => {
  describe("diceChoice 真实 DICE 结算", () => {
    it("LEAVE 应发放奖励并消费 DICE 事件", async () => {
      const player = await readyPlayer("rogue_2");
      // 注入 DICE pending 事件
      (player.rlv2 as any)._status._pending._pending.push({
        type: "DICE",
        content: { dice: { result: { diceEventId: "rogue_2_diceEve_1", diceRoll: 3 }, rerollCount: 0 } },
      });
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      const ret = await (player.rlv2 as any).diceChoice({ choice: "LEAVE" });
      expect(ret.result).toBe(1);
      expect((player.rlv2 as any)._status.pending.length).toBe(0);
      const items = emitSpy.mock.calls.filter((c: any) => c[0] === "rlv2:get:items");
      expect(items.length).toBeGreaterThan(0);
    });

    it("REROLL 应重新生成骰子结果并保留 DICE 事件", async () => {
      const player = await readyPlayer("rogue_2");
      (player.rlv2 as any)._status._pending._pending.push({
        type: "DICE",
        content: { dice: { result: { diceEventId: "", diceRoll: 1 }, rerollCount: 0 } },
      });
      await (player.rlv2 as any).diceChoice({ choice: "REROLL" });
      expect((player.rlv2 as any)._status.pending.length).toBe(1);
      const dice = (player.rlv2 as any)._status.pending[0].content.dice;
      expect(dice.rerollCount).toBe(1);
      expect(dice.result.diceEventId).not.toBe("");
    });
  });

  describe("sacrificeChoice 真实献祭", () => {
    it("应发放献祭回报并关闭事件", async () => {
      const player = await readyPlayer("rogue_3");
      (player.rlv2 as any)._status._pending._pending.push({
        type: "SACRIFICE",
        content: { sacrifice: { type: 0 } },
      });
      const emitSpy = vi.spyOn(player._trigger as any, "emit");
      await (player.rlv2 as any).sacrificeChoice({ choice: "1", leave: 0 });
      expect((player.rlv2 as any)._status.pending.length).toBe(0);
      const relicGain = emitSpy.mock.calls.filter((c: any) => c[0] === "rlv2:relic:gain");
      // 池空时回退金币
      expect(relicGain.length + emitSpy.mock.calls.filter((c: any) => c[0] === "rlv2:get:items").length).toBeGreaterThan(0);
    });

    it("leave 应直接关闭事件", async () => {
      const player = await readyPlayer("rogue_3");
      (player.rlv2 as any)._status._pending._pending.push({ type: "SACRIFICE", content: {} });
      await (player.rlv2 as any).sacrificeChoice({ choice: "", leave: 1 });
      expect((player.rlv2 as any)._status.pending.length).toBe(0);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });
  });

  describe("zoneReward / traderReturn 实际填充", () => {
    it("checkZoneEnd 推进层数时应填充 zoneReward", async () => {
      const player = await readyPlayer("rogue_3");
      (player.rlv2 as any)._status.cursor.zone = 1;
      (player.rlv2 as any)._status.cursor.position = { x: 3, y: 0 };
      (player.rlv2 as any)._map.zones[1] = { nodes: { "300": { zone_end: true } } } as any;
      await (player.rlv2 as any).checkZoneEnd();
      expect((player.rlv2 as any)._status.zoneReward).toBeTruthy();
    });

    it("leaveShop 应填充 traderReturn", async () => {
      const player = await readyPlayer("rogue_3");
      await (player.rlv2 as any).leaveShop();
      expect((player.rlv2 as any)._status.traderReturn).toBeTruthy();
    });
  });
});

describe("分队机制（2026-08-11）", () => {
  it("chooseInitialRelic 应应用分队生命加成（level_life_point_add）", async () => {
    const player = await readyPlayer("rogue_1");
    // 注入 GAME_INIT_RELIC 事件
    (player.rlv2 as any)._status._pending._pending.push({
      type: "GAME_INIT_RELIC",
      content: { initRelic: { items: { "0": { id: "rogue_1_band_1", count: 1 } } } },
    });
    (player.rlv2 as any)._status.property.hp = { current: 4, max: 4 };
    await (player.rlv2 as any).chooseInitialRelic({ select: "0" });
    expect((player.rlv2 as any)._status.property.hp.max).toBe(8);
    expect((player.rlv2 as any)._status.property.hp.current).toBe(8);
  });

  it("chooseInitialRelic 应应用分队可部署上限（level_char_limit_add）", async () => {
    const player = await readyPlayer("rogue_1");
    (player.rlv2 as any)._status._pending._pending.push({
      type: "GAME_INIT_RELIC",
      content: { initRelic: { items: { "0": { id: "rogue_1_band_2", count: 1 } } } },
    });
    (player.rlv2 as any)._status.property.population.max = 6;
    await (player.rlv2 as any).chooseInitialRelic({ select: "0" });
    expect((player.rlv2 as any)._status.property.population.max).toBe(8);
  });

  it("ensureOuterTheme 应初始化 collect.band 分队解锁状态", async () => {
    const player = await readyPlayer("rogue_1");
    // 新主题 outer 无 collect → createGame 路径初始化
    delete (player.rlv2 as any).outer.rogue_1?.collect;
    (player.rlv2 as any).current.game = { theme: "rogue_1", mode: "NORMAL", modeGrade: 0 } as any;
    await (player.rlv2 as any).createGame({ theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefinedId: null });
    const collect = (player.rlv2 as any).outer.rogue_1.collect;
    expect(collect.band).toBeTruthy();
    expect(Object.keys(collect.band).length).toBeGreaterThan(0);
    // 开局可选分队应已解锁
    expect(Object.values(collect.band).every((b: any) => b.state === 1)).toBe(true);
  });
});
