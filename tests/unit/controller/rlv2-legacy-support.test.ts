import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// rogue_6 P2：襁褓生灵接入行动奖励（羽蛇 +1 选项 / 三头犬 +1 选择次数）
// + 难度 0 失败补偿（下次开局特勤任务影像）
const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        stages: { ro6_n_1_1: { id: "ro6_n_1_1" }, ro6_n_3_1: { id: "ro6_n_3_1" }, ro6_n_5_1: { id: "ro6_n_5_1" } },
        init: [
          { modeGrade: 0, predefinedId: null, modeId: "NORMAL", initialHp: 8, initialGold: 8, initialPopulation: 6, initialSquadCapacity: 6, initialBandRelic: [], initialRecruitGroup: [] },
        ],
        bandRef: {},
        difficulties: [{ modeDifficulty: "NORMAL", grade: 0, scoreFactor: 1 }],
        items: {
          rogue_6_gold: { id: "rogue_6_gold", type: "GOLD", rarity: "NONE" },
          rogue_6_population: { id: "rogue_6_population", type: "POPULATION", rarity: "NONE" },
          rogue_6_relic_fight_29: { id: "rogue_6_relic_fight_29", type: "RELIC", rarity: "RARE" },
          rogue_6_start_1: { id: "rogue_6_start_1", type: "RELIC", rarity: "NORMAL" },
        },
        relics: {
          rogue_6_relic_fight_29: { id: "rogue_6_relic_fight_29", buffs: [] },
          rogue_6_start_1: { id: "rogue_6_start_1", buffs: [] },
          // 襁褓生灵（数据驱动：init_gift / init_support_multi_chance / force_add_choice）
          rogue_6_legacy_01: { id: "rogue_6_legacy_01", buffs: [{ key: "init_gift", blackboard: [{ key: "id", value: 0, valueStr: "rogue_6_gold" }, { key: "count", value: 5, valueStr: null }] }] },
          rogue_6_legacy_02: { id: "rogue_6_legacy_02", buffs: [{ key: "init_gift", blackboard: [{ key: "id", value: 0, valueStr: "rogue_6_population" }, { key: "count", value: 1, valueStr: null }] }] },
          rogue_6_legacy_03: { id: "rogue_6_legacy_03", buffs: [{ key: "init_support_multi_chance", blackboard: [{ key: "add", value: 1, valueStr: null }] }] },
          rogue_6_legacy_04: { id: "rogue_6_legacy_04", buffs: [{ key: "force_add_choice", blackboard: [{ key: "choice_id", value: 0, valueStr: "choice_ro6_startbuff_7" }, { key: "scene_ids", value: 0, valueStr: "scene_ro6_startbuff_enter" }] }] },
        },
        choices: {
          choice_ro6_startbuff_1: { id: "choice_ro6_startbuff_1" },
          choice_ro6_startbuff_2: { id: "choice_ro6_startbuff_2" },
          choice_ro6_startbuff_3: { id: "choice_ro6_startbuff_3" },
          choice_ro6_startbuff_4: { id: "choice_ro6_startbuff_4" },
          choice_ro6_startbuff_5: { id: "choice_ro6_startbuff_5" },
          choice_ro6_startbuff_6: { id: "choice_ro6_startbuff_6" },
          choice_ro6_startbuff_7: { id: "choice_ro6_startbuff_7" },
          choice_ro6_startbuff_8: { id: "choice_ro6_startbuff_8" },
          choice_ro6_startbuff_9: { id: "choice_ro6_startbuff_9" },
        },
      },
    },
    modules: {
      rogue_6: { moduleTypes: ["GRID_ZONE", "SCRAP"], scrap: { scrapItemToType: {} } },
    },
    consts: {},
  },
  CharacterTable: {},
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import { RoguelikePendingEvent } from "@game/controller/rlv2/events";

function makePlayer(modeGrade = 0, support = false) {
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
  (player.rlv2 as any).current.game = {
    theme: "rogue_6",
    mode: "NORMAL",
    modeGrade,
    outer: { support },
  } as any;
  return player;
}

/** 构造一个 GAME_INIT_SUPPORT pending 事件并返回其选项列表 */
function supportChoices(player: any): string[] {
  const ev = new RoguelikePendingEvent(
    player.rlv2,
    (player.rlv2 as any)._trigger,
    "GAME_INIT_SUPPORT",
    0,
    { step: [1, 3] },
  );
  return Object.keys(ev.content.initSupport.scene.choices);
}

describe("rogue_6 襁褓生灵 → 行动奖励选项/选择次数", () => {
  it("无襁褓：基础 6 选项随机 3 个", async () => {
    const player = makePlayer();
    const choices = supportChoices(player);
    expect(choices.length).toBe(3);
    for (const c of choices) {
      const n = parseInt(c.replace(/^.*startbuff_/, ""), 10);
      expect(n).toBeGreaterThanOrEqual(1);
      expect(n).toBeLessThanOrEqual(6);
    }
  });

  it("襁褓羽蛇（legacy_04：支援选项+1）→ 追加 1 个襁褓选项（startbuff_7..12）", async () => {
    const player = makePlayer();
    (player.rlv2 as any).outer.rogue_6.record = {
      legacy: ["rogue_6_legacy_04"],
    };
    const choices = supportChoices(player);
    expect(choices.length).toBe(4);
    const extra = choices.find(
      (c) => parseInt(c.replace(/^.*startbuff_/, ""), 10) >= 7,
    );
    expect(extra).toBeTruthy();
  });

  it("襁褓三头犬（legacy_03：选择次数+1）→ 生成 2 个 GAME_INIT_SUPPORT 事件", async () => {
    const player = makePlayer(0, true); // 有行动奖励阶段（上一把到 3 层）
    (player.rlv2 as any).outer.rogue_6.record = {
      legacy: ["rogue_6_legacy_03"],
    };
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._trigger.emit("rlv2:create", [player.rlv2]);
    const pending = (player.rlv2 as any)._status.pending;
    const supports = pending.filter((e: any) => e.type === "GAME_INIT_SUPPORT");
    expect(supports.length).toBe(2);
  });

  it("无三头犬：仅 1 个 GAME_INIT_SUPPORT 事件", async () => {
    const player = makePlayer(0, true);
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._trigger.emit("rlv2:create", [player.rlv2]);
    const pending = (player.rlv2 as any)._status.pending;
    expect(
      pending.filter((e: any) => e.type === "GAME_INIT_SUPPORT").length,
    ).toBe(1);
  });

  it("无行动奖励阶段（上一把未到 3 层）→ 无 GAME_INIT_SUPPORT", async () => {
    const player = makePlayer(0, false);
    await (player.rlv2 as any)._module.create();
    await (player.rlv2 as any)._trigger.emit("rlv2:create", [player.rlv2]);
    const pending = (player.rlv2 as any)._status.pending;
    expect(
      pending.filter((e: any) => e.type === "GAME_INIT_SUPPORT").length,
    ).toBe(0);
  });
});

describe("rogue_6 难度 0 失败补偿（特勤任务影像）", () => {
  it("难度 ≤3 失败 → record.legacy 记录特勤任务影像（下次开局发放）", async () => {
    const player = makePlayer(0);
    await (player.rlv2 as any)._module.create();
    (player.rlv2 as any)._status.runResult = "giveup";
    (player.rlv2 as any)._status.cursor.zone = 3;
    await (player.rlv2 as any).gameSettle();
    const legacy = (player.rlv2 as any).outer.rogue_6.record.legacy;
    expect(legacy).toContain("rogue_6_relic_fight_29");
  });

  it("难度 4+ 失败 → 不再记录特勤任务影像", async () => {
    const player = makePlayer(4);
    await (player.rlv2 as any)._module.create();
    (player.rlv2 as any)._status.runResult = "giveup";
    (player.rlv2 as any)._status.cursor.zone = 3;
    await (player.rlv2 as any).gameSettle();
    const legacy = (player.rlv2 as any).outer.rogue_6.record.legacy || [];
    expect(legacy).not.toContain("rogue_6_relic_fight_29");
  });

  it("createGame：record.legacy 含特勤任务影像 → 开局获得该收藏品", async () => {
    const player = makePlayer(0);
    (player.rlv2 as any).outer.rogue_6.record = {
      legacy: ["rogue_6_relic_fight_29"],
    };
    await (player.rlv2 as any).createGame({
      theme: "rogue_6",
      mode: "NORMAL",
      modeGrade: 0,
      predefinedId: null,
    });
    const relics = Object.values((player.rlv2 as any).inventory.relic).map(
      (r: any) => r.id,
    );
    expect(relics).toContain("rogue_6_relic_fight_29");
  });
});
