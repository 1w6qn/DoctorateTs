import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// ===== 实践者列表（MONTH_TEAM）模式修复回归 =====
// 用户 bug：MONTH_TEAM 开局血/血上限 0、希望 7、recruitChar 意外临时招募、finishEvent 后卡死。
// 根因：createGame 把 MONTH_TEAM 强制转 NORMAL 但保留 predefinedId（month_team_N）→
// status.create/initConfig 的 init.find（modeId==NORMAL && predefinedId==month_team_N）无匹配
// → status.create 抛错（血 0/0）、events.create 部分失败（pending 缺 RELIC/RECRUIT_SET）
// → 客户端开局流程错乱、后续卡死。
// 修复：createGame 保留 MONTH_TEAM mode（init 表有 month_team_1/2 专属条目），
// 仅 CHALLENGE 转 NORMAL（无专属 init 条目）；recruit_group_m1/m2"支援作战"= 2 张随机招募券。

// 用真实 excel 数据（避免 mock 与官方 init 表结构偏差掩盖/伪造 bug）
vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: require("../../../data/excel/roguelike_topic_table.json"),
    CharacterTable: require("../../../data/excel/character_table.json"),
    GameDataConst: require("../../../data/excel/gamedata_const.json"),
    RoguelikeConsts: require("../../../data/rlv2.json"),
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: {
      outer: {
        rogue_6: {
          record: { last: 0, lastZone: 3, legacy: [], stageCnt: {}, bandCnt: {}, bandGrade: {} },
          collect: { band: {} },
          buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
    troop: {
      chars: {
        1: { charId: "char_002_amiya", instId: 1, rarity: "TIER_5" },
        2: { charId: "char_010_chen", instId: 2, rarity: "TIER_6" },
        3: { charId: "char_124_kroos", instId: 3, rarity: "TIER_3" },
        4: { charId: "char_1039_thorn2", instId: 4, rarity: "TIER_6" },
        5: { charId: "char_017_huang", instId: 5, rarity: "TIER_6" },
        6: { charId: "char_102_texas", instId: 6, rarity: "TIER_5" },
        7: { charId: "char_129_bluep", instId: 7, rarity: "TIER_5" },
        8: { charId: "char_148_nearl", instId: 8, rarity: "TIER_5" },
        9: { charId: "char_144_red", instId: 9, rarity: "TIER_5" },
        10: { charId: "char_242_otter", instId: 10, rarity: "TIER_5" },
      },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  return player;
}

/** 消费 GIFT（finishEvent）+ SUPPORT（selectChoice 首个选项） */
async function consumeGiftAndSupport(rlv2: any) {
  await rlv2.finishEvent(); // GAME_INIT_GIFT
  const s = rlv2._status;
  const sup = s.pending.find((e: any) => e.type === "GAME_INIT_SUPPORT");
  if (sup) {
    const choiceId = Object.keys(sup.content.choices || {})[0];
    await rlv2.selectChoice({ choice: choiceId });
  }
}

describe("实践者列表（MONTH_TEAM）模式", () => {
  it("createGame 不崩：血 8/8、希望 6、pending 完整 5 事件", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "MONTH_TEAM", modeGrade: 0, predefinedId: "month_team_1" });
    const s = rlv2._status;
    expect(s.property.hp.current).toBe(8);
    expect(s.property.hp.max).toBe(8);
    expect(s.property.population.max).toBe(6);
    // pending 完整（修复前缺 GAME_INIT_RELIC / GAME_INIT_RECRUIT_SET）
    const types = s.pending.map((e: any) => e.type);
    expect(types).toContain("GAME_INIT_RELIC");
    expect(types).toContain("GAME_INIT_GIFT");
    expect(types).toContain("GAME_INIT_RECRUIT_SET");
    expect(types).toContain("GAME_INIT_RECRUIT");
    // 招募组为实践者专属（支援作战 m1）
    expect(rlv2.initConfig.initialRecruitGroup).toContain("recruit_group_m1");
  });

  it("完整开局流程不卡死：2 张支援作战票招募后 finishEvent 进入 WAIT_MOVE", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    const rand = vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      await rlv2.createGame({ theme: "rogue_6", mode: "MONTH_TEAM", modeGrade: 0, predefinedId: "month_team_1" });
      await rlv2.chooseInitialRelic({ select: "0" });
      await consumeGiftAndSupport(rlv2);
      await rlv2.chooseInitialRecruitSet({ select: "recruit_group_m1" });
      const recruitEvt = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_RECRUIT");
      const tickets = recruitEvt?.content?.initRecruit?.tickets || [];
      // 支援作战：2 张随机招募券
      expect(tickets.length).toBe(2);
      for (const t of tickets) {
        await rlv2.activeRecruitTicket({ id: t });
        const ticket = rlv2.inventory.recruit[t];
        // 候选非空（真实干员库），招募结果为 NORMAL（非意外临时）
        expect(ticket.list.length).toBeGreaterThan(0);
        await rlv2.recruitChar({ ticketIndex: t, optionId: String(ticket.list[0].instId) });
        expect(rlv2.inventory.recruit[t].result?.type).toBe("NORMAL");
      }
      // 消费 GAME_INIT_RECRUIT → 进入第一层
      await rlv2.finishEvent();
      expect(rlv2._status.state).toBe("WAIT_MOVE");
      expect(rlv2._status.cursor.zone).toBe(1);
    } finally {
      rand.mockRestore();
    }
  });

  it("recruit_group_m2 同样 2 张随机票", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    const rand = vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      await rlv2.createGame({ theme: "rogue_6", mode: "MONTH_TEAM", modeGrade: 0, predefinedId: "month_team_2" });
      await rlv2.chooseInitialRelic({ select: "0" });
      await consumeGiftAndSupport(rlv2);
      await rlv2.chooseInitialRecruitSet({ select: "recruit_group_m2" });
      const recruitEvt = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_RECRUIT");
      expect(recruitEvt?.content?.initRecruit?.tickets?.length).toBe(2);
    } finally {
      rand.mockRestore();
    }
  });

  it("CHALLENGE 模式保持转 NORMAL（无专属 init 条目）", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "CHALLENGE", modeGrade: 0, predefinedId: null });
    expect(rlv2.current.game.mode).toBe("NORMAL");
    const s = rlv2._status;
    expect(s.property.hp.max).toBe(8); // NORMAL grade 0 初始血
  });
});
