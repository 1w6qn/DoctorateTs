import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// ===== N15 开局血量回归 =====
// 用户 bug：N15（modeGrade 15）开局血/血上限 0，客户端"系统发生未知故障"。
// 根因：init 表已按 modeGrade 预扣血量（grade 0=8 / 1-9=6 / 10+=4），
// 但 difficultyBuffs 又从难度描述解析"目标生命上限-2"（难度1/难度10 各 -2）
// 二次应用 → N15 4-2-2=0/0。
// 修复：难度描述不再生成 level_life_point_add（血量由 init 表承载）。

// 用真实 excel 数据
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

function makePlayer(modeGrade = 15) {
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
      },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade, predefined: null, outer: { support: true } } as any;
  return player;
}

describe("N15 开局血量（init 表承载难度扣血，不二次解析）", () => {
  it("createGame N15：血 4/4（init grade15 initialHp=4），难度 buff 无 level_life_point_add", async () => {
    const player = makePlayer(15);
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    expect(rlv2._status.property.hp).toEqual({ current: 4, max: 4 });
    expect(rlv2._status.property.population.max).toBe(6);
    const diffs = rlv2._buff.difficultyBuffs("rogue_6", 15);
    expect(diffs.some((b: any) => b.key === "level_life_point_add")).toBe(false);
    // 其余难度 buff 正常累积
    const keys = diffs.map((b: any) => b.key);
    expect(keys).toContain("scrap_limit_add");
    expect(keys).toContain("zone_gold_loss_percent");
    expect(keys).toContain("deploy_limit_add");
    expect(keys).toContain("recruit_hop_cost");
  });

  it("各难度档初始血量 = init 表（0:8 / 1:6 / 10:4），无双重扣血", async () => {
    for (const [grade, hp] of [
      [0, 8],
      [1, 6],
      [9, 6],
      [10, 4],
      [15, 4],
    ] as const) {
      const player = makePlayer(grade);
      const rlv2 = player.rlv2 as any;
      await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: grade, predefinedId: null });
      expect(rlv2._status.property.hp.current).toBe(hp);
      expect(rlv2._status.property.hp.max).toBe(hp);
    }
  });

  it("N15 完整开局（选分队→招募→finishEvent）：血保持 4/4，WAIT_MOVE 进入第一层", async () => {
    const player = makePlayer(15);
    const rlv2 = player.rlv2 as any;
    const rand = vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
      await rlv2.chooseInitialRelic({ select: "0" });
      // 消费 GIFT（无 legacy 则无）→ SUPPORT → RecruitSet → 招募
      const pend = rlv2._status.pending;
      const types = pend.map((e: any) => e.type);
      expect(types).toContain("GAME_INIT_RECRUIT_SET");
      await rlv2.chooseInitialRecruitSet({ select: "recruit_group_1" });
      const recruitEvt = pend.find((e: any) => e.type === "GAME_INIT_RECRUIT");
      for (const t of recruitEvt?.content?.initRecruit?.tickets || []) {
        await rlv2.activeRecruitTicket({ id: t });
        const ticket = rlv2.inventory.recruit[t];
        if (ticket.list.length > 0) {
          await rlv2.recruitChar({ ticketIndex: t, optionId: String(ticket.list[0].instId) });
        }
      }
      await rlv2.finishEvent();
      expect(rlv2._status.state).toBe("WAIT_MOVE");
      expect(rlv2._status.cursor.zone).toBe(1);
      // 分队 0 = 指挥分队（目标生命上限+2）→ 4+2=6；血量非 0/0 即通过（回归双重扣血）
      expect(rlv2._status.property.hp.max).toBe(6);
      expect(rlv2._status.property.hp.current).toBe(6);
    } finally {
      rand.mockRestore();
    }
  });
});

describe("各主题招募/进阶希望消耗（官方表）", () => {
  it("rogue_5 萨卡兹：招募消耗表 000026（4星0/5星2/6星6）", async () => {
    const player = makePlayer(0);
    const rlv2 = player.rlv2 as any;
    // 覆盖当前主题为 rogue_5（populationFor 按 theme 分支）
    rlv2.current.game.theme = "rogue_5";
    await rlv2._module.create();
    const recruit = rlv2.inventory._recruit;
    const pop = (recruit as any).populationFor.bind(recruit);
    // TIER_3→2 / TIER_4→3 / TIER_5→4 / TIER_6→5
    expect(pop(2)).toBe(0); // 3星
    expect(pop(3)).toBe(0); // 4星
    expect(pop(4)).toBe(2); // 5星
    expect(pop(5)).toBe(6); // 6星
    // rogue_6 保持 6星4（实测确认）
    rlv2.current.game.theme = "rogue_6";
    expect(pop(5)).toBe(4);
    // 进阶消耗表（000113：4星1/5星1/6星3）
    rlv2.current.game.theme = "rogue_5";
    const adv = (recruit as any).advancePopulationFor.bind(recruit);
    expect(adv(3)).toBe(1);
    expect(adv(4)).toBe(1);
    expect(adv(5)).toBe(3);
  });
});

describe("rlv2 响应 outer 精简（对齐官服 createGame）", () => {
  it("createGame 响应 outer 只含当前主题 record/monthTeam，响应显著瘦身", async () => {
    const player = makePlayer(15);
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    const { rlv2Response } = await import("@game/router/rlv2");
    const resp = rlv2Response(player as any, undefined);
    const r = resp.playerDataDelta.modified.rlv2;
    // outer 只含当前主题 rogue_6（不再全量 6 主题）
    expect(Object.keys(r.outer)).toEqual(["rogue_6"]);
    // 该主题只含 record + monthTeam（官服 createGame 结构；collect/buff/bank 等
    // 客户端从 syncData 全量拿，不随 rlv2 路由下发）
    expect(Object.keys(r.outer.rogue_6).sort()).toEqual(["monthTeam", "record"]);
    // 响应总大小显著小于修复前（255KB → 数 KB）
    expect(JSON.stringify(resp).length).toBeLessThan(20000);
  });
});
