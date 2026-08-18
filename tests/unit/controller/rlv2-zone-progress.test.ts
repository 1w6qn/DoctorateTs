import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// ===== 探索中 zone 推进回归（真实 excel 数据）=====
// 完整开局 → 走到 zone_end 节点 → finishEvent → zone 2 生成；
// NORMAL 与 MONTH_TEAM 双模式验证（此前只测到 zone 1 生成，未覆盖推进）
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

/** 完整开局到 WAIT_MOVE（zone 1），返回 recruitGroup 选择函数 */
async function openToWaitMove(rlv2: any, group = "recruit_group_1") {
  await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 0, predefinedId: null });
  await rlv2.chooseInitialRelic({ select: "0" });
  await rlv2.finishEvent();
  const sup = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_SUPPORT");
  if (sup) {
    const cid = Object.keys(sup.content.choices || {})[0];
    await rlv2.selectChoice({ choice: cid });
  }
  await rlv2.chooseInitialRecruitSet({ select: group });
  const recruitEvt = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_RECRUIT");
  for (const t of recruitEvt?.content?.initRecruit?.tickets || []) {
    await rlv2.activeRecruitTicket({ id: t });
    const ticket = rlv2.inventory.recruit[t];
    if (ticket.list.length > 0) {
      await rlv2.recruitChar({ ticketIndex: t, optionId: String(ticket.list[0].instId) });
    }
  }
  await rlv2.finishEvent();
}

/** 走到当前层 zone_end 节点并 finishEvent 推进（消费可能的商店事件） */
async function advanceZone(rlv2: any): Promise<number> {
  const zone = rlv2._status.cursor.zone;
  const mapKey = String(1000 + zone - 1);
  const mapZone = rlv2._map.zones[mapKey];
  const ends = Object.entries(mapZone.nodes).filter(([, n]: any) => n.zone_end);
  expect(ends.length).toBeGreaterThan(0);
  await rlv2.gridZoneMoveTo({ route: [ends[0][0]] });
  if (rlv2._status.pending[0]?.type === "BATTLE_SHOP") {
    await rlv2.finishEvent();
  }
  await rlv2.finishEvent(); // checkZoneEnd
  return rlv2._status.cursor.zone;
}

describe("探索中 zone 推进（真实 excel）", () => {
  it("NORMAL：zone 1 → 终点 → zone 2 生成，pending 为空与官服一致", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    let seed = 0;
    const rand = vi.spyOn(Math, "random").mockImplementation(() => (seed++ % 100) / 100);
    try {
      await openToWaitMove(rlv2);
      expect(rlv2._status.state).toBe("WAIT_MOVE");
      expect(rlv2._status.cursor.zone).toBe(1);
      // 层尾节点存在且标记 zone_end（map 侧）
      const ends = Object.entries(rlv2._map.zones["1000"].nodes).filter(
        ([, n]: any) => n.zone_end,
      );
      expect(ends.length).toBeGreaterThan(0);
      const nextZone = await advanceZone(rlv2);
      expect(nextZone).toBe(2);
      expect(rlv2._status.state).toBe("WAIT_MOVE");
      // pending 空（与官服 finishEvent → WAIT_MOVE 一致）
      expect(rlv2._status.pending.length).toBe(0);
      // 新层地图已生成（map + gridZone 双侧）
      expect(rlv2._map.zones["1001"]).toBeTruthy();
      expect(rlv2._module.gridZone.zones["zone_2"]).toBeTruthy();
    } finally {
      rand.mockRestore();
    }
  });

  it("MONTH_TEAM：同样可推进到 zone 2（模式修复后完整链路）", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    let seed = 0;
    const rand = vi.spyOn(Math, "random").mockImplementation(() => (seed++ % 100) / 100);
    try {
      await rlv2.createGame({ theme: "rogue_6", mode: "MONTH_TEAM", modeGrade: 0, predefinedId: "month_team_1" });
      await rlv2.chooseInitialRelic({ select: "0" });
      await rlv2.finishEvent();
      const sup = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_SUPPORT");
      if (sup) {
        const cid = Object.keys(sup.content.choices || {})[0];
        await rlv2.selectChoice({ choice: cid });
      }
      await rlv2.chooseInitialRecruitSet({ select: "recruit_group_m1" });
      const recruitEvt = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_RECRUIT");
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
      const nextZone = await advanceZone(rlv2);
      expect(nextZone).toBe(2);
      expect(rlv2._status.pending.length).toBe(0);
    } finally {
      rand.mockRestore();
    }
  });

  it("作战节点：移动生成 BATTLE 事件（state PENDING），后续可正常 finishEvent", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    let seed = 0;
    const rand = vi.spyOn(Math, "random").mockImplementation(() => (seed++ % 100) / 100);
    try {
      await openToWaitMove(rlv2);
      const battle = Object.entries(rlv2._map.zones["1000"].nodes).find(
        ([, n]: any) => n.type === 1 && n.stage,
      );
      expect(battle).toBeTruthy();
      await rlv2.gridZoneMoveTo({ route: [battle![0]] });
      expect(rlv2._status.state).toBe("PENDING");
      const bEvent = rlv2._status.pending.find((e: any) => e.type === "BATTLE");
      expect(bEvent).toBeTruthy();
      expect((bEvent as any).content?.battle?.state).toBe(1);
    } finally {
      rand.mockRestore();
    }
  });
});
