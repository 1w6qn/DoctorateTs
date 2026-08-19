import { describe, it, expect, vi, beforeAll } from "vitest";

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({ completeState: 1, finalHp: 8, isPerfect: 1 }),
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import excel from "@excel/excel";

beforeAll(async () => {
  await excel.init();
}, 120000);

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: {
      outer: {
        rogue_6: {
          record: { last: 0, lastZone: 3, legacy: [], stageCnt: {}, bandCnt: {}, bandGrade: {} },
          collect: { band: {} },
          buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
          monthTeam: { valid: [] },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
    troop: {
      chars: {
        33: {
          instId: 33, charId: "char_4230_mcnist", level: 90, exp: 0, evolvePhase: 2,
          potentialRank: 5, favorPoint: 625, mainSkillLvl: 7, gainTime: 0, skin: "char_4230_mcnist#2",
          defaultSkillIndex: 0, voiceLan: "cn",
          skills: [
            { skillId: "skchr_mcnist_1", unlock: 1, state: 0, specializeLevel: 2, completeUpgradeTime: -1 },
            { skillId: "skchr_mcnist_2", unlock: 1, state: 0, specializeLevel: 2, completeUpgradeTime: -1 },
            { skillId: "skchr_mcnist_3", unlock: 1, state: 0, specializeLevel: 3, completeUpgradeTime: -1 },
          ],
          currentEquip: "uniequip_002_mcnist",
          equip: {
            uniequip_001_mcnist: { hide: 0, locked: 0, level: 1 },
            uniequip_002_mcnist: { hide: 0, locked: 0, level: 3 },
          },
          master: { master_mcnist_1: 3, master_mcnist_2: 2, master_mcnist_3: 3, master_mcnist_4: 3, master_mcnist_5: 1, master_mcnist_6: 1 },
        },
      },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefined: null, outer: { support: false } } as any;
  return player;
}

describe("recruitChar 响应结构对齐官服（2026-08-18 抓包校准）", () => {
  it("招募结果含完整养成结构：skills/master/equip/currentEquip + instId/troopInstId 语义", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    // Emittery emit 异步：构造期 rlv2:init 未 await，等微任务落定后再注入票
    await Promise.resolve();
    const rm = rlv2.inventory._recruit;
    rm.tickets["t_0"] = {
      index: "t_0", id: "rogue_6_recruit_ticket_sniper", state: 1,
      list: [{
        instId: "0", charId: "char_4230_mcnist", type: "NORMAL",
        favorPoint: 625, potentialRank: 5, mainSkillLvl: 7, skin: "char_4230_mcnist#2",
        level: 90, exp: 0, evolvePhase: 2, defaultSkillIndex: 0, skills: [],
        upgradeLimited: false, upgradePhase: 1, isUpgrade: false, isCure: false,
        population: 2, charBuff: [], troopInstId: "33", master: {},
      }],
      result: null, from: "initial", mustExtra: 0, needAssist: false, ts: 0,
    } as any;
    await rm.done("t_0", "0");
    const c = rm.tickets["t_0"].result as any;
    expect(c).toBeTruthy();
    // 官服 chars[0] 22 键
    const expected = ["instId","charId","type","favorPoint","potentialRank","mainSkillLvl","skin","level","exp","evolvePhase","defaultSkillIndex","skills","upgradeLimited","upgradePhase","isUpgrade","isCure","population","charBuff","troopInstId","master","currentEquip","equip"];
    expect(Object.keys(c).sort()).toEqual([...expected].sort());
    expect(c.instId).toBe("33");
    expect(c.troopInstId).toBe("1");
    expect((c.skills || []).length).toBe(3);
    expect(Object.keys(c.master || {}).length).toBe(6);
    expect(c.currentEquip).toBe("uniequip_002_mcnist");
    expect(Object.keys(c.equip || {}).length).toBe(2);
    const troopChars = rlv2.troop.chars;
    expect(Object.keys(troopChars)).toEqual(["1"]);
    expect(troopChars["1"].instId).toBe("1");
    expect(troopChars["1"].charId).toBe("char_4230_mcnist");
    expect((troopChars["1"].skills || []).length).toBe(3);
    expect(troopChars["1"].currentEquip).toBe("uniequip_002_mcnist");
  });
});
