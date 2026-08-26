import { describe, it, expect, vi, beforeAll } from "vitest";

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({ completeState: 1, finalHp: 8, isPerfect: 1 }),
}));

import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";
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
    // instId = 候选序号（list 下标，与客户端 optionId 一致——官服 recruitChar chars[].instId 即 optionId）；
    // troopInstId = 对局内入队序号（1 基递增）
    expect(c.instId).toBe("0");
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

  it("精二源干员首次招募被锁定精一时：专精/模组养成同步裁剪（显示与状态一致）", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await Promise.resolve();
    const rm = rlv2.inventory._recruit;
    // 候选体现 active() 的 levelPatch：精二源降为精一（evolvePhase=1、精一满级、exp=0、upgradeLimited）
    rm.tickets["t_0"] = {
      index: "t_0", id: "rogue_6_recruit_ticket_sniper", state: 1,
      list: [{
        instId: "0", charId: "char_4230_mcnist", type: "NORMAL",
        favorPoint: 625, potentialRank: 5, mainSkillLvl: 7, skin: "char_4230_mcnist#2",
        level: 50, exp: 0, evolvePhase: 1, defaultSkillIndex: 0, skills: [],
        upgradeLimited: true, upgradePhase: 0, isUpgrade: false, isCure: false,
        population: 2, charBuff: [], troopInstId: "33", master: {},
      }],
      result: null, from: "initial", mustExtra: 0, needAssist: false, ts: 0,
    } as any;
    await rm.done("t_0", "0");
    const c = rm.tickets["t_0"].result as any;
    expect(c.evolvePhase).toBe(1);
    // 精一仅保留已解锁的前 2 个技能（三技能 skchr_mcnist_3 为 PHASE_2 需精二，剔除）
    expect(c.skills.map((s: any) => s.skillId)).toEqual([
      "skchr_mcnist_1",
      "skchr_mcnist_2",
    ]);
    // 专精归零（精一不可专精）
    for (const s of c.skills) expect(s.specializeLevel).toBe(0);
    // 默认技能钳制到保留技能数内（候选 defaultSkillIndex=0 保持 0）
    expect(c.defaultSkillIndex).toBe(0);
    // 无专精 → master 清空；无模组 → equip/currentEquip 清空
    expect(Object.keys(c.master || {})).toEqual([]);
    expect(Object.keys(c.equip || {})).toEqual([]);
    expect(c.currentEquip).toBe("");
  });

  it("战斗获取招募券招募：result.instId 保持候选序号（防客户端按 instId 回查候选列表命中错误干员崩溃）", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await Promise.resolve();
    const rm = rlv2.inventory._recruit;
    // 模拟战斗获取招募券 t_0：候选 troopInstId 为玩家主队伍 instId（此处恰为 "5"，
    // 数值落在候选列表下标范围内——旧实现把 result.instId 写成该值会让客户端
    // 按 chars[].instId 回查候选列表命中错误干员 → 招募后崩溃）
    rm.tickets["t_0"] = {
      index: "t_0", id: "rogue_6_recruit_ticket_tank", state: 1,
      list: [{
        instId: "0", charId: "char_4230_mcnist", type: "NORMAL",
        favorPoint: 625, potentialRank: 5, mainSkillLvl: 7, skin: "char_4230_mcnist#2",
        level: 80, exp: 0, evolvePhase: 1, defaultSkillIndex: 0, skills: [],
        upgradeLimited: true, upgradePhase: 0, isUpgrade: false, isCure: false,
        population: 6, charBuff: [], troopInstId: "5", master: {},
      }],
      result: null, from: "battle", mustExtra: 0, needAssist: false, ts: 0,
    } as any;
    await rm.done("t_0", "0");
    const c = rm.tickets["t_0"].result as any;
    // instId 必须等于候选序号（与客户端请求 optionId "0" 一致），而非玩家主队伍 instId "5"
    expect(c.instId).toBe("0");
    expect(c.charId).toBe("char_4230_mcnist");
    expect(c.troopInstId).toBe("1");
    // 信赖取整（客户端 favorPoint 为 int；历史数据可为小数）
    expect(Number.isInteger(c.favorPoint)).toBe(true);
    // 招募结果结构与官服一致（22 键）
    const expected = ["instId","charId","type","favorPoint","potentialRank","mainSkillLvl","skin","level","exp","evolvePhase","defaultSkillIndex","skills","upgradeLimited","upgradePhase","isUpgrade","isCure","population","charBuff","troopInstId","master","currentEquip","equip"];
    expect(Object.keys(c).sort()).toEqual([...expected].sort());
  });
});
