import { describe, it, expect, vi } from "vitest";

const excelMock = vi.hoisted(() => {
  const autochessAct = {
    modeDataDict: {
      mode_training_1: {
        modeId: "mode_training_1",
        preposedMode: null,
        modeType: 0,
        modeDifficulty: 0,
        specialPhaseTime: 150,
      },
      mode_single_funny: {
        modeId: "mode_single_funny",
        preposedMode: "mode_training_1",
        modeType: "SINGLE",
        modeDifficulty: "FUNNY",
        specialPhaseTime: 150,
      },
      mode_single_normal: {
        modeId: "mode_single_normal",
        preposedMode: "mode_single_funny;mode_multi_funny",
        modeType: "SINGLE",
        modeDifficulty: "NORMAL",
        specialPhaseTime: 150,
      },
    },
    baseRewardDataList: [
      {
        round: 1,
        item: { id: "act2autochess_token_chess", count: 10, type: "ACTIVITY_ITEM" },
        dailyMissionPoint: 10,
      },
      {
        round: 2,
        item: { id: "act2autochess_token_chess", count: 20, type: "ACTIVITY_ITEM" },
        dailyMissionPoint: 20,
      },
    ],
    charShopChessDatas: {
      chess_char_1_01_a: {
        chessId: "chess_char_1_01_a",
        charId: "char_001",
        tmplId: null,
        defaultSkillIndex: 1,
      },
    },
    chessNormalIdLookupDict: {
      chess_char_1_01_b: "chess_char_1_01_a",
    },
    diyChessDict: {},
    stageDatasDict: {
      act1autochess_m01: { stageId: "act1autochess_m01" },
    },
    constData: {
      maxDeckChessCnt: 2,
      dailyMissionParam: 200,
      trainingModeId: "mode_training_1",
      milestoneId: "act2autochess_token_chess",
    },
  };
  return {
    ActivityTable: {
      activity: {
        autochessSeason: {
          act2autochess: autochessAct,
        },
      },
      autoChessData: {},
      basicInfo: {
        act2autochess: { id: "act2autochess", type: "AUTOCHESS_SEASON" },
      },
    },
    getItem(id: string) {
      return undefined;
    },
    itemName(id: string) {
      return id;
    },
    makeItem(id: string, count: number, type?: string) {
      return type ? { id, count, type } : { id, count };
    },
    charData() {
      return undefined;
    },
    stageData() {
      return undefined;
    },
  };
});

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { AutoChessManager } from "@game/modules/autochess/autochess";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    activity: {} as any,
    status: {
      uid: "1",
      nickName: "博士",
      nickNumber: 0,
      level: 1,
      exp: 0,
    } as any,
  });
  pd.battle = {
    start: vi.fn().mockResolvedValue({ battleId: "battle-train-1", result: 0 }),
    finish: vi.fn().mockResolvedValue({ result: 0, rewards: [] }),
  };
  return pd;
}

function makeManager(player: any) {
  return new AutoChessManager(player, player._trigger);
}

describe("autochess 赛季管理器", () => {
  it("syncInfo 惰性播种玩家存档并返回空 changed/battleInfo", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    const resp = await mgr.syncInfo({ actId: "act2autochess" });
    expect(resp.changed).toEqual([]);
    expect(resp.battleInfo).toBeNull();
    const user = player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    expect(user.mode).toEqual({});
    expect(user.milestone).toEqual({ point: 0, got: [] });
    expect(user.chessSquad).toEqual({});
    expect(player._playerdata.autochessSeason).toEqual({
      band: {},
      trainingModeFin: {},
    });
  });

  it("setChessPoolDeploy 校验 excel 并持久化 chessSquad（含 golden 映射），超上限拒绝", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    await mgr.syncInfo({ actId: "act2autochess" });

    const ok = await mgr.setChessPoolDeploy({
      actId: "act2autochess",
      chessPool: {
        chess_char_1_01_a: { skillIndex: 2, currentEquip: "uniequip_001" },
        chess_char_1_01_b: { skillIndex: 1 },
      },
    });
    expect(ok.ok).toBe(true);
    const user = player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    expect(Object.keys(user.chessSquad)).toEqual([
      "chess_char_1_01_a",
      "chess_char_1_01_b",
    ]);
    expect(user.chessSquad.chess_char_1_01_a.charId).toBe("char_001");
    expect(user.chessSquad.chess_char_1_01_a.skillIndex).toBe(2);
    expect(user.chessSquad.chess_char_1_01_b.charId).toBe("char_001"); // 经 chessNormalIdLookupDict 映射

    // 超过 maxDeckChessCnt=2 拒绝
    const tooMany = await mgr.setChessPoolDeploy({
      actId: "act2autochess",
      chessPool: {
        chess_char_1_01_a: { skillIndex: 1 },
        chess_char_1_01_b: { skillIndex: 1 },
        chess_char_1_01_c: { skillIndex: 1 },
      },
    });
    expect(tooMany.ok).toBe(false);
    expect(tooMany.ok ? "" : tooMany.reason).toBe("too-many");

    // 未知 chessId 拒绝
    const unknown = await mgr.setChessPoolDeploy({
      actId: "act2autochess",
      chessPool: { chess_unknown: { skillIndex: 1 } },
    });
    expect(unknown.ok).toBe(false);
  });

  it("setChessPoolDiyChar 写入 DIY 槽位；removeChessPoolChar 删除", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    await mgr.syncInfo({ actId: "act2autochess" });

    const ok = await mgr.setChessPoolDiyChar({
      actId: "act2autochess",
      diyChessPool: {
        chess_char_1_01_a: {
          skillIndex: 3,
          diyChar: "char_diy",
          origChessId: "chess_char_1_01_a",
        },
      },
    });
    expect(ok.ok).toBe(true);
    const user = player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    expect(user.chessSquad.chess_char_1_01_a.type).toBe(3); // DIY
    expect(user.chessSquad.chess_char_1_01_a.charId).toBe("char_diy");
    expect(user.chessSquad.chess_char_1_01_a.diyBackupChessId).toBe(
      "chess_char_1_01_a",
    );

    const removed = await mgr.removeChessPoolChar({
      actId: "act2autochess",
      chessId: "chess_char_1_01_a",
    });
    expect(removed.ok).toBe(true);
    const afterRemove =
      player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    expect(afterRemove.chessSquad.chess_char_1_01_a).toBeUndefined();
  });

  it("组队/匹配：createTeam/joinTeam 返回 team；startMatch→queryMatch OK，needLeave 取消", () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    const created = mgr.createTeam({ activityId: "act2autochess", modeId: "mode_single_funny" });
    expect(created.result).toBe(0);
    expect(created.team.teamId).toBeTruthy();
    expect(created.team.serverToken).toBe("mode_single_funny|create");

    const joined = mgr.joinTeam({ activityId: "act2autochess", teamId: "team-x" });
    expect(joined.team.teamId).toBe("team-x");

    const noMatch = mgr.queryMatch({ activityId: "act2autochess" });
    expect(noMatch.result).toBe(1);
    expect(noMatch.team).toBeNull();

    mgr.startMatch({ activityId: "act2autochess", option: { mode: "mode_single_normal" } });
    const matched = mgr.queryMatch({ activityId: "act2autochess" });
    expect(matched.result).toBe(0);
    expect(matched.team?.serverToken).toBe("mode_single_normal");

    const cancelled = mgr.queryMatch({ activityId: "act2autochess", needLeave: 1 });
    expect(cancelled.result).toBe(1);
    expect(cancelled.team).toBeNull();
  });

  it("multiBattleStart→finish→settleGame：excel 驱动 milestone/每日进度/模式解锁，重复结算拒绝", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    await mgr.syncInfo({ actId: "act2autochess" });
    mgr.startMatch({ activityId: "act2autochess", option: { mode: "mode_single_funny" } });

    const start = await mgr.multiBattleStart({
      activityId: "act2autochess",
      sceneId: "act1autochess_m01",
    });
    expect(start.ok).toBe(true);
    if (!start.ok) return;
    expect(start.data.battleId).toBeTruthy();
    expect(start.data.result).toBe(0);

    const finish = mgr.multiBattleFinish({
      activityId: "act2autochess",
      sceneId: "act1autochess_m01",
    });
    expect(finish.ok).toBe(true);

    const settle = await mgr.settleGame({ activityId: "act2autochess" });
    expect(settle.ok).toBe(true);
    if (!settle.ok) return;
    expect(settle.data.result).toBe(0);
    const user = player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    // round1 基础奖励：token=10 / dailyMissionPoint=10
    expect(user.milestone.point).toBe(10);
    expect(user.dailyMission.process).toBe(10);
    // 完成 mode_single_funny 后解锁 mode_single_normal（preposedMode 链）
    expect(user.mode.mode_single_funny.completeCnt).toBe(1);
    expect(user.mode.mode_single_normal.unlock).toBe(1);
    expect(settle.data.gameSettleData?.recordInfos.normalMilestone).toBe(10);

    // 会话已清除，二次结算失败
    const again = await mgr.settleGame({ activityId: "act2autochess" });
    expect(again.ok).toBe(false);
  });

  it("训练模式：startGuideBattle 复用标准战斗；finishGuideBattle 标记 trainingModeFin 并解锁后续模式", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    await mgr.syncInfo({ actId: "act2autochess" });

    const start = await mgr.trainingBattleStart({
      activityId: "act2autochess",
      stageId: "act1autochess_m01",
    });
    expect(start.ok).toBe(true);
    if (!start.ok) return;
    expect(start.data.battleId).toBe("battle-train-1");
    expect(player.battle.start).toHaveBeenCalledOnce();

    const finish = await mgr.trainingBattleFinish({
      activityId: "act2autochess",
      data: "encrypted",
      battleData: { isCheat: "0", completeTime: 123 },
    });
    expect(finish.ok).toBe(true);
    expect(player._playerdata.autochessSeason.trainingModeFin.mode_training_1).toBe(1);
    const user = player._playerdata.activity.AUTOCHESS_SEASON.act2autochess;
    expect(user.mode.mode_training_1.completeCnt).toBe(1);
    expect(user.mode.mode_single_funny.unlock).toBe(1); // preposedMode=mode_training_1
  });

  it("quitSingleGame 清除会话；无效 sceneId 的 multiBattleStart 拒绝", async () => {
    const player = makePlayer();
    const mgr = makeManager(player);
    await mgr.syncInfo({ actId: "act2autochess" });

    const invalid = await mgr.multiBattleStart({
      activityId: "act2autochess",
      sceneId: "no_such_scene",
    });
    expect(invalid.ok).toBe(false);

    mgr.startMatch({ activityId: "act2autochess", option: { mode: "mode_single_funny" } });
    const start = await mgr.multiBattleStart({
      activityId: "act2autochess",
      sceneId: "act1autochess_m01",
    });
    expect(start.ok).toBe(true);
    const quit = mgr.quitSingleGame({
      activityId: "act2autochess",
      sceneId: "act1autochess_m01",
    });
    expect(quit.result).toBe(0);
    expect(quit.battleInfo).toBeNull();
    const sync = await mgr.syncInfo({ actId: "act2autochess" });
    expect(sync.battleInfo).toBeNull();
  });
});
