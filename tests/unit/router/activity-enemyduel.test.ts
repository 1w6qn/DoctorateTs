import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// enemyDuel 结算读取 excel ActivityTable.ENEMY_DUEL.npcData 填充排行榜
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    ActivityTable: {
      activity: {
        ENEMY_DUEL: {
          act1enemyduel: {
            npcData: { act1enemyduel_npc_01: {}, act1enemyduel_npc_02: {} },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import activityRouter from "@game/modules/activities";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("enemyDuel（怪猎对决）路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      activity: {
        ENEMY_DUEL: {
          act1enemyduel: {
            modeInfo: {
              soloOperation: { curStage: "act1enemyduel_01b", highScore: 0, isUnlock: true },
            },
          },
        },
      } as any,
    });
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    activityRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /enemyDuel/singleBattleStart 应返回 battleId stub", async () => {
    await call("/enemyDuel/singleBattleStart", { activityId: "act1enemyduel", modeId: "soloOperation" });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toBe(0);
    expect(typeof sent.battleId).toBe("string");
    expect(sent.battleId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("POST /enemyDuel/singleBattleFinish 应返回玩家成绩 + 活动表 NPC 填充排行榜", async () => {
    await call("/enemyDuel/singleBattleFinish", {
      activityId: "act1enemyduel",
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
      settle: { rankList: [{ id: "1", rank: 1, score: 1919810, isPlayer: 1 }] },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toBe(0);
    // 玩家 + 2 个 NPC 填充
    expect(sent.rankList).toHaveLength(3);
    expect(sent.rankList[0]).toEqual({ id: "1", rank: 1, score: 1919810, isPlayer: 1 });
    expect(sent.rankList[1]).toEqual({ id: "act1enemyduel_npc_01", rank: 2, score: 0, isPlayer: 0 });
    expect(sent.choiceCnt).toEqual({ skip: 0, normal: 5, allIn: 1 });
    expect(sent.isHighScore).toBe(false);
    expect(sent.dailyMission).toEqual({ add: 0, reward: 0 });
    expect(sent.bp).toBe(0);
  });

  it("POST /enemyDuel/startMatch + queryMatch 应返回队伍信息（serverToken = modeId|curStage）", async () => {
    await call("/enemyDuel/startMatch", { activityId: "act1enemyduel", modeId: "soloOperation" });
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ result: 0 }));

    await call("/enemyDuel/queryMatch", { activityId: "act1enemyduel", needLeave: false });
    const sent = res.send.mock.calls[1][0];
    expect(sent.result).toBe(0);
    expect(sent.team.serverToken).toBe("soloOperation|act1enemyduel_01b");
    expect(sent.team.serverAddress).toContain(":");
    expect(sent.playerCnt).toBe(8);
  });

  it("POST /enemyDuel/queryMatch needLeave 应返回 result 1 team null", async () => {
    await call("/enemyDuel/queryMatch", { activityId: "act1enemyduel", needLeave: true });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1, team: null, playerCnt: 0 })
    );
  });

  it("POST /enemyDuel/createTeam / joinTeam 应返回队伍 stub", async () => {
    await call("/enemyDuel/createTeam", { activityId: "act1enemyduel", modeId: "multiOperationMatch" });
    const created = res.send.mock.calls[0][0];
    expect(created.result).toBe(0);
    expect(created.team.serverToken).toBe("multiOperationMatch|create");

    await call("/enemyDuel/joinTeam", { activityId: "act1enemyduel", teamId: "team-123" });
    const joined = res.send.mock.calls[1][0];
    expect(joined.result).toBe(0);
    expect(joined.team.teamId).toBe("team-123");
  });

  it("POST /enemyDuel/multiBattleStart / multiBattleFinish 应返回对应 stub", async () => {
    await call("/enemyDuel/multiBattleStart", { activityId: "act1enemyduel", sceneId: "scene_1" });
    const startSent = res.send.mock.calls[0][0];
    expect(startSent.result).toBe(0);
    expect(typeof startSent.battleId).toBe("string");

    await call("/enemyDuel/multiBattleFinish", {
      activityId: "act1enemyduel",
      sceneId: "scene_1",
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    const finishSent = res.send.mock.calls[1][0];
    expect(finishSent.result).toBe(0);
    expect(finishSent.rankList.length).toBeGreaterThanOrEqual(1);
    expect(finishSent.rankList[0].isPlayer).toBe(1);
  });
});
