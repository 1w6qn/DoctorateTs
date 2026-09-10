import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

const timeMock = vi.hoisted(() => ({ now: 1735000000 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

// 危机合约赛季数据来自 data/crisis{2}/*.json（readJson）；测试用固定夹具替换文件读取
const filesMock = vi.hoisted(() => ({
  v1: {
    ts: 0,
    data: {
      seasonInfo: [{ seasonId: "rune_season_1_1", stages: {}, permStageGroup: [] }],
      trainingInfo: {},
      runeInfoList: {},
      stageRune: { "level_rune_03-01": { rune_a: { points: 4 } } },
    },
  },
  v2: {
    info: {
      seasonId: "crisis_v2_season_1_1",
      mapStageDataMap: {
        crisis_v2_01_01: { mapId: "crisis_v2_01_01", stageType: "PERMANENT" },
        crisis_v2_01_02: { mapId: "crisis_v2_01_02", stageType: "TEMPORARY" },
      },
      mapDetailDataMap: {
        crisis_v2_01_01: {
          nodeDataMap: {
            node_1: { slotPackId: "pack_1", mutualExclusionGroup: "g1", runeId: "rune_1" },
          },
          runeDataMap: { rune_1: { score: 10, dimension: 0 } },
          bagDataMap: {
            pack_1: { slotPackId: "pack_1", dimension: 0, rewardScore: 5 },
          },
          // 挑战节点条件（官服仅 PassWithDimScore / PassWithRunes 两类）
          challengeNodeDataMap: {
            keypoint_1: { missionType: "PassWithDimScore", missionParamList: ["0;1;2;3;4;5", "10"] },
            keypoint_2: { missionType: "PassWithRunes", missionParamList: ["node_1", "1"] },
            keypoint_3: { missionType: "PassWithRunes", missionParamList: ["node_1", "2"] },
          },
        },
      },
    },
  },
}));
// 部分 mock：仅替换赛季数据读取（readJson），保留 config 依赖的 readJsonSync
vi.mock("@utils/file", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@utils/file")>();
  return {
    ...actual,
    readJson: vi.fn(async (p: string) =>
      p.includes("crisisV2") ? filesMock.v2 : filesMock.v1),
  };
});
vi.mock("./crisis-seasons", () => ({
  listCrisisSeasons: vi.fn(async () => ({ v1: ["cc1"], v2: ["cc1"] })),
  CRISIS_JSON_BASE_PATH: "data/crisis/",
  CRISIS_V2_JSON_BASE_PATH: "data/crisisV2/",
}));
vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
  },
}));

import httpContext from "express-http-context2";
import crisisRouter from "@game/modules/crisis/routes";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

/** 构造一个完成任务 + 一个未完成任务的赛季挑战表 */
function challengeWithTasks() {
  return {
    taskList: {
      doneTask: { fts: 100, rts: -1 },
      freshTask: { fts: -1, rts: -1 },
    },
  };
}

describe("crisis（危机合约）分数/点数落盘与领取标记", () => {
  let player: any;
  let res: any;

  function makePlayer(extra: any = {}) {
    return mockPlayerData({
      crisis: { season: {} },
      crisisV2: { seasons: {}, shop: { coin: 666, info: [] } },
      ...extra,
    } as any);
  }

  beforeEach(() => {
    vi.clearAllMocks();
    player = makePlayer();
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    crisisRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 30));
  }

  it("v2/battleFinish：永久图写入 scoreSingle 并返回 isNewRecord/newRecordTs", async () => {
    // 选 node_1 → 指标集 pack_1 满足（rewardScore 5）+ 符文 rune_1（score 10）→ 维度 0 共 15 分
    await call("/v2/battleStart", { mapId: "crisis_v2_01_01", runeSlots: ["node_1"] });
    await call("/v2/battleFinish", {});
    const sent = res.send.mock.calls.at(-1)![0];
    expect(sent.scoreCurrent[0]).toBe(15);
    expect(sent.isNewRecord).toBe(true);
    expect(sent.scoreRecord).toEqual([15, 0, 0, 0, 0, 0]);
    const perm = player._playerdata.crisisV2.seasons.crisis_v2_season_1_1.permanent;
    expect(perm.state).toBe(1);
    expect(perm.scoreSingle).toEqual([15, 0, 0, 0, 0, 0]);
    expect(player._playerdata.crisisV2.newRecordTs).toBe(timeMock.now);
  });

  it("v2/battleFinish：临时图写入 temporary[mapId].scoreTotal（不碰永久记录）", async () => {
    await call("/v2/battleStart", { mapId: "crisis_v2_01_02", runeSlots: [] });
    await call("/v2/battleFinish", {});
    const season = player._playerdata.crisisV2.seasons.crisis_v2_season_1_1;
    const map = season.temporary.crisis_v2_01_02;
    expect(map.state).toBe(1);
    expect(map.scoreTotal).toEqual([0, 0, 0, 0, 0, 0]);
    // 永久记录未被这次临时图作战改写（state 仍为初始 0）
    expect(season.permanent.state).toBe(0);
  });

  it("v2/battleFinish：同分重复作战不再算新纪录", async () => {
    await call("/v2/battleStart", { mapId: "crisis_v2_01_01", runeSlots: ["node_1"] });
    await call("/v2/battleFinish", {});
    await call("/v2/battleStart", { mapId: "crisis_v2_01_01", runeSlots: ["node_1"] });
    await call("/v2/battleFinish", {});
    const sent = res.send.mock.calls.at(-1)![0];
    expect(sent.isNewRecord).toBe(false);
    expect(sent.scoreRecord).toEqual([15, 0, 0, 0, 0, 0]);
  });

  it("battleFinish（V1）：风险点数写入 permanent.point / topPoint 并回填 before/after", async () => {
    // rune_a 风险点数 4（对应官服存档 point = 4）
    await call("/battleStart", { stageId: "level_rune_03-01", rune: ["rune_a"] });
    await call("/battleFinish", {});
    const sent = res.send.mock.calls.at(-1)![0];
    expect(sent.score).toBe(4);
    expect(sent.updateInfo.point).toEqual({ before: -1, after: 4 });
    const perm = player._playerdata.crisis.season.rune_season_1_1.permanent;
    expect(perm.point).toBe(4);
    expect(perm.challenge.topPoint).toBe(4);
    // 记录只增不减：再打一次低风险不改动
    await call("/battleStart", { stageId: "level_rune_03-01", rune: [] });
    await call("/battleFinish", {});
    expect(
      player._playerdata.crisis.season.rune_season_1_1.permanent.point,
    ).toBe(4);
  });

  // 勋章（2026-09-09 修复）：危机合约批次此前零 emit —— 监听器虽注册却无事件可收，
  // 叠加 unlockParam 目标位取错（param[0] 是赛季 id）→ 该类勋章永不可得。
  it("battleFinish（V1）：派发 CrisisStageScoreSome / CrisisStageScoreBeforeTime（含赛季+关卡）", async () => {
    await call("/battleStart", { stageId: "level_rune_03-01", rune: ["rune_a"] });
    await call("/battleFinish", {});
    const emitted = (player._trigger.emit as any).mock.calls.map((c: any[]) => c[0]);
    expect(emitted).toContain("CrisisStageScoreSome");
    expect(emitted).toContain("CrisisStageScoreBeforeTime");
    const arg = (player._trigger.emit as any).mock.calls.find(
      (c: any[]) => c[0] === "CrisisStageScoreSome",
    )![1][0];
    expect(arg).toEqual({
      seasonId: "rune_season_1_1",
      stageId: "level_rune_03-01",
      score: 4,
    });
  });

  it("unlockRune：仅首次解锁派发 CrisisUnlockPermRuneSome（重复请求不刷进度）", async () => {
    player = makePlayer({
      crisis: { season: { rune_season_1_1: { permanent: { rune: {} } } } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/unlockRune", { seasonId: "rune_season_1_1", runeId: "enemy_reid_3" });
    let calls = (player._trigger.emit as any).mock.calls.filter(
      (c: any[]) => c[0] === "CrisisUnlockPermRuneSome",
    );
    expect(calls).toHaveLength(1);
    expect(calls[0][1][0]).toEqual({
      seasonId: "rune_season_1_1",
      runeId: "enemy_reid_3",
      count: 1,
    });
    // 重复解锁同一词条：不再派发
    await call("/unlockRune", { seasonId: "rune_season_1_1", runeId: "enemy_reid_3" });
    calls = (player._trigger.emit as any).mock.calls.filter(
      (c: any[]) => c[0] === "CrisisUnlockPermRuneSome",
    );
    expect(calls).toHaveLength(1);
  });

  it("challengeRewardTask：仅实际领取时派发 CrisisTaskSome", async () => {
    player = makePlayer({
      crisis: {
        season: { rune_season_1_1: { permanent: { challenge: challengeWithTasks() } } },
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/challengeRewardTask", { seasonId: "rune_season_1_1", taskId: "freshTask" });
    expect(
      (player._trigger.emit as any).mock.calls.filter(
        (c: any[]) => c[0] === "CrisisTaskSome",
      ),
    ).toHaveLength(0);
    await call("/challengeRewardTask", { seasonId: "rune_season_1_1", taskId: "doneTask" });
    const calls = (player._trigger.emit as any).mock.calls.filter(
      (c: any[]) => c[0] === "CrisisTaskSome",
    );
    expect(calls).toHaveLength(1);
    expect(calls[0][1][0]).toEqual({
      seasonId: "rune_season_1_1",
      taskId: "doneTask",
      count: 1,
    });
  });

  it("v2/battleFinish：派发 CrisisV2DimScoreSome（各维峰值）与 CrisisV2DimScoreTotal（各维之和）", async () => {
    await call("/v2/battleStart", { mapId: "crisis_v2_01_01", runeSlots: ["node_1"] });
    await call("/v2/battleFinish", {});
    const calls = (player._trigger.emit as any).mock.calls;
    const some = calls.find((c: any[]) => c[0] === "CrisisV2DimScoreSome")!;
    const total = calls.find((c: any[]) => c[0] === "CrisisV2DimScoreTotal")!;
    expect(some[1][0]).toEqual({
      seasonId: "crisis_v2_season_1_1",
      mapId: "crisis_v2_01_01",
      score: 15,
    });
    expect(total[1][0]).toEqual({
      seasonId: "crisis_v2_season_1_1",
      mapId: "crisis_v2_01_01",
      score: 15,
    });
    // 未携带助战 → 不派发 CrisisV2UseAssist
    expect(calls.some((c: any[]) => c[0] === "CrisisV2UseAssist")).toBe(false);
  });

  it("v2/battleFinish：battleStart 携带 assistFriend 时派发 CrisisV2UseAssist", async () => {
    await call("/v2/battleStart", {
      mapId: "crisis_v2_01_01",
      runeSlots: ["node_1"],
      assistFriend: { uid: "2" },
    });
    await call("/v2/battleFinish", {});
    const call2 = (player._trigger.emit as any).mock.calls.find(
      (c: any[]) => c[0] === "CrisisV2UseAssist",
    );
    expect(call2).toBeTruthy();
    expect(call2[1][0]).toEqual({ seasonId: "crisis_v2_season_1_1", used: 1 });
  });

  // 勋章（2026-09-09 修复，Round 31）：CrisisV2NodeSome 的节点记录（challenge / runePack）
  // 此前**从不写入** —— 需按地图 challengeNodeDataMap 条件对单局战绩求值。
  it("v2/battleFinish：按挑战节点条件写入 challenge/runePack 并派发 CrisisV2NodeSome 节点全集", async () => {
    // node_1 → 指标集 pack_1 满足（rewardScore 5）+ 符文 rune_1（score 10）→ 维度 0 共 15 分
    await call("/v2/battleStart", { mapId: "crisis_v2_01_01", runeSlots: ["node_1"] });
    await call("/v2/battleFinish", {});
    const perm = player._playerdata.crisisV2.seasons.crisis_v2_season_1_1.permanent;
    // keypoint_1（任一维 ≥10，实测 15）/ keypoint_2（携带 node_1 ≥1）达成；keypoint_3 需 2 个未达成
    expect(perm.challenge).toEqual({ keypoint_1: 2, keypoint_2: 2 });
    // 指标集满足 → runePack 记 2（官服存档实证已完成值 = 2）
    expect(perm.runePack).toEqual({ pack_1: 2 });
    const call2 = (player._trigger.emit as any).mock.calls.find(
      (c: any[]) => c[0] === "CrisisV2NodeSome",
    );
    expect(call2[1][0].seasonId).toBe("crisis_v2_season_1_1");
    expect(call2[1][0].nodeIds.sort()).toEqual([
      "crisis_v2_01_01^keypoint_1",
      "crisis_v2_01_01^keypoint_2",
      "crisis_v2_01_01^pack_1",
    ]);
  });

  it("v2/battleFinish：轮换测试地节点写入 temporary[mapId].challenge（主测试地记录不受影响）", async () => {
    await call("/v2/battleStart", { mapId: "crisis_v2_01_02", runeSlots: [] });
    await call("/v2/battleFinish", {});
    const season = player._playerdata.crisisV2.seasons.crisis_v2_season_1_1;
    // 无符文 → 得分 0，keypoint_1（≥10）不达成；且该图无 challengeNodeDataMap 时不应报错
    expect(season.temporary.crisis_v2_01_02.challenge).toEqual({});
    expect(season.permanent.challenge ?? {}).toEqual({});
    const call2 = (player._trigger.emit as any).mock.calls.find(
      (c: any[]) => c[0] === "CrisisV2NodeSome",
    );
    expect(call2[1][0].nodeIds).toEqual([]);
  });

  it("challengeRewardPoint：领取标记写时间戳而非字面量 1，且不可重复领取", async () => {
    player = makePlayer({
      crisis: { season: { rune_season_1_1: { permanent: { challenge: { pointList: { "1": -1, "2": -1 } } } } } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/challengeRewardPoint", { seasonId: "rune_season_1_1", pointId: "1" });
    const list = player._playerdata.crisis.season.rune_season_1_1.permanent.challenge.pointList;
    expect(list["1"]).toBe(timeMock.now);
    expect(list["2"]).toBe(-1);
    await call("/challengeRewardPoint", { seasonId: "rune_season_1_1", pointId: "1" });
    expect(list["1"]).toBe(timeMock.now);
  });

  it("challengeRewardTask：未完成（fts=-1）的任务不可领取，已完成的可领取", async () => {
    player = makePlayer({
      crisis: {
        season: { rune_season_1_1: { permanent: { challenge: challengeWithTasks() } } },
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    /** mockPlayerData.update 会整体替换 crisis 子树，故每次断言前重新读取 */
    const tasksOf = () =>
      player._playerdata.crisis.season.rune_season_1_1.permanent.challenge.taskList;
    await call("/challengeRewardTask", { seasonId: "rune_season_1_1", taskId: "freshTask" });
    expect(tasksOf().freshTask.rts).toBe(-1);
    await call("/challengeRewardTask", { seasonId: "rune_season_1_1", taskId: "doneTask" });
    expect(tasksOf().doneTask.rts).toBe(timeMock.now);
    // 已领取不再变动
    await call("/challengeRewardTask", { seasonId: "rune_season_1_1", taskId: "doneTask" });
    expect(tasksOf().doneTask.rts).toBe(timeMock.now);
  });
});
