import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

const timeMock = vi.hoisted(() => ({ now: 1735000000 })); // tower_season_1 时段内
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

// 保全派驻数据（climb_tower_table）：首通奖励档 / 上限常量 / 层号 / 赛季任务
vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    CharacterTable: {
      char_sniper: { charId: "char_sniper", profession: "SNIPER", rarity: "TIER_4" },
    },

    ClimbTowerTable: {
      rewardInfoList: [
        { stageSort: 1, lowerItemCount: 2, higherItemCount: 0 },
        { stageSort: 2, lowerItemCount: 3, higherItemCount: 1 },
        { stageSort: 3, lowerItemCount: 3, higherItemCount: 2 },
        { stageSort: 4, lowerItemCount: 4, higherItemCount: 2 },
        { stageSort: 5, lowerItemCount: 4, higherItemCount: 2 },
        { stageSort: 6, lowerItemCount: 4, higherItemCount: 3 },
      ],
      rewardInfoListHardMode: [
        { stageSort: 1, lowerItemCount: 4, higherItemCount: 0 },
      ],
      detailConst: {
        lowerItemId: "mod_update_token_1",
        lowerItemLimit: 60,
        higherItemId: "mod_update_token_2",
        higherItemLimit: 24,
        sweepCostCount: 2,
        subcardStageSort: 4,
      },
      levels: {
        lt_17_01: { id: "lt_17_01", layerNum: 1 },
        lt_17_02: { id: "lt_17_02", layerNum: 2 },
        lt_17_03: { id: "lt_17_03", layerNum: 3 },
      },
      towers: {
        tower_n_17: { id: "tower_n_17", levels: ["lt_17_01", "lt_17_02", "lt_17_03"] },
        tower_n_16: { id: "tower_n_16", levels: ["lt_17_01", "lt_17_02", "lt_17_03"] },
      },
      seasonInfos: {
        tower_season_1: { id: "tower_season_1", seasonNum: 1, startTs: 1730000000, endTs: 1740000000, towers: ["tower_n_17"] },
      },
      missionGroup: {
        tower_season_1: { id: "tower_season_1", missionIds: ["tower_season1_1", "tower_season1_7"] },
      },
      missionData: {
        tower_season1_1: {
          id: "tower_season1_1", template: "TowerCardPassLayer", param: ["0", "card_01", "3"],
          rewards: [{ type: "MATERIAL", id: "30104", count: 2 }],
        },
        tower_season1_7: {
          id: "tower_season1_7", template: "TowerRecruit", param: ["0", "2", "SNIPER"],
          rewards: [{ type: "GOLD", id: "4001", count: 20000 }],
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import towerRouter from "@game/modules/tower/routes";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("tower（保全派驻）奖励与记录落盘", () => {
  let player: any;
  let res: any;

  function makePlayer(extra: any = {}) {
    return mockPlayerData({
      inventory: {},
      tower: {
        current: { layer: [], cards: {}, godCard: { id: "", subGodCardId: "" }, trap: [], halftime: { count: 0, candidate: [], canGiveUp: false }, status: { state: "NONE", tower: "", coord: 0, isHard: false } },
        outer: {},
        season: {},
      },
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
    towerRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("layerReward：按 rewardInfoList 发首通奖励并记录已领层（不再是 202 空响应）", async () => {
    await call("/layerReward", { tower: "tower_n_17", layers: [1, 2] });
    // 修复点：返回 JSON delta，而不是 sendStatus(202)
    expect(res.sendStatus).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalled();
    const inv = player._playerdata.inventory;
    expect(inv.mod_update_token_1).toBe(5); // 2 + 3
    expect(inv.mod_update_token_2).toBe(1); // 0 + 1
    expect(player._playerdata.tower.outer.towers.tower_n_17.reward).toEqual([1, 2]);
    expect(player._trigger.emit).toHaveBeenCalledWith("items:get", [[
      { id: "mod_update_token_1", count: 5, type: "MATERIAL" },
      { id: "mod_update_token_2", count: 1, type: "MATERIAL" },
    ]]);
  });

  it("layerReward：同一层不重复发放", async () => {
    await call("/layerReward", { tower: "tower_n_17", layers: [1] });
    await call("/layerReward", { tower: "tower_n_17", layers: [1] });
    expect(player._playerdata.inventory.mod_update_token_1).toBe(2);
    expect(player._playerdata.tower.outer.towers.tower_n_17.reward).toEqual([1]);
  });

  it("layerReward：层号可用关卡 id 表达（levels[].layerNum），且受 detailConst 上限封顶", async () => {
    player = makePlayer({ inventory: { mod_update_token_1: 59, } });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/layerReward", { tower: "tower_n_17", layers: ["lt_17_02"] });
    // 第 2 层应发 3 个，但只剩 1 个额度
    expect(player._playerdata.inventory.mod_update_token_1).toBe(60);
    expect(player._playerdata.tower.outer.towers.tower_n_17.reward).toEqual([2]);
  });

  it("seasonMissionsAward：达成任务发奖并置 hasRecv（不再是 202）", async () => {
    player = makePlayer({
      tower: {
        current: { layer: [], cards: {}, godCard: { id: "", subGodCardId: "" }, trap: [], halftime: { count: 0, candidate: [], canGiveUp: false }, status: { state: "NONE", tower: "", coord: 0, isHard: false } },
        outer: {},
        season: { id: "tower_season_1", missions: { tower_season1_1: { value: 1, target: 1, hasRecv: false } } },
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/seasonMissionsAward", {});
    expect(res.sendStatus).not.toHaveBeenCalled();
    expect(player._playerdata.tower.season.missions.tower_season1_1.hasRecv).toBe(true);
    expect(player._trigger.emit).toHaveBeenCalledWith("items:get", [[
      { id: "30104", count: 2, type: "MATERIAL" },
    ]]);
  });

  it("settleGame：写 best/unlockHard/canSweep/hasTowerPass 并结算首通奖励", async () => {
    player = makePlayer({
      tower: {
        current: {
          layer: [
            { id: "lt_17_01", tryNum: 1, pass: 1 },
            { id: "lt_17_02", tryNum: 1, pass: 1 },
            { id: "lt_17_03", tryNum: 1, pass: 1 },
          ],
          cards: {},
          godCard: { id: "card_01", subGodCardId: "" },
          trap: [],
          halftime: { count: 0, candidate: [], canGiveUp: false },
          status: { state: "END", tower: "tower_n_17", coord: 3, isHard: false },
          reward: { high: 0, low: 0 },
        },
        outer: {},
        season: {},
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/settleGame", {});
    const sent = res.send.mock.calls[0][0];
    // 全 3 层首通：low = 2+3+3 = 8，high = 0+1+2 = 3
    expect(sent.reward.low).toEqual({ cnt: 8, from: 0, to: 8 });
    expect(sent.reward.high).toEqual({ cnt: 3, from: 0, to: 3 });
    const rec = player._playerdata.tower.outer.towers.tower_n_17;
    expect(rec.best).toBe(3);
    expect(rec.reward).toEqual([1, 2, 3]);
    expect(rec.unlockHard).toBe(true);
    expect(rec.canSweep).toBe(true);
    expect(player._playerdata.tower.outer.hasTowerPass).toBe(1);
    expect(player._playerdata.tower.season.passWithGodCard.card_01).toEqual(["tower_n_17"]);
    // 赛季任务推进：TowerCardPassLayer(param 阈值 3，神卡 card_01) 达成
    expect(player._playerdata.tower.season.missions.tower_season1_1.value).toBe(1);
  });

  it("settleGame：非当期赛季的塔不解锁扫荡", async () => {
    player = makePlayer({
      tower: {
        current: {
          // 3 层塔只通了 1 层（未全通）
          layer: [
            { id: "lt_17_01", tryNum: 1, pass: 1 },
            { id: "lt_17_02", tryNum: 0, pass: 0 },
            { id: "lt_17_03", tryNum: 0, pass: 0 },
          ],
          cards: {},
          godCard: { id: "card_01", subGodCardId: "" },
          trap: [],
          halftime: { count: 0, candidate: [], canGiveUp: false },
          status: { state: "END", tower: "tower_n_16", coord: 1, isHard: false },
        },
        outer: {},
        season: {},
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/settleGame", {});
    const rec = player._playerdata.tower.outer.towers.tower_n_16;
    expect(rec.best).toBe(1);
    expect(rec.canSweep).toBeUndefined();
    expect(rec.unlockHard).toBe(false);
  });

  it("sweepGame：未解锁扫荡时拒绝；解锁后一次性领取全部未领层", async () => {
    await call("/sweepGame", { tower: "tower_n_17" });
    expect(res.send.mock.calls[0][0].result).toBe(1);
    expect(res.sendStatus).not.toHaveBeenCalled();

    player._playerdata.tower.outer.towers = {
      tower_n_17: { best: 3, reward: [1], unlockHard: true, hardBest: 0, canSweep: true },
    };
    await call("/sweepGame", { tower: "tower_n_17" });
    // 第 2、3 层：low 3+3=6，high 1+2=3
    expect(player._playerdata.inventory.mod_update_token_1).toBe(6);
    expect(player._playerdata.inventory.mod_update_token_2).toBe(3);
    expect(player._playerdata.tower.outer.towers.tower_n_17.reward).toEqual([1, 2, 3]);
  });

  it("recruit：按干员职业推进 TowerRecruit 赛季任务", async () => {
    player = makePlayer({
      troop: { chars: { "9": { instId: 9, charId: "char_sniper", evolvePhase: 0, level: 1, skills: [] } } },
      tower: {
        current: {
          layer: [],
          cards: {},
          godCard: { id: "card_01", subGodCardId: "" },
          trap: [],
          halftime: { count: 0, candidate: [], canGiveUp: false },
          status: { state: "RECRUIT", tower: "tower_n_17", coord: 1, isHard: false },
        },
        outer: {},
        season: { id: "tower_season_1", missions: { tower_season1_7: { value: 0, target: 2, hasRecv: false } } },
      },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    await call("/recruit", { charId: "char_sniper", giveUp: 0 });
    expect(player._playerdata.tower.season.missions.tower_season1_7.value).toBe(1);
  });
});
