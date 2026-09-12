import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// act1vhalfidle 任命/产出/科技全部读活动配置（ActivityTable.activity.halfidleVerify1.act1vhalfidle）
/** excel mock 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 干员行夹具形状（本文件用到的字段子集） */
interface ExcelCharRowMock {
  charId?: string;
  rarity?: string;
  profession?: string;
}

vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: undefined as { items?: Record<string, ExcelRowMock> } | undefined,
    StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelCharRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },

    CharacterTable: {
      char_pac_a: { charId: "char_pac_a", rarity: "TIER_4" },
      char_pac_b: { charId: "char_pac_b", rarity: "TIER_6" },
      char_new_1: { charId: "char_new_1", rarity: "TIER_6" },
      char_dir_1: { charId: "char_dir_1", rarity: "TIER_6" },
      char_dir_2: { charId: "char_dir_2", rarity: "TIER_6" },
      char_norm_ok: { charId: "char_norm_ok", rarity: "TIER_4" },
      char_norm_low: { charId: "char_norm_low", rarity: "TIER_2" },
      char_link_owned: { charId: "char_link_owned", rarity: "TIER_5" },
      char_link_missing: { charId: "char_link_missing", rarity: "TIER_5" },
    } as Record<string, ExcelCharRowMock>,

    ActivityTable: {
      activity: {
        halfidleVerify1: {
          act1vhalfidle: {
            gachaPoolData: {
              normalGachaPool: {
                poolId: "normalGachaPool",
                itemId: "gacha_normal",
                poolType: "GACHA_NORMAL",
                name: "随机任命",
                charData: [],
                consumeData: [{ gachaTimes: 1, consume: 20 }],
              },
              newPlayerGachaPool: {
                poolId: "newPlayerGachaPool",
                itemId: "gacha_newplayer",
                poolType: "GACHA_NEWPLAYER",
                name: "专项任命",
                charData: ["char_new_1"],
                consumeData: [{ gachaTimes: 1, consume: 1 }],
              },
              gachaPac1: {
                poolId: "gachaPac1",
                itemId: "gacha_pac1",
                poolType: "GACHA_PAC",
                name: "标准机动密令·α",
                charData: ["char_pac_a", "char_pac_b"],
                consumeData: [{ gachaTimes: 1, consume: 1 }],
              },
              directionGachaPool: {
                poolId: "directionGachaPool",
                itemId: "gacha_direct",
                poolType: "GACHA_DIRECT",
                name: "特约任命",
                charData: ["char_dir_1", "char_dir_2"],
                consumeData: [
                  { gachaTimes: 1, consume: 100 },
                  { gachaTimes: 2, consume: 150 },
                  { gachaTimes: 3, consume: 150 },
                  { gachaTimes: 4, consume: 200 },
                ],
              },
            },
            gachaCharData: {
              char_norm_ok: { charId: "char_norm_ok", isLinkageChar: false },
              char_norm_low: { charId: "char_norm_low", isLinkageChar: false },
              char_pac_a: { charId: "char_pac_a", isLinkageChar: false },
              char_new_1: { charId: "char_new_1", isLinkageChar: false },
              char_link_owned: { charId: "char_link_owned", isLinkageChar: true },
              char_link_missing: { charId: "char_link_missing", isLinkageChar: true },
            },
            stageProductionData: {
              act1halfidle_01: {
                stageId: "act1halfidle_01",
                fixedProduction: ["act1vhalfidle_token_point", "level_exp"],
                productionData: {
                  act1vhalfidle_token_point: { itemId: "act1vhalfidle_token_point", efficiencyMax: 300, isFixed: true, maxDropValue: 300 },
                  level_exp: { itemId: "level_exp", efficiencyMax: 24000, isFixed: true, maxDropValue: 24000 },
                  gacha_normal: { itemId: "gacha_normal", efficiencyMax: 15, isFixed: false, maxDropValue: 15 },
                  asc_pio: { itemId: "asc_pio", efficiencyMax: 0, isFixed: false, maxDropValue: 0 },
                },
              },
              act1halfidle_02: {
                stageId: "act1halfidle_02",
                fixedProduction: ["act1vhalfidle_token_point", "level_exp"],
                productionData: {
                  act1vhalfidle_token_point: { itemId: "act1vhalfidle_token_point", efficiencyMax: 300, isFixed: true, maxDropValue: 300 },
                  level_exp: { itemId: "level_exp", efficiencyMax: 30000, isFixed: true, maxDropValue: 30000 },
                  gacha_normal: { itemId: "gacha_normal", efficiencyMax: 16, isFixed: false, maxDropValue: 16 },
                },
              },
            },
            techTreeData: {
              node_1_1: { nodeId: "node_1_1", nodeType: "NORMAL", prevNodeId: null, tokenCost: 50, name: "地形改造" },
              node_1_2: { nodeId: "node_1_2", nodeType: "NORMAL", prevNodeId: ["node_1_1"], tokenCost: 50, name: "标准机动组·α" },
            },
            charMaxRankData: {
              TIER_4: {
                maxEvolvePhase: 2,
                maxRankData: {
                  PHASE_0: { evolvePhase: 0, maxLevel: 45, maxSkillRank: 4 },
                  PHASE_1: { evolvePhase: 1, maxLevel: 60, maxSkillRank: 7 },
                  PHASE_2: { evolvePhase: 2, maxLevel: 70, maxSkillRank: 10 },
                },
              },
              TIER_6: {
                maxEvolvePhase: 2,
                maxRankData: {
                  PHASE_0: { evolvePhase: 0, maxLevel: 50, maxSkillRank: 4 },
                  PHASE_1: { evolvePhase: 1, maxLevel: 80, maxSkillRank: 7 },
                  PHASE_2: { evolvePhase: 2, maxLevel: 90, maxSkillRank: 10 },
                },
              },
            },
            milestoneList: [{ milestoneId: "mileStone_1", orderId: 1, tokenNum: 1200 }],
            constData: {
              normalStageIds: ["act1halfidle_01"],
              hardStageIds: ["act1halfidle_02"],
              productMaxEfficiencyDict: {
                act1vhalfidle_token_point: 600,
                level_exp: 54000,
                gacha_normal: 31,
                asc_pio: 0,
              },
              milestoneId: "act1vhalfidle_token_point",
              techCostItemId: "strategy_point",
              levelExpItemId: "level_exp",
              skillExpItemId: "skill_exp",
              produceCd: 900,
              efficiencyDurationMax: 172800,
            },
          },
        },
      },
    },
  },
}));

import type { Response } from "express";
import httpContext from "express-http-context2";
import activityRouter from "@game/modules/activities";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager, MockPlayerDataSeed } from "../../helpers";

/** 次生预案请求体视图（本文件各端点用到的字段集合） */
interface HalfIdleBody {
  activityId?: string;
  poolId?: string;
  count?: number;
  charId?: string;
  stageId?: string;
  techId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: HalfIdleBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/** 半挂机 troop.chars 干员条目读取视图（字段面与 R1 覆盖一致） */
interface HalfIdleCharView {
  instId?: number;
  charId?: string;
  level?: number;
  skillLvl?: number;
  skillLvlWithSpec?: number;
  evolvePhase?: number;
  isAssist?: number;
  defaultSkillId?: string;
  defaultEquipId?: string;
}

/**
 * HALFIDLE_VERIFY1 活动子树读取视图
 *
 * `PlayerActivity` 的具名键与兜底索引签名取交集，兜底值为两层 `ServerPayload`，
 * 而本活动的 `production` / `stage` / `settleInfo` / `recruit` 是三层结构，
 * 故夹具无法经 `mockPlayerData` 种子写入（TS2345）。这里按 R1 覆盖的字段面就地声明
 * 读取视图（键名与类型与 `scripts/playerdata-server-adapt.ts` 的 HALFIDLE_VERIFY1 覆盖一致），
 * 运行期键与值一字不改。
 */
interface HalfIdleView {
  coin?: number;
  globalBan?: number;
  troop?: { chars?: { [instId: string]: HalfIdleCharView }; trap?: string[]; npc?: string[]; extraAssist?: number };
  stage?: { [stageId: string]: { rate?: { [itemId: string]: number }; bossState?: number } };
  settleInfo?: { rate?: { [itemId: string]: number }; bossState?: number; stageId?: string; progress?: number };
  production?: {
    rate?: { [itemId: string]: number };
    product?: { [itemId: string]: number };
    harvestTs?: number;
    refreshTs?: number;
  };
  recruit?: { poolGain?: { [poolId: string]: string[] }; poolTimes?: { [poolId: string]: number } };
  milestone?: { point?: number; got?: string[] };
  inventory?: { [itemId: string]: number };
  tech?: { unlock?: string[] };
}

interface HalfIdleActivityView {
  HALFIDLE_VERIFY1?: { [actId: string]: HalfIdleView };
}

type RouterReq = Parameters<typeof activityRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

describe("act1vhalfidle（次生预案）路由", () => {
  let player: MockPlayerDataManager;
  let res: MockRes;

  function makePlayer(
    halfIdleData: HalfIdleView,
    extra: Omit<MockPlayerDataSeed, "activity" | "troop"> = {},
  ): MockPlayerDataManager {
    const made = mockPlayerData({ troop: { chars: {} }, activity: {}, ...extra });
    // 与旧夹具同形：activity.HALFIDLE_VERIFY1.act1vhalfidle = 传入的活动数据（同一对象引用）
    (made._playerdata.activity as HalfIdleActivityView).HALFIDLE_VERIFY1 = { act1vhalfidle: halfIdleData };
    return made;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    player = makePlayer({});
    res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
  });

  async function call(url: string, body: HalfIdleBody) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    activityRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  /** 读取 HALFIDLE_VERIFY1 活动数据（见 HalfIdleActivityView 的说明） */
  function halfIdle(): HalfIdleView {
    return (player._playerdata.activity as HalfIdleActivityView).HALFIDLE_VERIFY1!.act1vhalfidle!;
  }

  it("recruitNormal：机动密令不足时不消耗、不给干员", async () => {
    player = makePlayer({
      inventory: { gacha_pac1: 0, gacha_normal: 0 },
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/recruitNormal", { activityId: "act1vhalfidle", poolId: "gachaPac1", count: 1 });
    expect(vi.mocked(res.send).mock.calls[0][0].result).toBe(1);
    expect(halfIdle().inventory!.gacha_pac1).toBe(0);
    expect(Object.keys(halfIdle().troop!.chars!)).toHaveLength(0);
  });

  it("recruitNormal：机动密令一次只任命 1 名（修复：原实现整池全给）", async () => {
    player = makePlayer({
      inventory: { gacha_pac1: 2, gacha_normal: 0 },
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/recruitNormal", { activityId: "act1vhalfidle", poolId: "gachaPac1", count: 1 });
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.ticketCount).toBe(1);
    const data = halfIdle();
    expect(Object.keys(data.troop!.chars!)).toHaveLength(1);
    expect(Object.values(data.troop!.chars!)[0].charId).toBe("char_pac_a");
    expect(data.recruit!.poolTimes!.gachaPac1).toBe(1);
    expect(data.recruit!.poolGain!.gachaPac1).toEqual(["char_pac_a"]);
    // 第二次任命取池内未获得的下一名
    await call("/act1vhalfidle/recruitNormal", { activityId: "act1vhalfidle", poolId: "gachaPac1", count: 1 });
    expect(Object.keys(halfIdle().troop!.chars!)).toHaveLength(2);
    expect(halfIdle().inventory!.gacha_pac1).toBe(0);
  });

  it("recruitNormal：随机任命按 poolTypeData 口径排除预留/联动未持有/低星", async () => {
    player = makePlayer({
      inventory: { gacha_normal: 40, gacha_pac1: 0 },
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: { 1: { instId: 1, charId: "char_link_owned" } } },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/recruitNormal", { activityId: "act1vhalfidle", poolId: "normalGachaPool", count: 2 });
    expect(vi.mocked(res.send).mock.calls[0][0].ticketCount).toBe(0);
    const gained = Object.values(halfIdle().troop!.chars!).map((c) => c.charId!);
    expect(gained).toHaveLength(2);
    // 合法候选只有 char_norm_ok 与 char_link_owned（已持有的联动干员允许）：
    // char_norm_low 为 2 星被排除、Pac/NewPlayer 干员被预留、char_link_missing 联动未持有被排除
    expect(new Set(gained).size).toBeGreaterThan(0);
    expect(gained.every((id: string) => ["char_norm_ok", "char_link_owned"].includes(id))).toBe(true);
expect(gained).not.toContain("char_norm_low");
expect(gained).not.toContain("char_pac_a");
expect(gained).not.toContain("char_link_missing");
  });

  it("recruitDirect：特约任命按分档消耗（100/150）且可任命未持有干员", async () => {
    player = makePlayer({
      inventory: { gacha_direct: 250 },
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/recruitDirect", { activityId: "act1vhalfidle", charId: "char_dir_1" });
    expect(halfIdle().inventory!.gacha_direct).toBe(150);
    expect(halfIdle().recruit!.poolTimes!.directionGachaPool).toBe(1);
    await call("/act1vhalfidle/recruitDirect", { activityId: "act1vhalfidle", charId: "char_dir_2" });
    expect(halfIdle().inventory!.gacha_direct).toBe(0);
    const chars = Object.values(halfIdle().troop!.chars!);
    expect(chars).toHaveLength(2);
    expect(chars[0].skillLvlWithSpec).toBe(4);
    expect(chars[0].isAssist).toBe(0);
  });

  it("battleFinish：登记关卡产出并汇总 production.rate", async () => {
    player = makePlayer({
      inventory: {},
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/battleFinish", { activityId: "act1vhalfidle", stageId: "act1halfidle_01" });
    await call("/act1vhalfidle/battleFinish", { activityId: "act1vhalfidle", stageId: "act1halfidle_02" });
    const data = halfIdle();
    expect(data.stage!.act1halfidle_01.rate!.level_exp).toBe(24000);
    expect(data.settleInfo!.stageId).toBe("act1halfidle_02");
    expect(data.production!.rate!.level_exp).toBe(54000);
    expect(data.production!.rate!.act1vhalfidle_token_point).toBe(600);
  });

  it("harvest：按 rate×时长结算、按上限封顶、并累计里程碑点数", async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    player = makePlayer({
      inventory: {},
      production: {
        rate: { act1vhalfidle_token_point: 600, level_exp: 54000 },
        product: {},
        harvestTs: past,
        refreshTs: past,
      },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
      milestone: { point: 10, got: [] },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    await call("/act1vhalfidle/harvest", { activityId: "act1vhalfidle" });
    const sent = vi.mocked(res.send).mock.calls[0][0];
    const data = halfIdle();
    // 1 小时：token 600（恰为上限）、level_exp 54000（恰为上限）
    expect(sent.milestoneAdd).toBe(600);
    expect(data.inventory!.act1vhalfidle_token_point).toBe(600);
    expect(data.inventory!.level_exp).toBe(54000);
    expect(data.milestone!.point).toBe(610);
    expect(sent.items).toEqual([
      { itemId: "act1vhalfidle_token_point", count: 600 },
      { itemId: "act1vhalfidle_level_exp", count: 54000 },
    ]);
  });

  it("unlockTech：扣 strategy_point 且校验前置节点", async () => {
    player = makePlayer({
      inventory: { strategy_point: 100 },
      production: { rate: {}, product: {}, harvestTs: 0, refreshTs: 0 },
      recruit: { poolGain: {}, poolTimes: {} },
      troop: { chars: {} },
      tech: { unlock: [] },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    // 前置未解锁 → 拒绝
    await call("/act1vhalfidle/unlockTech", { activityId: "act1vhalfidle", techId: "node_1_2" });
    expect(vi.mocked(res.send).mock.calls[0][0].result).toBe(1);
    expect(halfIdle().inventory!.strategy_point).toBe(100);
    // 根节点 → 扣 50
    await call("/act1vhalfidle/unlockTech", { activityId: "act1vhalfidle", techId: "node_1_1" });
    expect(halfIdle().tech!.unlock).toEqual(["node_1_1"]);
    expect(halfIdle().inventory!.strategy_point).toBe(50);
  });
});
