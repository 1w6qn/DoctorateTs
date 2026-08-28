import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// 最小化 act44side excel（键用真实数据的小写变体；含里程碑配置供 rewardMilestone 分支）
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
        tYPE_ACT44SIDE: {
          act44side: {
            customerDataMap: {
              policeman: { id: "policeman", name: "惟任警官", isSp: true },
              fans: { id: "fans", name: "追星族", isSp: false },
              citizen_beginner: { id: "citizen_beginner", name: "教程路人", isSp: false },
            },
            tagDataMap: {
              special: { id: "special", name: "特殊顾客", isSp: true },
              picky: { id: "picky", name: "挑剔的", isSp: false },
            },
            choiceDataMap: {
              dialogue_a: {
                id: "dialogue_a",
                attentionArrow: 2,
                trustArrow: 1,
                attentionValue: 16,
                trustValue: 8,
                patienceValue: 1,
              },
              dialogue_c: {
                id: "dialogue_c",
                attentionArrow: 3,
                trustArrow: -1,
                attentionValue: 24,
                trustValue: -8,
                patienceValue: 1,
              },
            },
            customerDialogMap: { policeman_entrance_01: "" },
            keeperDialogMap: {
              shopkeeper_dialogueA_01: "",
              shopkeeper_lowTrust_01: "",
            },
            newsDataMap: { news_01: { id: "news_01" } },
            insightDescMap: {},
            mileStoneList: [
              {
                mileStoneId: "mileStone_1",
                mileStoneLvl: 1,
                needPointCnt: 4000,
                rewardItem: { id: "4001", count: 20000, type: "GOLD" },
              },
              {
                mileStoneId: "mileStone_2",
                mileStoneLvl: 2,
                needPointCnt: 8000,
                rewardItem: { id: "30014", count: 1, type: "MATERIAL" },
              },
            ],
            constData: {
              attentionMax: 180,
              trustMax: 180,
              attentionMin: 30,
              trustMin: 30,
              patienceRCRoundNum: 4,
              beginnerPatienceRCRoundNum: 1,
              specialCustomerListId: ["policeman"],
              informantUnlockStageId: "act44side_tr01",
              informantItemId: "act44side_token_information",
              informantItemType: "ACTIVITY_ITEM",
              informantItemCount: 100,
              milestoneItemId: "act44side_token_treasure",
              milestoneRewardList: [],
              forCountBigSuccess: 2,
              outerOpenUnlock: "",
              customerTagFormat: "<{0}>",
            },
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

describe("act44side（情报屋）路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Math, "random").mockReturnValue(0); // 受控随机：pick 恒取首个、掷点/抖动确定
    player = mockPlayerData({
      status: { uid: "1" } as any,
      // 预置历史顶层状态（模拟已播种；live 客户端发 act44sre，excel 键为 act44side）
      activity: {
        TYPE_ACT44SIDE: {
          act44sre: {
            coin: 32,
            favorList: ["char_1044_hsgma2"],
            informantPt: 67,
            milestone: { point: 1224, got: [] },
            businessDay: 1,
            unlockedCustomers: {},
            unlockedTags: {},
            isNew: false,
            outerOpen: true,
            game: null,
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

  it("startGame 应在请求的 activityId 下开启营业日并返回 delta", async () => {
    await call("/act44side/startGame", { activityId: "act44sre" });
    const act = player._playerdata.activity.TYPE_ACT44SIDE.act44sre;
    expect(act.game).not.toBeNull();
    expect(act.game.state).toBe(0);
    expect(act.game.customerId).toBe("policeman");
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
    // 顶层历史字段保留（coin/informantPt/milestone 不被重置）
    expect(act.coin).toBe(32);
    expect(act.milestone.point).toBe(1224);
  });

  it("完整营业日循环应正确转移状态并日结算", async () => {
    await call("/act44side/startGame", { activityId: "act44sre" });
    const incomes: number[] = [];
    for (let slot = 0; slot < 3; slot++) {
      await call("/act44side/nextState", { activityId: "act44sre", state: 0 }); // ENTRY→CHOICE
      await call("/act44side/selectChoice", { activityId: "act44sre", index: 0 }); // CHOICE_END
      await call("/act44side/nextState", { activityId: "act44sre", state: 2 }); // round+1
      await call("/act44side/nextState", { activityId: "act44sre", state: 1 }); // 结算
      const g = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.game!;
      expect(g.state).toBe(4);
      expect(g.settle[slot].income).toBe(Math.round(g.basicIncome * g.settle[slot].incomeRate));
      incomes.push(g.settle[slot].income);
      if (slot < 2) await call("/act44side/nextState", { activityId: "act44sre", state: 4 });
    }
    await call("/act44side/nextState", { activityId: "act44sre", state: 4 }); // RESULT 日结算
    let act = player._playerdata.activity.TYPE_ACT44SIDE.act44sre;
    expect(act.game!.state).toBe(5);
    expect(act.milestone.point).toBe(1224 + incomes.reduce((a, b) => a + b, 0));
    await call("/act44side/nextState", { activityId: "act44sre", state: 5 }); // 收摊
    act = player._playerdata.activity.TYPE_ACT44SIDE.act44sre;
    expect(act.game).toBeNull();
    expect(act.businessDay).toBe(2);
    expect(act.unlockedCustomers.policeman).toBe(1);
    expect(act.unlockedTags.special).toBeUndefined();
  });

  it("selectChoice 应按 excel 累加数值并记录 lastChoice", async () => {
    await call("/act44side/startGame", { activityId: "act44sre" });
    await call("/act44side/nextState", { activityId: "act44sre", state: 0 });
    await call("/act44side/selectChoice", { activityId: "act44sre", index: 0 });
    const g = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.game!;
    expect(g.tradeInfo.trust).toBe(8); // dialogue_a trustValue=8
    expect(g.tradeInfo.attention).toBe(16); // dialogue_a attentionValue=16
    expect(g.tradeInfo.lastChoice).toBe("dialogue_a");
    expect(g.state).toBe(2);
  });

  it("useInsight 应消耗次数并填充洞悉提示", async () => {
    await call("/act44side/startGame", { activityId: "act44sre" });
    await call("/act44side/nextState", { activityId: "act44sre", state: 0 });
    await call("/act44side/useInsight", { activityId: "act44sre" });
    const g = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.game!;
    expect(g.insightTimes).toBe(2);
    expect(g.insight).toMatchObject({
      trustRE: expect.any(Number),
      trustMAX: expect.any(Number),
      attentionRE: expect.any(Number),
      attentionMAX: expect.any(Number),
    });
  });

  it("无播种状态的 activityId 应自愈创建而不崩溃", async () => {
    await call("/act44side/startGame", { activityId: "act99new" });
    const act = player._playerdata.activity.TYPE_ACT44SIDE.act99new;
    expect(act.game).not.toBeNull();
    expect(act.businessDay).toBe(1);
  });

  describe("rewardMilestone（TYPE_ACT44SIDE 分支）", () => {
    beforeEach(() => {
      player._playerdata.activity.TYPE_ACT44SIDE.act44sre.milestone.point = 5000;
    });

    it("达标里程碑应写 got 并发放 rewardItem", async () => {
      await call("/rewardMilestone", {
        activityId: "act44sre",
        milestoneId: "mileStone_1",
      });
      const ms = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.milestone;
      expect(ms.got).toEqual(["mileStone_1"]);
      expect(player._trigger.emit).toHaveBeenCalledWith("items:get", [
        [{ id: "4001", count: 20000, type: "GOLD" }],
      ]);
      expect(res.send).toHaveBeenCalledWith(
        expect.objectContaining({
          item: [{ id: "4001", count: 20000, type: "GOLD" }],
        }),
      );
    });

    it("未达标里程碑应拒绝领取", async () => {
      await call("/rewardMilestone", {
        activityId: "act44sre",
        milestoneId: "mileStone_2", // 需要 8000，当前 5000
      });
      const ms = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.milestone;
      expect(ms.got).toEqual([]);
      expect(player._trigger.emit).not.toHaveBeenCalledWith(
        "items:get",
        expect.anything(),
      );
    });

    it("重复领取应幂等", async () => {
      await call("/rewardMilestone", {
        activityId: "act44sre",
        milestoneId: "mileStone_1",
      });
      await call("/rewardMilestone", {
        activityId: "act44sre",
        milestoneId: "mileStone_1",
      });
      const ms = player._playerdata.activity.TYPE_ACT44SIDE.act44sre.milestone;
      expect(ms.got.filter((id: string) => id === "mileStone_1")).toHaveLength(1);
    });
  });
});
