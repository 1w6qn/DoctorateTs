import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// 最小化 act44side excel 数据（字典键用真实数据的小写变体 tYPE_ACT44SIDE，
// 同时验证大小写不敏感解析）；数据形状对照官服抓包（tmp/act44side-captures.json）
vi.mock("@excel/excel", () => ({
  default: {
    ActivityTable: {
      activity: {
        tYPE_ACT44SIDE: {
          act44side: {
            zoneAdditionDataMap: {},
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
            customerDialogMap: {
              policeman_entrance_01: "",
              policeman_highPatience_01: "",
              policeman_LowPatience_01: "", // 大写 L 变体（真实数据即如此）
              fans_entrance_01: "",
            },
            keeperDialogMap: {
              shopkeeper_dialogueA_01: "",
              shopkeeper_dialogueC_02: "",
              shopkeeper_lowTrust_01: "",
              shopkeeper_lowPatience_01: "",
              shopkeeper_highAttention_01: "",
              shopkeeper_normalDeal_01: "",
            },
            newsDataMap: {
              news_01: { id: "news_01" },
              news_02: { id: "news_02" },
              news_03: { id: "news_03" },
            },
            insightDescMap: {},
            mileStoneList: [],
            constData: {
              informantUnlockStageId: "act44side_tr01",
              informantItemId: "act44side_token_information",
              informantItemType: "ACTIVITY_ITEM",
              informantItemCount: 100,
              milestoneItemId: "act44side_token_treasure",
              attentionMax: 180,
              trustMax: 180,
              attentionMin: 30,
              trustMin: 30,
              patienceRCRoundNum: 4,
              beginnerPatienceRCRoundNum: 1,
              specialCustomerListId: ["policeman"],
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

import {
  InformantState,
  dayInsight,
  defaultAct44State,
  ensureAct44State,
  informantNextState,
  informantSelectChoice,
  informantStartGame,
  informantUseInsight,
  resolveAct44Data,
} from "../../../app/game/service/activity/act44side/informant";

/** 受控随机：pick 恒取首个、掷点恒成功、incomeRate 无抖动 */
let randomSpy: ReturnType<typeof vi.spyOn>;

function newDraft(): any {
  return { activity: {} };
}

describe("act44side 情报屋状态机", () => {
  beforeEach(() => {
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
  });
  afterEach(() => {
    randomSpy.mockRestore();
  });

  it("resolveAct44Data 应大小写不敏感解析并按唯一条目兜底", () => {
    expect(resolveAct44Data("act44side")?.constData.specialCustomerListId).toEqual(["policeman"]);
    // live 客户端发 act44sre，excel 键为 act44side——兜底唯一条目
    expect(resolveAct44Data("act44sre")).toBe(resolveAct44Data("act44side"));
    expect(resolveAct44Data()).toBeDefined();
  });

  it("ensureAct44State 应为任意 activityId 自愈创建默认状态", () => {
    const draft = newDraft();
    const { state } = ensureAct44State(draft, "act44sre");
    expect(state).toEqual(defaultAct44State());
    expect(draft.activity.TYPE_ACT44SIDE.act44sre).toBe(state);
    // 二次进入不重建，保留已改字段
    state.businessDay = 7;
    expect(ensureAct44State(draft, "act44sre").state.businessDay).toBe(7);
  });

  it("startGame 应开新营业日：槽位0 发特殊顾客、ENTRY 态、每日新闻轮换", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.ENTRY);
    expect(game.customerId).toBe("policeman"); // specialCustomerListId[0]
    expect(game.customerList).toEqual([1, 0, 0]);
    expect(game.tagId).toBe("special");
    expect(game.insightTimes).toBe(3);
    expect(game.tradeInfo).toEqual({ trust: 0, attention: 0, choices: [], lastChoice: null });
    expect(game.settle).toEqual([]);
    expect(game.newsId).toBe("news_01"); // businessDay=1 → 首条新闻
    // 顶层默认字段保留
    expect(draft.activity.TYPE_ACT44SIDE.act44sre.milestone).toEqual({ point: 0, got: [] });
  });

  it("nextState(0) 应进入 CHOICE 并发出选项对与进场台词", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.CHOICE);
    expect(game.tradeInfo.choices).toEqual(["dialogue_a", "dialogue_c"]); // random=0 取前两个
    expect(game.customerLine).toBe("policeman_entrance_01");
    expect(game.keeperLine).toBeNull();
  });

  it("selectChoice 应按 excel 数值累加并记录 lastChoice 与店主回应", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    informantSelectChoice(draft, "act44sre", 0); // dialogue_a: trust+8 / attention+16
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.CHOICE_END);
    expect(game.tradeInfo.trust).toBe(8);
    expect(game.tradeInfo.attention).toBe(16);
    expect(game.tradeInfo.lastChoice).toBe("dialogue_a");
    expect(game.tradeInfo.choices).toEqual([]);
    expect(game.keeperLine).toMatch(/^shopkeeper_dialogueA_/);
  });

  it("selectChoice 非法下标应保持原状", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    informantSelectChoice(draft, "act44sre", 9);
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.CHOICE);
    expect(game.tradeInfo.lastChoice).toBeNull();
  });

  it("nextState(2) 应 round+1 回到 CHOICE 并刷新选项与台词", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    informantSelectChoice(draft, "act44sre", 0);
    informantNextState(draft, "act44sre", 2);
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.CHOICE);
    expect(game.round).toBe(1);
    expect(game.tradeInfo.choices).toEqual(["dialogue_a", "dialogue_c"]);
    expect(game.tradeInfo.lastChoice).toBeNull();
    // round 1 < patienceRCRoundNum(4) → 高耐心台词档
    expect(game.customerLine).toBe("policeman_highPatience_01");
  });

  it("nextState(1) 应结算当前顾客：settle 追加、income 公式、洞悉填充", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    informantSelectChoice(draft, "act44sre", 0); // t/a = 8/16
    informantNextState(draft, "act44sre", 2); // 取新一轮选项（官方时序）
    informantNextState(draft, "act44sre", 1); // 耐心耗尽 → 从 CHOICE 结算
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.state).toBe(InformantState.SINGLE_RESULT);
    expect(game.settle).toHaveLength(1);
    const entry = game.settle[0];
    expect(entry.customerId).toBe("policeman");
    expect(entry.tagId).toBe("special");
    // random=0：rate = round(50*(8-30)/150 + 50*(16-30)/150) → clamp 0；掷点 0<0 不成立
    expect(entry.successRate).toBe(0);
    expect(entry.success).toBe(false);
    expect(entry.incomeRate).toBe(3); // 3 + 1.2*0 + 0
    expect(entry.income).toBe(Math.round(game.basicIncome * entry.incomeRate));
    expect(game.insight).toEqual(dayInsight("act44sre", 1));
    expect(game.keeperLine).not.toBeNull();
  });

  it("useInsight 应消耗次数且当日定值稳定（与结算洞悉一致）", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0);
    informantUseInsight(draft, "act44sre");
    let game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.insightTimes).toBe(2);
    const revealed = game.insight;
    expect(revealed).toEqual(dayInsight("act44sre", 1));
    // 结算时的洞悉应与揭示一致（同日同种子）
    informantSelectChoice(draft, "act44sre", 0);
    informantNextState(draft, "act44sre", 2);
    informantNextState(draft, "act44sre", 1);
    game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.insight).toEqual(revealed); // 同日同种子 → 值相同（各自新建对象）
  });

  it("完整营业日：三顾客结算后 RESULT 累加 point，收摊解锁并清空 game", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    const incomes: number[] = [];
    for (let slot = 0; slot < 3; slot++) {
      informantNextState(draft, "act44sre", 0); // ENTRY→CHOICE
      informantSelectChoice(draft, "act44sre", 0); // CHOICE→CHOICE_END
      informantNextState(draft, "act44sre", 2); // 取新选项（round+1）
      informantNextState(draft, "act44sre", 1); // 从 CHOICE 结算
      let game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
      expect(game.state).toBe(InformantState.SINGLE_RESULT);
      incomes.push(game.settle[slot].income);
      if (slot < 2) {
        informantNextState(draft, "act44sre", 4); // 下一位顾客
        game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
        expect(game.state).toBe(InformantState.ENTRY);
        expect(game.curCustomer).toBe(slot + 1);
        expect(game.settle).toHaveLength(slot + 1); // settle 保留累计
        expect(game.tradeInfo.trust).toBe(0); // 交易重置
      }
    }
    // 三位齐 → RESULT 日结算
    informantNextState(draft, "act44sre", 4);
    let state = draft.activity.TYPE_ACT44SIDE.act44sre;
    expect(state.game!.state).toBe(InformantState.RESULT);
    expect(state.milestone.point).toBe(incomes.reduce((a, b) => a + b, 0));

    // 收摊
    informantNextState(draft, "act44sre", 5);
    state = draft.activity.TYPE_ACT44SIDE.act44sre;
    expect(state.game).toBeNull();
    expect(state.businessDay).toBe(2);
    expect(state.unlockedCustomers.policeman).toBe(1);
    expect(state.unlockedCustomers.fans).toBe(1);
    expect(state.unlockedTags.special).toBeUndefined(); // 特殊标签不入表（抓包一致）
    expect(state.unlockedTags.picky).toBe(1);
  });

  it("不支持的状态（BEFORE_SINGLE_RESULT）应保持原状", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    game.state = InformantState.BEFORE_SINGLE_RESULT;
    informantNextState(draft, "act44sre", 3);
    expect(draft.activity.TYPE_ACT44SIDE.act44sre.game.state).toBe(
      InformantState.BEFORE_SINGLE_RESULT,
    );
  });

  it("无会话时 nextState/selectChoice/useInsight 应安全忽略", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    draft.activity.TYPE_ACT44SIDE.act44sre.game = null;
    expect(() => informantNextState(draft, "act44sre", 0)).not.toThrow();
    expect(() => informantSelectChoice(draft, "act44sre", 0)).not.toThrow();
    expect(() => informantUseInsight(draft, "act44sre")).not.toThrow();
    expect(draft.activity.TYPE_ACT44SIDE.act44sre.game).toBeNull();
  });

  it("低耐心回合应命中 LowPatience 台词档（含大写 L 数据变体）", () => {
    const draft = newDraft();
    informantStartGame(draft, "act44sre");
    informantNextState(draft, "act44sre", 0); // round0 entrance
    informantSelectChoice(draft, "act44sre", 0);
    for (let i = 1; i <= 4; i++) {
      informantNextState(draft, "act44sre", 2); // round → i
      if (i < 4) informantSelectChoice(draft, "act44sre", 0);
    }
    // round=4 ≥ patienceRCRoundNum(4) → LowPatience 档
    const game = draft.activity.TYPE_ACT44SIDE.act44sre.game;
    expect(game.round).toBe(4);
    expect(game.customerLine).toBe("policeman_LowPatience_01");
  });
});
