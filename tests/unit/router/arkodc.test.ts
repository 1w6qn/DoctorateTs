import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// 战斗数据解密：completeState=2 判定完成（battleFinish 推进 varSeqs 用）
vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({ completeState: 2, interrupt: false, giveUp: false }),
}));

// 奇象巡展 excel：ArkventTable.odcDataMap[topicId].rewardGroups（宝箱奖励）
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    ArkventTable: {
      odcDataMap: {
        ark_odc_act53side: {
          rewardGroups: {
            ark_odc_act53side_reward_q001: [
              { id: "30044", count: 1, type: "MATERIAL" },
              { id: "4001", count: 20000, type: "GOLD" },
            ],
          },
        },
      },
      arkventDataMap: {
        ark_odc_act53side: {
          taskData: {
            actorData: {
              banner_controller_p1: {
                actorShowCondition: [{ varSeqList: ["q001_banner_showed"] }],
              },
              banner_controller_p2: {
                actorShowCondition: [
                  { varSeqList: ["q002_prog"] },
                  { varSeqList: ["q002_banner_showed"] },
                ],
                actorTriggerOperations: {
                  "0": [
                    {
                      operationTemplate: "ReceiveArkodcAward",
                      operationParams: { awardId: "ark_odc_act53side_reward_q002" },
                    },
                  ],
                },
              },
            },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import arkodcRouter from "@game/modules/arkodc/routes";
import { finishArkOdcGuideStory } from "@game/modules/arkodc/public";
import { mockPlayerData } from "../../helpers/mockPlayerData";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("arkodc（act53side「直到大地变成一颗酸橙」安洁莉娜的旅行小记 ODC 小游戏）路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      pushFlags: { status: 1 } as any,
      // 无 arkodc 字段——模拟旧存档/真实时间模式（未播种）
    });
    res = mockRes();
    (httpContext.get as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    arkodcRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("savePosition：topic 缺失时惰性创建并保存位置（不再静默 no-op）", async () => {
    await call("/savePosition", { topicId: "ark_odc_act53side", x: 1.5, y: -0.9, z: 3.2 });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic).toBeDefined();
    expect(topic.position).toEqual({ x: 1.5, y: -0.9, z: 3.2 });
    expect(topic.varSeqs).toEqual({});
    expect(topic.rewards).toEqual({});
    expect(res.send).toHaveBeenCalled();
  });

  it("triggerInteraction：awardId 宝箱标记 rewards 并真实发放 items:get", async () => {
    await call("/triggerInteraction", {
      topicId: "ark_odc_act53side",
      awardId: "ark_odc_act53side_reward_q001",
    });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic.rewards["ark_odc_act53side_reward_q001"]).toBe(1);
    // 奖励真实发放（经 items:get 进背包）
    const emitted = player._trigger.emit.mock.calls.filter((c: any[]) => c[0] === "items:get");
    expect(emitted).toHaveLength(1);
    expect(emitted[0][1][0]).toEqual([
      { id: "30044", count: 1, type: "MATERIAL" },
      { id: "4001", count: 20000, type: "GOLD" },
    ]);
    // 响应 items 供客户端展示
    const response = res.send.mock.calls[0][0];
    expect(response.items).toHaveLength(2);
  });

  it("restart：topic 缺失时惰性创建并清空 varSeqs", async () => {
    await call("/restart", { topicId: "ark_odc_act53side" });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic).toBeDefined();
    expect(topic.varSeqs).toEqual({});
    const response = res.send.mock.calls[0][0];
    expect(
      response.playerDataDelta.modified.arkodc.topics["ark_odc_act53side"].varSeqs,
    ).toEqual({});
  });

  it("restart：读取 player.delta 触发落盘且响应 position 重置为 null", async () => {
    const deltaSpy = vi.spyOn(player, "delta", "get");
    await call("/restart", { topicId: "ark_odc_act53side" });
    // 落盘触发：update 后必须读取 delta（内部 emit "save" + 清空 _changes）
    expect(deltaSpy).toHaveBeenCalled();
    const response = res.send.mock.calls[0][0];
    expect(
      response.playerDataDelta.modified.arkodc.topics["ark_odc_act53side"].position,
    ).toBeNull();
  });

  it("battleFinish：actorData 存在时推进 varSeqs（topic 惰性创建）", async () => {
    const { decryptBattleData } = await import("@utils/crypt");
    // battleStart 记录 topic，battleFinish 消费
    await call("/battleStart", { topicId: "ark_odc_act53side", groupId: "g1" });
    await call("/battleFinish", {
      data: "fake-encrypted",
      battleData: { isCheat: "0", completeTime: 100 },
      actorId: "banner_controller_p1",
      operationId: "op1",
    });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic).toBeDefined();
    expect(topic.varSeqs["q001_banner_showed"]).toBe(1);
    expect(decryptBattleData).toHaveBeenCalled();
  });

  it("battleFinish：未完成（completeState=1）不推进 varSeqs", async () => {
    const { decryptBattleData } = await import("@utils/crypt");
    (decryptBattleData as any).mockResolvedValueOnce({ completeState: 1, interrupt: false, giveUp: false });
    await call("/battleStart", { topicId: "ark_odc_act53side", groupId: "g1" });
    await call("/battleFinish", {
      data: "fake-encrypted",
      battleData: { isCheat: "0", completeTime: 100 },
      actorId: "banner_controller_p1",
      operationId: "op1",
    });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic?.varSeqs).toBeUndefined();
  });

  it("finishArkOdcGuideStory：教程剧情提交后同步 varSeq bool_end_guide_done=1（topic 惰性创建）", async () => {
    await finishArkOdcGuideStory(
      player,
      "activities/act53side/ark_odc_act53side_guide",
    );
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic).toBeDefined();
    expect(topic.varSeqs.bool_end_guide_done).toBe(1);
  });

  it("finishArkOdcGuideStory：非 ODC 教程剧情不写入 varSeqs", async () => {
    await finishArkOdcGuideStory(player, "activities/act53side/level_act53side_01_beg");
    expect(player._playerdata.arkodc).toBeUndefined();
  });

  it("triggerInteraction：_qNNN 后缀奖励正确推进关联 actor varSeqs（修复索引错误）", async () => {
    await call("/triggerInteraction", {
      topicId: "ark_odc_act53side",
      awardId: "ark_odc_act53side_reward_q002",
    });
    const topic = player._playerdata.arkodc?.topics?.["ark_odc_act53side"];
    expect(topic.rewards["ark_odc_act53side_reward_q002"]).toBe(1);
    // 修复后：actor varSeqs 正确推进——q002_banner_showed=1 且 代码自动置 q002_end=1
    expect(topic.varSeqs["q002_banner_showed"]).toBe(1);
    expect(topic.varSeqs["q002_end"]).toBe(1);
  });

  it("battleFinish：未完成路径清理 topic（避免后续 battleFinish 沿用错误 topic）", async () => {
    const { decryptBattleData } = await import("@utils/crypt");
    // 第一次：battleStart 记录 topic，然后第一次 battleFinish 未完成
    await call("/battleStart", { topicId: "ark_odc_act53side", groupId: "g1" });
    (decryptBattleData as any).mockResolvedValueOnce({ completeState: 1, interrupt: false, giveUp: false });
    await call("/battleFinish", {
      data: "fake-encrypted",
      battleData: { isCheat: "0", completeTime: 100 },
      actorId: "banner_controller_p1",
      operationId: "op1",
    });
    // 第一次完成后 topic 已被清理，Map 中无残留
    // 第二次：无 battleStart 直接调用 battleFinish → topicId 应为空，不推进 varSeqs
    await call("/battleFinish", {
      data: "fake-encrypted",
      battleData: { isCheat: "0", completeTime: 100 },
      actorId: "banner_controller_p1",
      operationId: "op1",
    });
    // 因为 Map 无 topic（已清理）→ topicId 为空，不推进 varSeqs 也不创建 arkodc
    expect(player._playerdata.arkodc).toBeUndefined();
  });
});
