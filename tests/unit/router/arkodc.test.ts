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
            },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import arkodcRouter from "../../../app/game/router/arkodc";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("arkodc（奇象巡展 ODC）路由", () => {
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
});
