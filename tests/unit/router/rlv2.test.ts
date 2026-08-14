import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import rlv2Router from "../../../app/game/router/rlv2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("rlv2 路由", () => {
  let player: any;
  let res: any;
  let ctx: any;

  beforeEach(async () => {
    player = {
      delta: { playerDataDelta: { modified: { status: { ap: 1 } }, deleted: {} } },
      rlv2: {
        toJSON: () => ({ outer: {}, current: {} }),
        refreshShop: vi.fn().mockResolvedValue(undefined),
        leaveShop: vi.fn().mockResolvedValue(undefined),
        useTotem: vi.fn().mockResolvedValue(undefined),
        confirmPredict: vi.fn().mockResolvedValue(undefined),
        closeRecruitTicket: vi.fn().mockResolvedValue(undefined),
        selectChoice: vi.fn().mockResolvedValue(undefined),
        battlePassGetReward: vi.fn().mockResolvedValue({ items: [{ type: "GOLD", id: "4001", count: 1 }] }),
        nodeMissionConfirm: vi.fn().mockResolvedValue(undefined),
        nodeMissionGiveUp: vi.fn().mockResolvedValue(undefined),
        nodeMissionCloseTip: vi.fn().mockResolvedValue(undefined),
        scrapIdentify: vi.fn().mockResolvedValue({
          scrap: [{ id: "rogue_6_scrap_G_05", count: 1 }],
          legacy: [{ id: "rogue_6_legacy_02", count: 1 }],
        }),
      },
    };
    res = mockRes();
    ctx = await import("express-http-context2");
    (ctx.default.get as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    rlv2Router({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  /**
   * rlv2 统一响应约定：playerDataDelta.modified 含 Immer 增量 + 完整 rlv2 子树
   * （官方抓包确认客户端按 modified.rlv2 整体替换自身状态）
   */
  function expectRlv2Response(calledWith: any) {
    expect(calledWith.playerDataDelta).toBeTruthy();
    expect(calledWith.playerDataDelta.modified.status).toEqual({ ap: 1 });
    expect(calledWith.playerDataDelta.modified.rlv2).toEqual({ outer: {}, current: {} });
  }

  it("POST /refreshShop 应调用控制器并返回 delta", async () => {
    await call("/refreshShop", {});
    expect(player.rlv2.refreshShop).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /leaveShop 应调用控制器并返回 delta", async () => {
    await call("/leaveShop", {});
    expect(player.rlv2.leaveShop).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /useTotem 应透传参数", async () => {
    await call("/useTotem", { totemIndex: ["t_0", "t_1"], nodeIndex: ["1"] });
    expect(player.rlv2.useTotem).toHaveBeenCalledWith({
      totemIndex: ["t_0", "t_1"],
      nodeIndex: ["1"],
    });
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /confirmPredict 应调用控制器并返回 delta", async () => {
    await call("/confirmPredict", {});
    expect(player.rlv2.confirmPredict).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /closeRecruitTicket 应透传 id", async () => {
    await call("/closeRecruitTicket", { id: "t_1" });
    expect(player.rlv2.closeRecruitTicket).toHaveBeenCalledWith({ id: "t_1" });
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /selectChoice 应调用控制器并透传 choice（抓包 body {choice}）", async () => {
    await call("/selectChoice", { choice: "choice_leave" });
    expect(player.rlv2.selectChoice).toHaveBeenCalledWith({ choice: "choice_leave" });
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /battlePass_getReward（下划线路径）应调用控制器并带 items", async () => {
    await call("/battlePass_getReward", { theme: "rogue_2", rewards: ["bp_level_1"] });
    expect(player.rlv2.battlePassGetReward).toHaveBeenCalledWith("rogue_2", ["bp_level_1"]);
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([{ type: "GOLD", id: "4001", count: 1 }]);
    expectRlv2Response(sent);
  });

  it("POST /nodeMission_confirm（下划线路径）应调用控制器", async () => {
    await call("/nodeMission_confirm", {});
    expect(player.rlv2.nodeMissionConfirm).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /nodeMission_giveUp（下划线路径）应调用控制器", async () => {
    await call("/nodeMission_giveUp", {});
    expect(player.rlv2.nodeMissionGiveUp).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /nodeMission_closeTip（下划线路径）应调用控制器", async () => {
    await call("/nodeMission_closeTip", {});
    expect(player.rlv2.nodeMissionCloseTip).toHaveBeenCalled();
    expectRlv2Response(res.send.mock.calls[0][0]);
  });

  it("POST /scrap/identify 应调用控制器并带 scrap/legacy", async () => {
    await call("/scrap/identify", { count: 3 });
    expect(player.rlv2.scrapIdentify).toHaveBeenCalledWith({ count: 3 });
    const sent = res.send.mock.calls[0][0];
    expect(sent.scrap).toEqual([{ id: "rogue_6_scrap_G_05", count: 1 }]);
    expect(sent.legacy).toEqual([{ id: "rogue_6_legacy_02", count: 1 }]);
    expectRlv2Response(sent);
  });
});
