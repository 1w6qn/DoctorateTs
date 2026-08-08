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
      delta: { modified: { status: { ap: 1 } }, deleted: {} },
      rlv2: {
        refreshShop: vi.fn().mockResolvedValue(undefined),
        leaveShop: vi.fn().mockResolvedValue(undefined),
        useTotem: vi.fn().mockResolvedValue(undefined),
        confirmPredict: vi.fn().mockResolvedValue(undefined),
        closeRecruitTicket: vi.fn().mockResolvedValue(undefined),
        selectChoice: vi.fn().mockResolvedValue(undefined),
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

  it("POST /refreshShop 应调用控制器并返回 delta", async () => {
    await call("/refreshShop", {});
    expect(player.rlv2.refreshShop).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });

  it("POST /leaveShop 应调用控制器并返回 delta", async () => {
    await call("/leaveShop", {});
    expect(player.rlv2.leaveShop).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });

  it("POST /useTotem 应透传参数", async () => {
    await call("/useTotem", { totemIndex: ["t_0", "t_1"], nodeIndex: ["1"] });
    expect(player.rlv2.useTotem).toHaveBeenCalledWith({
      totemIndex: ["t_0", "t_1"],
      nodeIndex: ["1"],
    });
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });

  it("POST /confirmPredict 应调用控制器并返回 delta", async () => {
    await call("/confirmPredict", {});
    expect(player.rlv2.confirmPredict).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });

  it("POST /closeRecruitTicket 应透传 id", async () => {
    await call("/closeRecruitTicket", { id: "t_1" });
    expect(player.rlv2.closeRecruitTicket).toHaveBeenCalledWith({ id: "t_1" });
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });

  it("POST /selectChoice 应调用控制器并透传 choice（抓包 body {choice}）", async () => {
    await call("/selectChoice", { choice: "choice_leave" });
    expect(player.rlv2.selectChoice).toHaveBeenCalledWith({ choice: "choice_leave" });
    expect(res.send).toHaveBeenCalledWith(player.delta);
  });
});
