import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { router } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  router({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("user 基础端点管道", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", buyApRemainTimes: 0 } as any,
    });
  });

  it("buyAp 额度耗尽返回 { result: 1 }", async () => {
    const res = await call(player, "/buyAp", {});
    expect(res.send.mock.calls[0][0].result).toBe(1);
  });

  it("useItem 经 gainItem 消耗（cnt 字段）", async () => {
    player._playerdata.status.buyApRemainTimes = 10;
    const res = await call(player, "/useItem", { instId: 830, itemId: "ap_supply_lt_120", cnt: 1 });
    expect(player.gainItem.setTarget).toHaveBeenCalledWith("ap_supply_lt_120", undefined, 1, 830);
    expect(player.gainItem.use).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalled();
  });

  it("exchangeDiamondShard 负数 count 返回 400", async () => {
    const res = await call(player, "/exchangeDiamondShard", { count: -1 });
    expect(res.status).toHaveBeenCalledWith(400);
  });
});
