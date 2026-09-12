import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import type { Response } from "express";
import { router } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** user 基础端点请求体视图 */
interface UserStatusBody {
  instId?: number;
  itemId?: string;
  cnt?: number;
  count?: number;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: UserStatusBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  type: Response["type"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof router>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    type: vi.fn<Response["type"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(player: MockPlayerDataManager, url: string, body: UserStatusBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url, body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  router(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("user 基础端点管道", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", buyApRemainTimes: 0 },
    });
  });

  it("buyAp 额度耗尽返回 { result: 1 }", async () => {
    const res = await call(player, "/buyAp", {});
    expect(vi.mocked(res.send).mock.calls[0][0].result).toBe(1);
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
