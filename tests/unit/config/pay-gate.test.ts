import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890, userTimestamp: () => 1234567890 }));

import payRouter from "../../../app/game/router/pay";
import gateRouter from "../../../app/config/gate";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(router: any, url: string, res: any, method = "GET") {
  router({ method, url } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("pay 路由", () => {
  it("getUnconfirmedOrderIdList 应返回空订单列表", async () => {
    const res = mockRes();
    await call(payRouter, "/getUnconfirmedOrderIdList", res, "POST");
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        orderIdList: [],
        playerDataDelta: expect.any(Object),
      }),
    );
  });
});

describe("gate 网关 meta 路由", () => {
  it("meta/:platform 应返回网关元数据", async () => {
    const res = mockRes();
    await call(gateRouter, "/meta/Windows", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.code).toBe(0);
    expect(arg.data.platform).toBe("Windows");
    expect(arg.data.serverTime).toBe(1234567890);
  });

  it("info/:platform 应返回网关信息（启动链路早期请求）", async () => {
    const res = mockRes();
    await call(gateRouter, "/info/Windows?sign=1%202%203", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.code).toBe(0);
    expect(arg.data.platform).toBe("Windows");
    expect(arg.data.serverTime).toBe(1234567890);
  });
});
