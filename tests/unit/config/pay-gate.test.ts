import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("express-http-context2", () => ({
  default: {
    get: vi.fn(() => ({
      uid: "1",
      get delta() {
        return { playerDataDelta: {} };
      },
    })),
    set: vi.fn(),
  },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890, userTimestamp: () => 1234567890 }));

import payRouter from "@game/modules/pay/routes";
import gateRouter from "@core/config/gate";

/** 路由测试响应视图：只声明被测分支读到的四个方法（与 Express `Response` 同名成员一致，
 *  故 `res as Response` 的单向断言成立） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(
  router: typeof payRouter | typeof gateRouter,
  url: string,
  res: MockRes,
  method = "GET",
) {
  router({ method, url } as Request, res as Response, () => {});
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
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.code).toBe(0);
    expect(arg.data.platform).toBe("Windows");
    expect(arg.data.serverTime).toBe(1234567890);
  });

  it("info/:platform 应返回网关信息（启动链路早期请求）", async () => {
    const res = mockRes();
    await call(gateRouter, "/info/Windows?sign=1%202%203", res);
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.code).toBe(0);
    expect(arg.data.platform).toBe("Windows");
    expect(arg.data.serverTime).toBe(1234567890);
  });
});
