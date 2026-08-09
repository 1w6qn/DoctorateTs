import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import httpContext from "express-http-context2";
import shopRouter from "../../../app/game/router/shop";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("shop 路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      shop: {
        LS: { info: [{ id: "LS_good_1", count: 2 }] },
        HS: { info: [] },
        GP: {
          oneTime: { info: [{ id: "GP_Once_330", count: 1 }] },
          weekly: { info: [] },
        },
        CASH: { info: [{ id: "CS_1_r1", count: 1 }] },
        SOCIAL: { info: [] },
        CLASSIC: { info: [] },
      } as any,
    });
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    shopRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getGoodPurchaseState 应返回扁平 {goodId: 1|-1}（已购 -1 / 可购 1），对齐 CS 与抓包", async () => {
    await call("/getGoodPurchaseState", {
      goodIdMap: {
        LS: ["LS_good_1", "LS_not_bought"],
        GP: ["GP_Once_330"], // 嵌套结构（oneTime.info）
        CASH: ["CS_1_r1"],
        HS: [],
      },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toEqual({
      LS_good_1: -1, // 已购买
      LS_not_bought: 1, // 可购买
      GP_Once_330: -1, // GP 嵌套信息正确识别
      CS_1_r1: -1,
    });
    expect(Object.keys(sent.result).length).toBe(4); // 只返回请求的 goodId，而非全部 info
  });

  it("getGoodPurchaseState 空 goodIdMap 应返回空 result", async () => {
    await call("/getGoodPurchaseState", { goodIdMap: {} });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toEqual({});
  });
});
