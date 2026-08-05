import { describe, it, expect, vi } from "vitest";

vi.mock("@game/manager/AccountManger", () => ({
  accountManager: {
    tokenByPhonePassword: vi.fn().mockResolvedValue("token_123"),
    getUidByToken: vi.fn().mockResolvedValue("10000"),
    getUserConfig: vi.fn().mockResolvedValue({ auth: { phone: "13800000000" } }),
  },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("@utils/file", () => ({
  readJson: vi.fn().mockResolvedValue({ version: "1", appVersion: "1.0" }),
}));

import authRouter from "../../../app/auth/auth";
import { accountManager } from "@game/manager/AccountManger";

function mockRes() {
  const res: any = {
    send: vi.fn(),
    status: vi.fn().mockReturnThis(),
    sendStatus: vi.fn(),
    json: vi.fn(),
  };
  return res;
}

async function call(router: any, req: any, res: any) {
  router(req, res, () => {});
  // 等待异步 handler 完成
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("auth 路由", () => {
  it("GET /general/v1/server_time 应返回服务器时间", async () => {
    const res = mockRes();
    await call(authRouter, { method: "GET", url: "/general/v1/server_time" }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 0,
        data: { serverTime: 1234567890, isHoliday: false },
      }),
    );
  });

  it("GET /app/v1/config 应返回应用配置", async () => {
    const res = mockRes();
    await call(authRouter, { method: "GET", url: "/app/v1/config" }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ version: "1" }));
  });

  it("POST /user/auth/v1/token_by_phone_password 应返回 token", async () => {
    const res = mockRes();
    await call(
      authRouter,
      { method: "POST", url: "/user/auth/v1/token_by_phone_password", body: { phone: "13800000000", password: "pwd" } },
      res,
    );
    expect(accountManager.tokenByPhonePassword).toHaveBeenCalledWith(
      "13800000000",
      "pwd",
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ data: { token: "token_123" } }),
    );
  });

  it("GET /user/info/v1/basic 应返回用户 auth 信息", async () => {
    const res = mockRes();
    await call(authRouter, { method: "GET", url: "/user/info/v1/basic", query: { token: "t" } }, res);
    expect(accountManager.getUidByToken).toHaveBeenCalledWith("t");
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ data: { phone: "13800000000" } }),
    );
  });

  it("POST /user/oauth2/v2/grant 应返回授权码与 uid", async () => {
    const res = mockRes();
    await call(authRouter, { method: "POST", url: "/user/oauth2/v2/grant", body: { token: "t2" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ data: { code: "t2", uid: "10000" } }),
    );
  });

  it("POST /u8/user/v1/getToken 应解析渠道扩展并返回 token", async () => {
    const res = mockRes();
    await call(
      authRouter,
      { method: "POST", url: "/u8/user/v1/getToken", body: { extension: JSON.stringify({ code: "u8code" }) } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ token: "u8code", uid: "10000" }),
    );
  });

  it("POST /user/online/v1/loginout 应返回空对象", async () => {
    const res = mockRes();
    await call(authRouter, { method: "POST", url: "/user/online/v1/loginout" }, res);
    expect(res.send).toHaveBeenCalledWith({});
  });

  it("POST /u8/pay/getAllProductList 应返回空商品列表", async () => {
    const res = mockRes();
    await call(authRouter, { method: "POST", url: "/u8/pay/getAllProductList" }, res);
    expect(res.send).toHaveBeenCalledWith({ productList: [] });
  });
});
