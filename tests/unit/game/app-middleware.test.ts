import { describe, it, expect, vi, beforeEach } from "vitest";

const configMock = vi.hoisted(() => ({ default: { authMode: "single" } }));
vi.mock("../../../app/config", () => configMock);
vi.mock("@game/manager/AccountManger", () => ({
  accountManager: { getPlayerData: vi.fn(), getUidByToken: vi.fn() },
}));
vi.mock("express-http-context2", () => ({
  default: { set: vi.fn(), get: vi.fn(), middleware: vi.fn() },
}));

import { authMiddleware } from "../../../app/game/app";
import { accountManager } from "@game/manager/AccountManger";
import httpContext from "express-http-context2";

function mockReqRes(headers: any) {
  const req: any = { headers };
  const res: any = { send: vi.fn(), status: vi.fn().mockReturnThis() };
  const next = vi.fn();
  return { req, res, next };
}

describe("authMiddleware 认证中间件", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    configMock.default.authMode = "single";
    (accountManager.getPlayerData as any).mockResolvedValue({ uid: "1" });
  });

  it("single 模式：secret 强制为 1（单账号）", async () => {
    const { req, res, next } = mockReqRes({ secret: "2221" });
    await authMiddleware(req, res, next);
    expect(req.headers.secret).toBe("1");
    expect(accountManager.getPlayerData).toHaveBeenCalledWith("1");
    expect(httpContext.set).toHaveBeenCalledWith("playerData", { uid: "1" });
    expect(next).toHaveBeenCalled();
  });

  it("real 模式：保留客户端 secret（多账号）", async () => {
    configMock.default.authMode = "real";
    (accountManager.getUidByToken as any).mockResolvedValue("2221");
    (accountManager.getPlayerData as any).mockResolvedValue({ uid: "2221" });
    const { req, res, next } = mockReqRes({ secret: "2221" });
    await authMiddleware(req, res, next);
    expect(req.headers.secret).toBe("2221");
    expect(accountManager.getPlayerData).toHaveBeenCalledWith("2221");
    expect(httpContext.set).toHaveBeenCalledWith("playerData", { uid: "2221" });
  });

  it("real 模式：secret 为账号 token 时应解析 uid（参考 DoctoratePy）", async () => {
    configMock.default.authMode = "real";
    (accountManager.getUidByToken as any).mockResolvedValue("2221");
    (accountManager.getPlayerData as any).mockResolvedValue({ uid: "2221" });
    const { req, res, next } = mockReqRes({ secret: "secret_2221" });
    await authMiddleware(req, res, next);
    expect(accountManager.getUidByToken).toHaveBeenCalledWith("secret_2221");
    expect(accountManager.getPlayerData).toHaveBeenCalledWith("2221");
    expect(httpContext.set).toHaveBeenCalledWith("playerData", { uid: "2221" });
  });

  it("real 模式：secret 无效返回 401", async () => {
    configMock.default.authMode = "real";
    (accountManager.getUidByToken as any).mockResolvedValue("");
    const { req, res, next } = mockReqRes({ secret: "bad" });
    await authMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("无 secret 头时（single 模式）也应注入 uid=1", async () => {
    configMock.default.authMode = "single";
    (accountManager.getPlayerData as any).mockResolvedValue({ uid: "1" });
    const { req, res, next } = mockReqRes({});
    await authMiddleware(req, res, next);
    expect(accountManager.getPlayerData).toHaveBeenCalledWith("1");
    expect(httpContext.set).toHaveBeenCalledWith("playerData", { uid: "1" });
    expect(next).toHaveBeenCalled();
  });
});
