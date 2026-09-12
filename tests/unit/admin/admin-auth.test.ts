import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("@ops/admin/admin-config", () => ({
  getAdminConfig: vi.fn(),
}));

import { adminAuth } from "@ops/admin/admin-auth";
import { getAdminConfig } from "@ops/admin/admin-config";

/** adminAuth 测试响应视图：只声明被测分支读到的两个方法 */
interface MockRes {
  status: Response["status"];
  json: Response["json"];
}

/** adminAuth 测试请求视图：只声明被测分支读到的两个成员 */
interface MockReq {
  headers: Request["headers"];
  query?: Request["query"];
}

function mockReqRes(): MockRes {
  return {
    status: vi.fn<Response["status"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

/** 以窄视图调用中间件（视图成员与 express 类型单向兼容，故断言不破坏类型面） */
function invoke(req: MockReq, res: MockRes, next: () => void): void {
  adminAuth(req as Request, res as Response, next);
}

describe("adminAuth", () => {
  it("admin.enable=false 时应返回 403", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: false, token: "t" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: {} }, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("无 token 时应返回 401", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "t" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: {} }, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("token 错误时应返回 401", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: { authorization: "Bearer wrong" } }, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("Bearer token 正确时应放行", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: { authorization: "Bearer correct" } }, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("X-Admin-Token 正确时应放行", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: { "x-admin-token": "correct" } }, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("查询参数 ?token=（SSE EventSource 场景）正确时应放行", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: {}, query: { token: "correct" } }, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("查询参数 ?token= 错误时应 401", () => {
    vi.mocked(getAdminConfig).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    invoke({ headers: {}, query: { token: "wrong" } }, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});
