import { describe, it, expect, vi } from "vitest";

vi.mock("../../../app/admin/admin-config", () => ({
  getAdminConfig: vi.fn(),
}));

import { adminAuth } from "../../../app/admin/admin-auth";
import { getAdminConfig } from "../../../app/admin/admin-config";

function mockReqRes() {
  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
  };
  return res;
}

describe("adminAuth", () => {
  it("admin.enable=false 时应返回 403", () => {
    (getAdminConfig as any).mockReturnValue({ enable: false, token: "t" });
    const res = mockReqRes();
    const next = vi.fn();
    adminAuth({ headers: {} } as any, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("无 token 时应返回 401", () => {
    (getAdminConfig as any).mockReturnValue({ enable: true, token: "t" });
    const res = mockReqRes();
    const next = vi.fn();
    adminAuth({ headers: {} } as any, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("token 错误时应返回 401", () => {
    (getAdminConfig as any).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    adminAuth({ headers: { authorization: "Bearer wrong" } } as any, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("Bearer token 正确时应放行", () => {
    (getAdminConfig as any).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    adminAuth({ headers: { authorization: "Bearer correct" } } as any, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("X-Admin-Token 正确时应放行", () => {
    (getAdminConfig as any).mockReturnValue({ enable: true, token: "correct" });
    const res = mockReqRes();
    const next = vi.fn();
    adminAuth({ headers: { "x-admin-token": "correct" } } as any, res, next);
    expect(next).toHaveBeenCalled();
  });
});
