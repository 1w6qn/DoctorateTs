import { describe, it, expect, vi } from "vitest";

vi.mock("../../../app/admin/AdminService", () => ({
  adminService: {
    status: vi.fn().mockResolvedValue({ online: true }),
    listUsers: vi.fn().mockResolvedValue([{ uid: "1" }]),
    getUserInfo: vi.fn().mockResolvedValue(null),
    createUser: vi.fn().mockResolvedValue("2222"),
    reloadUser: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../../../app/admin/admin-auth", () => ({
  adminAuth: vi.fn((_req: any, _res: any, next: any) => next()),
}));
vi.mock("../../../app/config", () => ({ default: {} }));

import adminRouter from "../../../app/admin/admin-router";
import { adminService } from "../../../app/admin/AdminService";

function mockRes() {
  return {
    send: vi.fn(),
    sendFile: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
    sendStatus: vi.fn(),
  };
}

async function call(req: any, res: any) {
  adminRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("admin 路由", () => {
  it("GET /dashboard 应返回静态页面", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/dashboard" }, res);
    expect(res.sendFile).toHaveBeenCalledWith(expect.stringContaining("index.html"));
  });

  it("GET /api/status 应返回服务器状态", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/api/status" }, res);
    expect(adminService.status).toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ online: true });
  });

  it("GET /api/users 应返回用户列表", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/api/users" }, res);
    expect(res.json).toHaveBeenCalledWith([{ uid: "1" }]);
  });

  it("GET /api/users/:uid 用户不存在应返回 404", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/api/users/999", params: { uid: "999" } }, res);
    expect(adminService.getUserInfo).toHaveBeenCalledWith("999");
    expect(res.status).toHaveBeenCalledWith(404);
  });

  it("POST /api/users 应创建用户并返回 201", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/api/users", body: { phone: "13800000001", password: "pwd" } }, res);
    expect(adminService.createUser).toHaveBeenCalledWith("13800000001", "pwd");
    expect(res.status).toHaveBeenCalledWith(201);
  });
});
