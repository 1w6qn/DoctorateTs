import { describe, it, expect, vi } from "vitest";

vi.mock("../../../app/admin/AdminService", () => ({
  adminService: {
    status: vi.fn().mockResolvedValue({ online: true }),
    listUsers: vi.fn().mockResolvedValue([{ uid: "1" }]),
    getUserInfo: vi.fn().mockResolvedValue(null),
    createUser: vi.fn().mockResolvedValue("2222"),
    reloadUser: vi.fn().mockResolvedValue(undefined),
    grantItem: vi.fn().mockResolvedValue(undefined),
    grantChar: vi.fn().mockResolvedValue({ isNew: 1, name: "阿米娅" }),
    grantSkin: vi.fn().mockResolvedValue(undefined),
    listChars: vi.fn().mockResolvedValue([{ instId: 1, name: "阿米娅" }]),
    setCharAttrs: vi.fn().mockResolvedValue({ instId: 1, name: "阿米娅", level: 90 }),
    maxOutAccount: vi.fn().mockResolvedValue({ chars: 1, items: 10, skins: 2, rooms: 1 }),
    buildingMax: vi.fn().mockResolvedValue({ rooms: 3 }),
    backup: vi.fn().mockResolvedValue({ name: "1-20250101000000.json", size: 10 }),
    listBackups: vi.fn().mockResolvedValue([{ name: "1-20250101000000.json", size: 10 }]),
    restore: vi.fn().mockResolvedValue(undefined),
    getRawJson: vi.fn().mockResolvedValue({ status: { uid: "1" } }),
    listMails: vi.fn().mockResolvedValue([{ mailId: 1000001, subject: "欢迎" }]),
    deleteMail: vi.fn().mockResolvedValue(true),
    sendMail: vi.fn().mockResolvedValue({ mailId: 1000000 }),
    sendMailAll: vi.fn().mockResolvedValue({ sent: 2 }),
    refreshUser: vi.fn().mockResolvedValue(undefined),
    saveUser: vi.fn().mockResolvedValue(undefined),
    stats: vi.fn().mockResolvedValue({ userCount: 1, avgLevel: 60 }),
    logs: vi.fn().mockResolvedValue([{ ts: 1, action: "grantItem", uid: "1", detail: "x" }]),
    getCommonItems: vi.fn().mockResolvedValue([{ name: "龙门币", id: "4001" }]),
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

describe("admin 路由（扩展能力）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("POST /api/users/:uid/grant 应发放物品", async () => {
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/users/1/grant", params: { uid: "1" }, body: { itemId: "4001", count: 100 } },
      res,
    );
    expect(adminService.grantItem).toHaveBeenCalledWith("1", "4001", 100);
    expect(res.json).toHaveBeenCalledWith({ ok: true });
  });

  it("POST /api/users/:uid/grantchar 应发放干员", async () => {
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/users/1/grantchar", params: { uid: "1" }, body: { charId: "char_002_amiya" } },
      res,
    );
    expect(adminService.grantChar).toHaveBeenCalledWith("1", "char_002_amiya");
    expect(res.json).toHaveBeenCalledWith({ isNew: 1, name: "阿米娅" });
  });

  it("POST /api/users/:uid/grantskin 应解锁皮肤", async () => {
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/users/1/grantskin", params: { uid: "1" }, body: { skinId: "char_002_amiya#2" } },
      res,
    );
    expect(adminService.grantSkin).toHaveBeenCalledWith("1", "char_002_amiya#2");
  });

  it("GET /api/users/:uid/chars 应返回干员列表", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/api/users/1/chars", params: { uid: "1" } }, res);
    expect(adminService.listChars).toHaveBeenCalledWith("1");
    expect(res.json).toHaveBeenCalledWith([{ instId: 1, name: "阿米娅" }]);
  });

  it("POST /api/users/:uid/chars 应修改干员属性", async () => {
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/users/1/chars", params: { uid: "1" }, body: { instId: 1, level: 90 } },
      res,
    );
    expect(adminService.setCharAttrs).toHaveBeenCalledWith("1", 1, { level: 90 });
  });

  it("POST /api/users/:uid/maxout 应返回满配统计", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/api/users/1/maxout", params: { uid: "1" }, body: {} }, res);
    expect(adminService.maxOutAccount).toHaveBeenCalledWith("1");
    expect(res.json).toHaveBeenCalledWith({ chars: 1, items: 10, skins: 2, rooms: 1 });
  });

  it("POST /api/users/:uid/building-max 应满级基建", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/api/users/1/building-max", params: { uid: "1" }, body: {} }, res);
    expect(adminService.buildingMax).toHaveBeenCalledWith("1");
  });

  it("POST /api/users/:uid/backup 与 GET backups / POST restore 应透传", async () => {
    const res1 = mockRes();
    await call({ method: "POST", url: "/api/users/1/backup", params: { uid: "1" }, body: {} }, res1);
    expect(adminService.backup).toHaveBeenCalledWith("1");

    const res2 = mockRes();
    await call({ method: "GET", url: "/api/users/1/backups", params: { uid: "1" } }, res2);
    expect(adminService.listBackups).toHaveBeenCalledWith("1");

    const res3 = mockRes();
    await call(
      { method: "POST", url: "/api/users/1/restore", params: { uid: "1" }, body: { backup: "1-20250101000000.json" } },
      res3,
    );
    expect(adminService.restore).toHaveBeenCalledWith("1", "1-20250101000000.json");
  });

  it("GET /api/users/:uid/raw 应返回原始数据", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/api/users/1/raw", params: { uid: "1" } }, res);
    expect(adminService.getRawJson).toHaveBeenCalledWith("1");
    expect(res.json).toHaveBeenCalledWith({ status: { uid: "1" } });
  });

  it("GET /api/users/:uid/mails 与 DELETE mails/:mailId 应透传", async () => {
    const res1 = mockRes();
    await call({ method: "GET", url: "/api/users/1/mails", params: { uid: "1" } }, res1);
    expect(adminService.listMails).toHaveBeenCalledWith("1");

    const res2 = mockRes();
    await call({ method: "DELETE", url: "/api/users/1/mails/1000001", params: { uid: "1", mailId: "1000001" } }, res2);
    expect(adminService.deleteMail).toHaveBeenCalledWith("1", 1000001);
  });

  it("POST /api/mail 与 /api/mail/all 应区分单发/群发", async () => {
    const res1 = mockRes();
    await call(
      { method: "POST", url: "/api/mail", body: { uid: "1", subject: "hi", content: "", items: [] } },
      res1,
    );
    expect(adminService.sendMail).toHaveBeenCalled();

    const res2 = mockRes();
    await call(
      { method: "POST", url: "/api/mail/all", body: { subject: "公告", content: "", items: [] } },
      res2,
    );
    expect(adminService.sendMailAll).toHaveBeenCalledWith({
      subject: "公告",
      content: "",
      items: [],
    });
    expect(res2.status).toHaveBeenCalledWith(201);
  });

  it("POST /api/users/:uid/refresh 与 /save 应透传", async () => {
    const res1 = mockRes();
    await call({ method: "POST", url: "/api/users/1/refresh", params: { uid: "1" }, body: {} }, res1);
    expect(adminService.refreshUser).toHaveBeenCalledWith("1");

    const res2 = mockRes();
    await call({ method: "POST", url: "/api/users/1/save", params: { uid: "1" }, body: {} }, res2);
    expect(adminService.saveUser).toHaveBeenCalledWith("1");
  });

  it("GET /api/stats /api/logs /api/common-items 应返回数据", async () => {
    const res1 = mockRes();
    await call({ method: "GET", url: "/api/stats" }, res1);
    expect(adminService.stats).toHaveBeenCalled();

    const res2 = mockRes();
    await call({ method: "GET", url: "/api/logs", query: { limit: "10" } }, res2);
    expect(adminService.logs).toHaveBeenCalledWith(10);

    const res3 = mockRes();
    await call({ method: "GET", url: "/api/common-items" }, res3);
    expect(adminService.getCommonItems).toHaveBeenCalled();
  });
});
