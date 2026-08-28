import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@ops/admin/AdminService", () => ({
  adminService: {},
}));
vi.mock("@ops/admin/admin-auth", () => ({
  adminAuth: vi.fn((_req: any, _res: any, next: any) => next()),
}));
vi.mock("@ops/admin/cli-exec", () => ({ cliExec: vi.fn() }));
vi.mock("@core/config/index", () => ({ default: {} }));
vi.mock("@capture/capture-manager", () => ({ captureManager: {} }));
vi.mock("@logs/log-service", () => ({ logService: {} }));
vi.mock("@utils/sse", () => ({ createSse: vi.fn(() => () => {}), sseSend: vi.fn() }));
vi.mock("@plugin/index", () => ({
  pluginConfigService: {
    getAll: vi.fn(),
    setEnabled: vi.fn(),
  },
}));

import adminRouter from "@ops/admin/admin-router";
import { pluginConfigService } from "@plugin/index";

function mockRes() {
  return {
    send: vi.fn(),
    sendFile: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
    sendStatus: vi.fn(),
    set: vi.fn().mockReturnThis(),
  };
}

async function call(req: any, res: any) {
  adminRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("admin 插件管理端点", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("GET /api/plugin 应返回插件列表", async () => {
    vi.mocked(pluginConfigService.getAll).mockResolvedValue([
      { id: "enemy_hp", name: "敌人血量显示", desc: "", enabled: true },
    ]);
    const res = mockRes();
    await call({ method: "GET", url: "/api/plugin" }, res);
    expect(pluginConfigService.getAll).toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({
      plugins: [{ id: "enemy_hp", name: "敌人血量显示", desc: "", enabled: true }],
    });
  });

  it("POST /api/plugin/:id/enable 应启用插件", async () => {
    vi.mocked(pluginConfigService.setEnabled).mockResolvedValue(true);
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/plugin/enemy_hp/enable", params: { id: "enemy_hp" } },
      res,
    );
    expect(pluginConfigService.setEnabled).toHaveBeenCalledWith("enemy_hp", true);
    expect(res.json).toHaveBeenCalledWith({ ok: true, id: "enemy_hp", enabled: true });
  });

  it("POST /api/plugin/:id/disable 应停用插件", async () => {
    vi.mocked(pluginConfigService.setEnabled).mockResolvedValue(false);
    const res = mockRes();
    await call(
      { method: "POST", url: "/api/plugin/battle_assist/disable", params: { id: "battle_assist" } },
      res,
    );
    expect(pluginConfigService.setEnabled).toHaveBeenCalledWith("battle_assist", false);
    expect(res.json).toHaveBeenCalledWith({ ok: true, id: "battle_assist", enabled: false });
  });

  it("enable 时插件不存在应返回 400", async () => {
    vi.mocked(pluginConfigService.setEnabled).mockRejectedValue(new Error("未知插件: nope"));
    const res = mockRes();
    await call({ method: "POST", url: "/api/plugin/nope/enable", params: { id: "nope" } }, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: "未知插件: nope" });
  });
});