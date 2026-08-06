import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));

import accountRouter from "../../../app/game/router/account";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  accountRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("account 路由", () => {
  let mockPlayer: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = {
      delta: { modified: {} },
      update: vi.fn().mockImplementation(async (recipe: any) => {
        const draft: any = { pushFlags: { status: 0 } };
        await recipe(draft);
        mockPlayer._playerdata.pushFlags.status = draft.pushFlags.status;
      }),
      _playerdata: { pushFlags: { status: 0 } },
      _trigger: { emit: vi.fn().mockResolvedValue(undefined) },
    };
    (vi.mocked(httpContext.get) as any).mockReturnValue(mockPlayer);
  });

  it("login 应返回固定登录结果", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/login" }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, uid: "1", secret: "1" }),
    );
  });

  it("syncData 应直改 pushFlags.status（不走 Immer，避免深拷贝）并返回 user", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/syncData" }, res);
    // 直改登录时间戳（不调 update——全量同步无需 delta）
    expect(mockPlayer.update).not.toHaveBeenCalled();
    expect(mockPlayer._playerdata.pushFlags.status).toBe(1234567890);
    const arg = res.send.mock.calls[0][0];
    expect(arg.result).toBe(0);
    expect(arg.ts).toBe(1234567890);
    expect(arg.user).toBe(mockPlayer);
  });

  it("syncStatus 应触发 status:refresh:time 事件", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/syncStatus" }, res);
    expect(mockPlayer._trigger.emit).toHaveBeenCalledWith("status:refresh:time", []);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ ts: 1234567890, result: {} }),
    );
  });

  it("syncPushMessage 应返回 delta", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/syncPushMessage" }, res);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
