import { describe, it, expect, vi, beforeEach } from "vitest";

// 策略模块经 @game/service/player/AccountManager 访问 accountManager —— mock 以便隔离验证
vi.mock("@game/modules/account/AccountManager", () => ({
  accountManager: { getUidByToken: vi.fn(), registerUser: vi.fn() },
}));

import { accountManager } from "@game/modules/account/AccountManager";
import {
  SingleAccountStrategy,
  RealAccountStrategy,
  createAuthStrategy,
} from "@game/kernel/http/auth-strategy";

/** 构造最小 Express 请求对象 */
function mockReq(headers: Record<string, unknown> = {}): any {
  return { headers };
}

describe("SingleAccountStrategy 单账号私服策略", () => {
  it("缺省 uid 固定为 1（兼容任意/缺失 secret）", async () => {
    const s = new SingleAccountStrategy({ authMode: "single" });
    expect(await s.resolveUid(mockReq({ secret: "2221" }))).toBe("1");
    expect(await s.resolveUid(mockReq({ secret: "aId1QCwRP8rVkxSYsG4bCzjQ" }))).toBe("1");
    expect(await s.resolveUid(mockReq({}))).toBe("1");
    expect(s.forceSecretHeader).toBe(true);
  });

  it("配置 singleUid 时固定返回该账号（过渡用）", async () => {
    const s = new SingleAccountStrategy({ authMode: "single", singleUid: "2222" });
    expect(await s.resolveUid(mockReq({ secret: "any" }))).toBe("2222");
  });

  it("registerUid 收敛到固定账号（不真正建号）", async () => {
    const s = new SingleAccountStrategy({ authMode: "single" });
    expect(await s.registerUid("13900001111", "pwd123456")).toBe("1");
    const s2 = new SingleAccountStrategy({ authMode: "single", singleUid: "2222" });
    expect(await s2.registerUid("x", "y")).toBe("2222");
  });
});

describe("RealAccountStrategy 真实多账号策略", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("有效 secret（账号 token）→ 解析出对应 uid", async () => {
    (accountManager.getUidByToken as any).mockResolvedValue("2221");
    const s = new RealAccountStrategy();
    expect(await s.resolveUid(mockReq({ secret: "secret_2221" }))).toBe("2221");
    expect(accountManager.getUidByToken).toHaveBeenCalledWith("secret_2221");
    expect(s.forceSecretHeader).toBe(false);
  });

  it("无效 secret → undefined（中间件据此返回 401）", async () => {
    (accountManager.getUidByToken as any).mockResolvedValue("");
    const s = new RealAccountStrategy();
    expect(await s.resolveUid(mockReq({ secret: "bad" }))).toBeUndefined();
  });

  it("缺失 secret → undefined", async () => {
    const s = new RealAccountStrategy();
    expect(await s.resolveUid(mockReq({}))).toBeUndefined();
  });

  it("registerUid 委托 AccountManager 真正建号", async () => {
    (accountManager.registerUser as any).mockResolvedValue("42");
    const s = new RealAccountStrategy();
    expect(await s.registerUid("13800000000", "pwd123456")).toBe("42");
    expect(accountManager.registerUser).toHaveBeenCalledWith("13800000000", "pwd123456");
  });
});

describe("createAuthStrategy 工厂（唯一 authMode 决策点）", () => {
  it("real → RealAccountStrategy；single/缺省 → SingleAccountStrategy", () => {
    expect(createAuthStrategy({ authMode: "real" })).toBeInstanceOf(RealAccountStrategy);
    expect(createAuthStrategy({ authMode: "single" })).toBeInstanceOf(SingleAccountStrategy);
    expect(createAuthStrategy({})).toBeInstanceOf(SingleAccountStrategy);
  });
});