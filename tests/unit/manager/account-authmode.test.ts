import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../../app/config", () => ({
  default: { authMode: "single" },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));

import { accountManager } from "../../../app/game/manager/AccountManger";
import config from "../../../app/config";

describe("getUidByToken 认证模式", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" } },
      "2221": { auth: { phone: "2221" } },
    };
  });

  it("single 模式：token 原样返回（token=uid 简化）", async () => {
    (config as any).authMode = "single";
    expect(await accountManager.getUidByToken("aId1QCwRP8rVkxSYsG4bCzjQ")).toBe("aId1QCwRP8rVkxSYsG4bCzjQ");
    expect(await accountManager.getUidByToken("2221")).toBe("2221");
  });

  it("real 模式：有效 uid 返回原样，无效 token 返回空串", async () => {
    (config as any).authMode = "real";
    expect(await accountManager.getUidByToken("2221")).toBe("2221");
    expect(await accountManager.getUidByToken("aId1QCwRP8rVkxSYsG4bCzjQ")).toBe("");
  });
});
