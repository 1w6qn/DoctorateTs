import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../../app/config", () => ({
  default: { authMode: "single" },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined), rename: vi.fn().mockResolvedValue(undefined) };
});

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

  it("single 模式：任意 token 收敛到 uid=1（oauth2/basic/u8 全流程正常）", async () => {
    (config as any).authMode = "single";
    expect(await accountManager.getUidByToken("aId1QCwRP8rVkxSYsG4bCzjQ")).toBe("1");
    expect(await accountManager.getUidByToken("2221")).toBe("1");
    expect(await accountManager.getUidByToken("")).toBe("1");
  });

  it("single 模式 tokenByPhonePassword 返回固定 uid=1（不注册新账号）", async () => {
    (config as any).authMode = "single";
    expect(await accountManager.tokenByPhonePassword("13900001111", "any")).toBe("1");
    expect(await accountManager.tokenByPhonePassword("不存在", "pwd")).toBe("1");
  });

  it("real 模式：有效 uid 返回原样，无效 token 返回空串", async () => {
    (config as any).authMode = "real";
    expect(await accountManager.getUidByToken("2221")).toBe("2221");
    expect(await accountManager.getUidByToken("aId1QCwRP8rVkxSYsG4bCzjQ")).toBe("");
  });

  it("real 模式：token 匹配账号 secret 应返回对应 uid（参考 DoctoratePy query_account_by_secret）", async () => {
    (config as any).authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, secret: "secret_1" },
      "2221": { auth: { phone: "2221" }, secret: "secret_2221" },
    };
    expect(await accountManager.getUidByToken("secret_2221")).toBe("2221");
    expect(await accountManager.getUidByToken("secret_1")).toBe("1");
    expect(await accountManager.getUidByToken("unknown")).toBe("");
  });

  it("registerUser 应生成账号 secret（MD5 密钥）", async () => {
    const uid = await accountManager.registerUser("13900009999", "pwd123456");
    const conf = (accountManager as any).configs[uid];
    expect(conf.secret).toBeDefined();
    expect(conf.secret.length).toBe(32); // md5 hex
    // 同 phone 生成确定性 secret
    expect(conf.secret).toBe(
      (await import("crypto")).createHash("md5").update("13900009999" + "7318def77669979d").digest("hex"),
    );
  });

  it("real 模式 tokenByPhonePassword 应返回账号 secret（而非 uid）", async () => {
    (config as any).authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, password: "p1", secret: "secret_1" },
    };
    expect(await accountManager.tokenByPhonePassword("1", "p1")).toBe("secret_1");
  });
});
