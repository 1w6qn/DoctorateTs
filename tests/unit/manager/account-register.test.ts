import { describe, it, expect, beforeEach, vi } from "vitest";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { mockPlayerData } from "../../helpers";

vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined) };
});
vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    readFileSync: vi.fn(() => JSON.stringify({ status: { uid: "1", nickName: "模板" } })),
  };
});

describe("AccountManager 创建新用户", () => {
  let saveUserConfigSpy: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    (accountManager as any).configs = {
      "1": {
        uid: "1",
        password: "pwd1",
        auth: { phone: "13800000000" },
      },
    };
    (accountManager as any).data = { "1": mockPlayerData({}) };
    saveUserConfigSpy = vi
      .spyOn(accountManager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
  });

  it("registerUser 应创建新用户（uid 递增并写存档）", async () => {
    const uid = await accountManager.registerUser("13900000000", "pwd2");
    expect(uid).toBe("2");
    // 存档写入（databases/2.json）
    const writeMock = vi.mocked((await import("fs/promises")).writeFile);
    const dbWrite = writeMock.mock.calls.find((c: any) => String(c[0]).includes("2.json"));
    expect(dbWrite).toBeDefined();
    // 内存配置更新
    expect((accountManager as any).configs["2"].auth.phone).toBe("13900000000");
    expect(saveUserConfigSpy).toHaveBeenCalled();
  });

  it("registerUser 手机号重复应抛错", async () => {
    await expect(accountManager.registerUser("13800000000", "x")).rejects.toThrow("已存在");
  });

  it("tokenByPhonePassword 账号不存在应自动注册", async () => {
    const token = await accountManager.tokenByPhonePassword("13911112222", "pwd3");
    // 自动注册返回新 uid 作为 token
    expect(token).toBe("2");
    expect((accountManager as any).configs["2"].auth.phone).toBe("13911112222");
    expect((accountManager as any).configs["2"].password).toBe("pwd3");
  });

  it("tokenByPhonePassword 账号存在应返回原 token（不重复创建）", async () => {
    const before = Object.keys((accountManager as any).configs).length;
    const token = await accountManager.tokenByPhonePassword("13800000000", "pwd1");
    expect(token).toBe("1");
    expect(Object.keys((accountManager as any).configs).length).toBe(before);
  });
});
