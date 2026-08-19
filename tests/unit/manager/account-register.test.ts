import { describe, it, expect, beforeEach, vi } from "vitest";
// registerUser 现在会加载玩家（_loadPlayer 构造 PlayerDataManager，mission.init 需要 Immer Patches 插件）

const configMock = vi.hoisted(() => ({ default: { authMode: "real" } }));
vi.mock("../../../app/config", () => configMock);

import { accountManager } from "../../../app/game/manager/AccountManager";
import { mockPlayerData } from "../../helpers";
import { hashPassword, verifyPassword } from "@utils/crypt";

vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined), rename: vi.fn().mockResolvedValue(undefined) };
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
    // 内存配置更新（密码哈希存储——不落明文）
    expect((accountManager as any).configs["2"].auth.phone).toBe("13900000000");
    expect(verifyPassword((accountManager as any).configs["2"].password, "pwd2")).toBe(true);
    expect((accountManager as any).configs["2"].password).toMatch(/^sha256\$/);
    expect(saveUserConfigSpy).toHaveBeenCalled();
  });

  it("registerUser 后玩家数据已加载（searchPlayer 立即可搜，免重启）", async () => {
    const uid = await accountManager.registerUser("13900000000", "pwd2");
    const found = await accountManager.searchPlayer(uid);
    expect(found).toContain(uid);
  });

  it("registerUser 手机号重复应抛错", async () => {
    await expect(accountManager.registerUser("13800000000", "x")).rejects.toThrow("已存在");
  });

  it("tokenByPhonePassword 账号不存在应自动注册", async () => {
    const token = await accountManager.tokenByPhonePassword("13911112222", "pwd3");
    // 自动注册返回新账号的 secret 作为 token（参考 DoctoratePy token=secret 模型）
    expect(token).toBe((accountManager as any).configs["2"].secret);
    expect((accountManager as any).configs["2"].auth.phone).toBe("13911112222");
    // 密码哈希存储
    expect(verifyPassword((accountManager as any).configs["2"].password, "pwd3")).toBe(true);
    expect((accountManager as any).configs["2"].password).toMatch(/^sha256\$/);
  });

  it("tokenByPhonePassword 账号存在应返回原 token（不重复创建）", async () => {
    const before = Object.keys((accountManager as any).configs).length;
    const token = await accountManager.tokenByPhonePassword("13800000000", "pwd1");
    expect(token).toBe("1");
    expect(Object.keys((accountManager as any).configs).length).toBe(before);
  });
});
