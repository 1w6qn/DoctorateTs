import { describe, it, expect, vi, beforeEach } from "vitest";

const configMock = vi.hoisted(() => ({ default: { authMode: "single" } }));
vi.mock("../../../app/config", () => configMock);
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined), rename: vi.fn().mockResolvedValue(undefined) };
});
// readJson 默认走真实实现（读文件），懒加载用例可 mockResolvedValueOnce 覆盖
vi.mock("@utils/file", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@utils/file")>();
  return { ...actual, readJson: vi.fn(actual.readJson) };
});

import { accountManager } from "../../../app/game/manager/AccountManger";
import config from "../../../app/config";
import { readJson } from "@utils/file";
import { readFileSync } from "fs";

describe("getUidByToken 认证模式", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    configMock.default.authMode = "single";
    configMock.default.singleUid = undefined;
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

  it("single 模式配置 singleUid 时收敛到该账号（过渡用）", async () => {
    (config as any).authMode = "single";
    (config as any).singleUid = "2222";
    expect(await accountManager.getUidByToken("any")).toBe("2222");
    expect(await accountManager.tokenByPhonePassword("x", "y")).toBe("2222");
  });

  it("ensureSingleUser 应创建缺失的单例账号（干净模板）", async () => {
    const spy = vi
      .spyOn(accountManager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
    await accountManager.ensureSingleUser("2222");
    const conf = (accountManager as any).configs["2222"];
    expect(conf).toBeDefined();
    expect(conf.auth.phone).toBe("2222");
    expect(conf.secret).toBeDefined();
    expect(spy).toHaveBeenCalled();
  });

  it("ensureSingleUser 后应加载玩家数据（getPlayerData 可用）", async () => {
    const spy = vi
      .spyOn(accountManager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
    await accountManager.ensureSingleUser("2222");
    const data = (accountManager as any).data["2222"];
    expect(data).toBeDefined();
    expect(data._playerdata.status.uid).toBe("2222");
  });

  it("ensureSingleUser 账号已存在时应直接返回", async () => {
    const spy = vi
      .spyOn(accountManager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
    await accountManager.ensureSingleUser("1");
    expect(spy).not.toHaveBeenCalled();
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

  it("getTokenByUid 应返回账号 secret（无 secret 旧账号回退 uid）", async () => {
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, secret: "abc123" },
      "2": { auth: { phone: "2" } },
    };
    expect(await accountManager.getTokenByUid("1")).toBe("abc123");
    expect(await accountManager.getTokenByUid("2")).toBe("2");
  });

  it("getPlayerData 懒加载：data 缺失时从存档文件加载（real 模式注册后免重启）", async () => {
    // 用真实 1.json 模板构造完整 playerdata（PlayerDataManager 构造需要完整字段）
    const raw = JSON.parse(readFileSync("./data/user/databases/1.json", "utf8"));
    raw.status.uid = "7";
    (vi.mocked(readJson) as any).mockResolvedValueOnce(raw);
    (accountManager as any).data = {}; // 模拟未加载状态
    const player = await accountManager.getPlayerData("7");
    expect(player).toBeDefined();
    expect((player as any)._playerdata.status.uid).toBe("7");
  });
});
