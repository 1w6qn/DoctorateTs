import { describe, it, expect, vi, beforeEach } from "vitest";
// PlayerDataManager 构造挂载 mission.init（fire-and-forget）需要 Immer Patches 插件——
// 缺失会报「The plugin for 'Patches' has not been loaded」unhandled rejection（假阳性噪音）

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

import { accountManager } from "../../../app/game/manager/AccountManager";
import config from "../../../app/config";
import { readJson } from "@utils/file";
import { readFileSync } from "fs";
import { writeFile, rename } from "fs/promises";

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

  it("ensureSingleUser 在 1.json 缺失时回退 player_data.json 官服基底（S3）", async () => {
    const spy = vi
      .spyOn(accountManager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
    (vi.mocked(readJson) as any)
      .mockRejectedValueOnce(new Error("ENOENT")) // 1.json 缺失
      .mockResolvedValueOnce(JSON.parse(readFileSync("./player_data.json", "utf8")));
    await accountManager.ensureSingleUser("9999");
    expect((accountManager as any).configs["9999"]).toBeDefined();
    expect(spy).toHaveBeenCalled();
  });

  it("real 模式：有效 uid 返回原样，未知 SDK token 兜底默认账号", async () => {
    (config as any).authMode = "real";
    expect(await accountManager.getUidByToken("2221")).toBe("2221");
    // 宽松兜底（对齐 ODPY）：客户端 SDK 会话 token 回退第一个配置账号
    expect(await accountManager.getUidByToken("aId1QCwRP8rVkxSYsG4bCzjQ")).toBe("1");
  });

  it("real 模式：token 匹配账号 secret 应返回对应 uid（参考 DoctoratePy query_account_by_secret）", async () => {
    (config as any).authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, secret: "secret_1" },
      "2221": { auth: { phone: "2221" }, secret: "secret_2221" },
    };
    expect(await accountManager.getUidByToken("secret_2221")).toBe("2221");
    expect(await accountManager.getUidByToken("secret_1")).toBe("1");
    // 未知 SDK token 兜底默认账号（非配置 key）
    expect(await accountManager.getUidByToken("unknown")).toBe("1");
  });

  it("registerUser 应生成账号 secret（MD5 密钥）——real 模式", async () => {
    (config as any).authMode = "real";
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
    // 旧明文账号登录成功后惰性升级为哈希（R7——不再明文存储）
    expect((accountManager as any).configs["1"].password).toMatch(/^sha256\$/);
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

  it("single 模式 registerUser 不建号（收敛固定账号，避免垃圾账号污染 configs/users）", async () => {
    (config as any).authMode = "single";
    (config as any).singleUid = undefined;
    expect(await accountManager.registerUser("13900009999", "pwd123456")).toBe("1");
    expect((accountManager as any).configs["13900009999"]).toBeUndefined();
    // 指定 singleUid 时收敛到该账号
    (config as any).singleUid = "2222";
    expect(await accountManager.registerUser("13900009999", "pwd123456")).toBe("2222");
  });

  it("real 模式：有 secret 的账号拒绝 uid 数字直通（必须用 secret 登录）", async () => {
    (config as any).authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, secret: "secret_1" },
      "2221": { auth: { phone: "2221" }, secret: "secret_2221" },
    };
    expect(await accountManager.getUidByToken("2221")).toBe("");
    expect(await accountManager.getUidByToken("1")).toBe("");
    expect(await accountManager.getUidByToken("secret_2221")).toBe("2221");
    expect(await accountManager.getUidByToken("secret_1")).toBe("1");
  });

  it("real 模式：无 secret 的旧账号保留 uid 直通（兼容迁移前账号）", async () => {
    (config as any).authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" } },
    };
    expect(await accountManager.getUidByToken("1")).toBe("1");
  });

  it("registerUser 原子写（.tmp + rename，避免写一半崩溃留坏档）", async () => {
    (config as any).authMode = "real";
    const writeMock = vi.mocked(writeFile);
    const renameMock = vi.mocked(rename);
    writeMock.mockClear();
    renameMock.mockClear();
    await accountManager.registerUser("13900009999", "pwd123456");
    const tmpWrite = writeMock.mock.calls.find((c: any) => String(c[0]).includes(".tmp"));
    expect(tmpWrite).toBeDefined();
    expect(renameMock).toHaveBeenCalledWith(
      expect.stringContaining("2222.json.tmp"),
      expect.stringContaining("2222.json"),
    );
  });

  it("getPlayerData 并发：同一 uid 共享一次加载（不双实例互踩）", async () => {
    (vi.mocked(readJson) as any).mockClear();
    const raw = JSON.parse(readFileSync("./data/user/databases/1.json", "utf8"));
    raw.status.uid = "8";
    (vi.mocked(readJson) as any).mockResolvedValueOnce(raw);
    // ShopController 构造时会异步读信用商店静态配置（SocialGoodList.json），一并给值
    (vi.mocked(readJson) as any).mockResolvedValueOnce({ goodList: [], charPurchase: {} });
    (accountManager as any).data = {};
    const [p1, p2] = await Promise.all([
      accountManager.getPlayerData("8"),
      accountManager.getPlayerData("8"),
    ]);
    expect(p1).toBe(p2);
    // 玩家数据只加载一次（第二次 readJson 为 ShopController 读 SocialGoodList 静态配置）
    const playerLoads = (vi.mocked(readJson) as any).mock.calls.filter(
      (c: any) => String(c[0]).includes("databases/8.json"),
    );
    expect(playerLoads).toHaveLength(1);
  });

  it("空闲账号清扫应卸载超时账号（先落盘；fresh 与 singleUid 保留）——D-1", async () => {
    (config as any).singleUid = "1";
    const manager = accountManager;
    (manager as any).data = { "1": {}, "2": {} };
    (manager as any)._lastAccess = {
      "1": Date.now(),
      "2": Date.now() - 40 * 60 * 1000, // 40 分钟前——超 30 分钟阈值
    };
    const flushSpy = vi
      .spyOn(manager, "flushSave")
      .mockResolvedValue(undefined as any);
    await (manager as any).sweepIdleAccounts();
    expect((manager as any).data["2"]).toBeUndefined();
    expect((manager as any).data["1"]).toBeDefined();
    expect(flushSpy).toHaveBeenCalledWith("2");
  });
});

describe("updatePassword / updatePhone（real 模式用户管理闭环）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    configMock.default.authMode = "real";
    (accountManager as any).configs = {
      "1": { auth: { phone: "1" }, secret: "secret_1" },
    };
  });

  it("updatePassword 应哈希存储新密码", async () => {
    const ok = await accountManager.updatePassword("1", "NewPwd123");
    expect(ok).toBe(true);
    const conf = (accountManager as any).configs["1"];
    expect(conf.password.startsWith("sha256$")).toBe(true);
    // 新密码可验证
    const { verifyPassword } = await import("@utils/crypt");
    expect(verifyPassword(conf.password, "NewPwd123")).toBe(true);
  });

  it("updatePassword 账号不存在返回 false", async () => {
    expect(await accountManager.updatePassword("999", "NewPwd123")).toBe(false);
  });

  it("updatePhone 应更新手机并刷新 secret", async () => {
    const ok = await accountManager.updatePhone("1", "13812345678");
    expect(ok).toBe(true);
    const conf = (accountManager as any).configs["1"];
    expect(conf.auth.phone).toBe("13812345678");
    expect(conf.secret).not.toBe("secret_1");
    expect(conf.secret).toBe(
      (await import("crypto")).createHash("md5").update("13812345678" + "7318def77669979d").digest("hex"),
    );
  });
});
