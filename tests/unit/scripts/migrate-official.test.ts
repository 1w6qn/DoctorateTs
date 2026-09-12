import { describe, it, expect, vi, beforeEach } from "vitest";

// mock 官服 API 与注册模块（不真实登录）
vi.mock("../../../scripts/official-api", () => ({
  syncPlayerData: vi.fn(),
}));
vi.mock("../../../scripts/official-register", () => ({
  registerImportedUser: vi.fn(),
  loadUsers: vi.fn(() => ({ "1": { uid: "1" } })),
  nextUid: vi.fn(() => "2"),
}));
// readUsers 改走 SQLite——mock user-repo 返回种子用户（避免真实 social.db）
vi.mock("@core/db/user-repo", () => ({
  UserRepository: class {
    getAll() {
      return { "1": { uid: "1" } };
    }
  },
  migrateUsersFromJsonFile: vi.fn(),
}));

const accountsContent = vi.hoisted(
  () => "13800000000\npwd123\n测试用\n13900000000\npwd456\n第二个",
);
const templateContent = vi.hoisted(() =>
  JSON.stringify({ status: { uid: "1" }, recruit: { normal: { slots: {} } } }),
);
const usersContent = vi.hoisted(() => JSON.stringify({ "1": { uid: "1" } }));

// 部分 mock：只替换 readFileSync，其余走真实实现
// - data/config.json：@core/config 在模块加载时读取（db 层解析后端配置会引入它），
//   空对象即「全部走缺省值」；不特判会被下面的兜底当成账号文本而 JSON 解析失败
// - 不能用「只导出 readFileSync」的整模块替换：@utils/logger 的落盘定时器会用到
//   fs.existsSync/readdirSync，缺导出会在测试结束后抛 unhandled error
vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    readFileSync: vi.fn((file: Parameters<typeof actual.readFileSync>[0]) => {
      if (String(file).includes("config.json")) return "{}";
      if (String(file).includes("databases")) return templateContent;
      if (String(file).includes("users.json")) return usersContent;
      return accountsContent;
    }),
  };
});
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined) };
});

import { runMigration } from "../../../scripts/migrate-official";
import { syncPlayerData } from "../../../scripts/official-api";
import { registerImportedUser } from "../../../scripts/official-register";
import { convertOfficialData } from "../../../scripts/official-convert";

describe("runMigration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("应按账号逐行迁移并注册", async () => {
    vi.mocked(syncPlayerData).mockResolvedValue({
      status: { uid: "10001", nickName: "A" },
      troop: {},
    });
    vi.mocked(registerImportedUser).mockResolvedValue({ uid: "2", nickName: "A" });

    const results = await runMigration({
      accounts: accountsContent,
      templateUid: "1",
    });

    expect(syncPlayerData).toHaveBeenCalledWith("13800000000", "pwd123");
    expect(registerImportedUser).toHaveBeenCalledWith(
      expect.objectContaining({ phone: "13800000000", officialUid: "10001" }),
    );
    expect(results).toHaveLength(2);
    expect(results[0].uid).toBe("2");
  });

  it("单个账号失败不应中断其他账号", async () => {
    vi.mocked(syncPlayerData)
      .mockRejectedValueOnce(new Error("login failed"))
      .mockResolvedValueOnce({ status: { uid: "10002", nickName: "B" }, troop: {} });
    vi.mocked(registerImportedUser).mockResolvedValue({ uid: "3", nickName: "B" });

    const results = await runMigration({
      accounts: accountsContent,
      templateUid: "1",
    });
    expect(results).toHaveLength(2);
    expect(results[0].error).toBeDefined();
    expect(results[1].uid).toBe("3");
  });

  it("convertedData 应使用模板兜底", async () => {
    vi.mocked(syncPlayerData).mockResolvedValue({ status: { uid: "10001" } });
    vi.mocked(registerImportedUser).mockResolvedValue({ uid: "2", nickName: "" });

    await runMigration({ accounts: accountsContent, templateUid: "1" });
    const call = vi.mocked(registerImportedUser).mock.calls[0][0];
    const converted = call.convertedData;
    // 模板兜底字段（official-convert 内部逻辑）
    expect(converted.status!.uid).toBe("2");
  });
});
