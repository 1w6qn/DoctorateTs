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
vi.mock("../../../app/db/user-repo", () => ({
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

vi.mock("fs", () => ({
  readFileSync: vi.fn((file: any) => {
    if (String(file).includes("databases")) return templateContent;
    if (String(file).includes("users.json")) return usersContent;
    return accountsContent;
  }),
}));
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
    (syncPlayerData as any).mockResolvedValue({
      status: { uid: "10001", nickName: "A" },
      troop: {},
    });
    (registerImportedUser as any).mockResolvedValue({ uid: "2", nickName: "A" });

    const results = await runMigration({
      accountsPath: "test.txt",
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
    (syncPlayerData as any)
      .mockRejectedValueOnce(new Error("login failed"))
      .mockResolvedValueOnce({ status: { uid: "10002", nickName: "B" }, troop: {} });
    (registerImportedUser as any).mockResolvedValue({ uid: "3", nickName: "B" });

    const results = await runMigration({
      accountsPath: "test.txt",
      templateUid: "1",
    });
    expect(results).toHaveLength(2);
    expect(results[0].error).toBeDefined();
    expect(results[1].uid).toBe("3");
  });

  it("convertedData 应使用模板兜底", async () => {
    (syncPlayerData as any).mockResolvedValue({ status: { uid: "10001" } });
    (registerImportedUser as any).mockResolvedValue({ uid: "2", nickName: "" });

    await runMigration({ accountsPath: "test.txt", templateUid: "1" });
    const call = (registerImportedUser as any).mock.calls[0][0];
    const converted = call.convertedData;
    // 模板兜底字段（official-convert 内部逻辑）
    expect(converted.status.uid).toBe("2");
  });
});
