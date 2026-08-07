import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// databases 存档写入 mock（防真实落盘）；账号注册走 SQLite（:memory:）
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined) };
});

import { openDatabase, closeDatabase } from "../../../app/db/database";
import { UserRepository } from "../../../app/db/user-repo";
import { registerImportedUser } from "../../../scripts/official-register";

describe("registerImportedUser", () => {
  let repo: UserRepository;

  beforeEach(() => {
    vi.clearAllMocks();
    // 单例连接指向内存库（registerImportedUser 内部 openDatabase() 复用）
    openDatabase(":memory:");
    repo = new UserRepository(openDatabase());
  });

  afterEach(() => {
    closeDatabase();
  });

  it("应生成新 uid 并注册账号（写 SQLite users 表）", async () => {
    repo.upsert("1", { uid: "1", password: "p" } as any);
    const result = await registerImportedUser({
      phone: "13800000000",
      officialUid: "10001",
      convertedData: { status: { uid: "2", nickName: "A" } } as any,
    });
    expect(result.uid).toBe("2");
    // 存档写入（databases/2.json）
    const { writeFile } = await import("fs/promises");
    const writeFileMock = vi.mocked(writeFile);
    const saveCall = writeFileMock.mock.calls.find((c) => String(c[0]).includes("databases"));
    expect(saveCall).toBeDefined();
    expect(JSON.parse(saveCall![1]).status.uid).toBe("2");
    // SQLite 注册
    const users = repo.getAll();
    expect(users["2"].auth.phone).toBe("13800000000");
    expect(users["2"].auth.hgId).toBe("10001");
    expect(users["2"].social).toBeDefined();
  });

  it("连续注册应递增 uid（基于 SQLite 现有账号）", async () => {
    repo.upsert("1", { uid: "1", password: "p" } as any);
    await registerImportedUser({
      phone: "13800000000",
      officialUid: "10001",
      convertedData: { status: { uid: "2", nickName: "A" } } as any,
    });
    const result = await registerImportedUser({
      phone: "13800000001",
      officialUid: "10002",
      convertedData: { status: { uid: "3", nickName: "B" } } as any,
    });
    expect(result.uid).toBe("3");
  });
});
