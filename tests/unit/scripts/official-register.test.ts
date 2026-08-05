import { describe, it, expect, vi, beforeEach } from "vitest";

// 共享内存状态：users.json 写入后回读（模拟真实文件读回）
const state = vi.hoisted(() => {
  const users: any = { "1": { uid: "1", password: "p" } };
  return { users };
});

vi.mock("fs", () => ({
  readFileSync: vi.fn(() => JSON.stringify(state.users)),
}));
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    writeFile: vi.fn((file: any, content: string) => {
      if (String(file).includes("users.json")) {
        state.users = JSON.parse(content);
      }
      return Promise.resolve(undefined);
    }),
  };
});

import { registerImportedUser } from "../../../scripts/official-register";

describe("registerImportedUser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    state.users = { "1": { uid: "1", password: "p" } };
  });

  it("应生成新 uid 并注册账号", async () => {
    const { writeFile } = await import("fs/promises");
    const writeFileMock = vi.mocked(writeFile);

    const result = await registerImportedUser({
      phone: "13800000000",
      officialUid: "10001",
      convertedData: { status: { uid: "2", nickName: "A" } } as any,
    });
    expect(result.uid).toBe("2");
    // 存档写入（databases/2.json）
    const saveCall = writeFileMock.mock.calls.find((c) => String(c[0]).includes("databases"));
    expect(saveCall).toBeDefined();
    expect(JSON.parse(saveCall![1]).status.uid).toBe("2");
    // users.json 注册
    const usersCall = writeFileMock.mock.calls.find((c) => String(c[0]).includes("users.json"));
    expect(usersCall).toBeDefined();
    const users = JSON.parse(usersCall![1]);
    expect(users["2"].auth.phone).toBe("13800000000");
    expect(users["2"].auth.hgId).toBe("10001");
    expect(users["2"].social).toBeDefined();
  });

  it("连续注册应递增 uid", async () => {
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
