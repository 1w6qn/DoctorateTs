import { describe, it, expect, vi, beforeEach } from "vitest";
// PlayerDataManager 构造挂载 mission.init（fire-and-forget）需要 Immer Patches 插件——
// 缺失会报「The plugin for 'Patches' has not been loaded」unhandled rejection（假阳性噪音）

const configMock = vi.hoisted(() => ({ default: { authMode: "single" } }));
vi.mock("@core/config/index", () => configMock);
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    writeFile: vi.fn().mockResolvedValue(undefined),
    rename: vi.fn().mockResolvedValue(undefined),
  };
});
vi.mock("@utils/file", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@utils/file")>();
  return { ...actual, readJson: vi.fn(actual.readJson) };
});

import { accountManager } from "../../../app/game/service/player/AccountManager";

describe("AccountManager 抽卡保底计数", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    (accountManager as any).configs = {
      "2222": {
        auth: { phone: "2222" },
        gacha: {},
      },
    };
  });

  it("未初始化的 gachaType 应返回 0（不 500）", async () => {
    const cnt = await accountManager.getBeforeNonHitCnt("2222", "NORMAL");
    expect(cnt).toBe(0);
  });

  it("saveBeforeNonHitCnt 应惰性初始化 gachaType 并写入计数", async () => {
    const emitSpy = vi.spyOn((accountManager as any)._trigger ?? { emit: vi.fn() }, "emit");
    // 若 _trigger 未挂载则补挂（测试环境直接操作 configs）
    if (!(accountManager as any)._trigger) {
      (accountManager as any)._trigger = { emit: emitSpy };
    }
    await accountManager.saveBeforeNonHitCnt("2222", "NORMAL", 7);
    expect((accountManager as any).configs["2222"].gacha.NORMAL).toEqual({
      beforeNonHitCnt: 7,
    });
    const cnt = await accountManager.getBeforeNonHitCnt("2222", "NORMAL");
    expect(cnt).toBe(7);
  });

  it("saveBeforeNonHitCnt 已存在 gachaType 时应覆盖计数", async () => {
    (accountManager as any).configs["2222"].gacha.NORMAL = { beforeNonHitCnt: 3 };
    if (!(accountManager as any)._trigger) {
      (accountManager as any)._trigger = { emit: vi.fn() };
    }
    await accountManager.saveBeforeNonHitCnt("2222", "NORMAL", 9);
    expect((accountManager as any).configs["2222"].gacha.NORMAL).toEqual({
      beforeNonHitCnt: 9,
    });
  });
});
