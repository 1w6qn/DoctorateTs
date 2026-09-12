import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/** excel 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

const mainMock = vi.fn().mockResolvedValue(0);
const excelInitMock = vi.fn().mockResolvedValue(undefined);
const warmupMock = vi.fn().mockResolvedValue(0);

vi.mock("../../../scripts/official-api", () => ({
  getResVersion: vi.fn(),
}));
vi.mock("../../../scripts/update-data", () => ({ main: mainMock }));
vi.mock("@core/config/index", () => ({
  default: { version: { resVersion: "v-local", clientVersion: "c" } },
}));
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },
    // 本文件不提供的表显式占位（`undefined` 与「键不存在」在 `?.` 读取下运行时等价）
    ItemTable: undefined as { items?: Record<string, ExcelRowMock> } | undefined,
    CharacterTable: undefined as Record<string, ExcelRowMock> | undefined,
    StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
 init: excelInitMock, warmupLazyTables: warmupMock },
}));

import { autoUpdateWatch } from "@ops/updater/auto-update-watch";
import { getResVersion } from "../../../scripts/official-api";

const mockedGetResVersion = vi.mocked(getResVersion);

beforeEach(() => {
  autoUpdateWatch.stop();
  mainMock.mockClear();
  excelInitMock.mockClear();
  warmupMock.mockClear();
  mockedGetResVersion.mockReset();
});

afterEach(() => {
  autoUpdateWatch.stop();
});

describe("autoUpdateWatch（运行期自动更新）", () => {
  it("版本未变化时不触发解包重签", async () => {
    mockedGetResVersion.mockResolvedValue({ resVersion: "v-local", clientVersion: "c" });
    await autoUpdateWatch.check();
    expect(mainMock).not.toHaveBeenCalled();
  });

  it("检测到官服版本变动 → 自动拉取+解包重签并热重载 excel", async () => {
    mockedGetResVersion.mockResolvedValue({ resVersion: "v-new", clientVersion: "c" });
    await autoUpdateWatch.check();
    expect(mainMock).toHaveBeenCalledTimes(1);
    expect(excelInitMock).toHaveBeenCalledTimes(1);
    expect(warmupMock).toHaveBeenCalledTimes(1);
  });

  it("探测失败仅告警，不崩溃", async () => {
    mockedGetResVersion.mockRejectedValue(new Error("network down"));
    await expect(autoUpdateWatch.check()).resolves.toBeUndefined();
    expect(mainMock).not.toHaveBeenCalled();
  });

  it("start 幂等；running 锁在繁忙时置 busy", async () => {
    // start 的即刻探测用同版本，快速返回，不干扰幂等断言
    mockedGetResVersion.mockResolvedValue({ resVersion: "v-local", clientVersion: "c" });
    autoUpdateWatch.start(99999);
    autoUpdateWatch.start(99999); // 幂等：不重复启动
    await new Promise((r) => setTimeout(r, 20)); // 等即刻探测结束
    autoUpdateWatch.stop();

    // running 锁：慢响应期间 busy 置位，完成复位
    mockedGetResVersion.mockImplementation(
      () => new Promise((r) => setTimeout(() => r({ resVersion: "b", clientVersion: "c" }), 50)),
    );
    const p = autoUpdateWatch.check();
    expect(autoUpdateWatch.busy).toBe(true);
    await p;
    expect(autoUpdateWatch.busy).toBe(false);
    autoUpdateWatch.stop();
  });
});