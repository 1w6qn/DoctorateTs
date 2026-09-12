import { describe, it, expect, vi, beforeEach } from "vitest";
import type { MockedFunction } from "vitest";
import type { readJson } from "@utils/file";

vi.mock("@utils/file", () => ({
  readJson: vi.fn(),
}));
vi.mock("@utils/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import excel from "@game/excel/excel";

describe("Excel.init 并行加载", () => {
  /** `readJson` 的替身（`vi.mocked` 后仍是真实签名：`<T>(filePath: string) => Promise<T>`） */
  let readJsonMock: MockedFunction<typeof readJson>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    readJsonMock = vi.mocked((await import("@utils/file")).readJson);
    // 所有表返回简单对象（按文件名区分）
    readJsonMock.mockImplementation(async (path: string) => ({
      _source: path,
      stages: { main_01_07: {} },
    }));
  });

  it("应加载全部数据表并正确赋值", async () => {
    await excel.init();
    expect(excel.MissionTable).toBeDefined();
    expect(excel.CharacterTable).toBeDefined();
    expect(excel.StageTable).toBeDefined();
    expect(excel.ZoneTable).toBeDefined();
    expect(excel.RoguelikeConsts).toBeDefined();
    // StageTable 已赋值（normalizeStageDropInfo 依赖）
    expect(excel.StageTable.stages).toBeDefined();
  });

  it("应读取所有表文件（并行 Promise.all 发起）", async () => {
    await excel.init();
    expect(readJsonMock.mock.calls.length).toBeGreaterThan(40);
    // 覆盖关键路径
    const paths = readJsonMock.mock.calls.map((c) => c[0]);
    expect(paths).toContain("./data/excel/mission_table.json");
    expect(paths).toContain("./data/excel/character_table.json");
    // RoguelikeConsts 由本表派生（不再读取 data/rlv2.json）
    expect(paths).toContain("./data/excel/roguelike_topic_table.json");
  });
});
