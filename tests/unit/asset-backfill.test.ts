import { describe, it, expect, vi, beforeEach } from "vitest";

const mockConfig = vi.hoisted(() => ({
  Host: "http://127.0.0.1",
  PORT: 8443,
  version: {
    resVersion: "26-08-07-14-53-29_30b8f0",
    clientVersion: "2.7.61",
    windows: { resVersion: "26-08-07-10-51-39_26e0fc", clientVersion: "2.7.61" },
  },
  assets: {
    enableMods: false,
    downloadLocally: true,
    autoUpdate: true,
    downloadPeoxy: false,
    backfillVersions: [],
  },
  NetworkConfig: {},
}));

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => mockConfig),
  exists: vi.fn().mockResolvedValue(false),
  size: vi.fn().mockResolvedValue(0),
}));
// excel 仅用到 StageTable（本测试不触碰），空实现即可
vi.mock("@excel/excel", () => ({
  default: { ActivityTable: { basicInfo: {}, activity: {}, zoneToActivity: {} }, StageTable: { stages: {} } },
}));

const mockReadFile = vi.hoisted(() => vi.fn());
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    readFile: mockReadFile,
    copyFile: vi.fn().mockResolvedValue(undefined),
    mkdir: vi.fn().mockResolvedValue(undefined),
    writeFile: vi.fn().mockResolvedValue(undefined),
  };
});

import {
  flattenBundleName,
  levelBundleCandidates,
  officialVersion,
  crisisSeasonLevelRefs,
  collectActivityLevelRefs,
} from "../../../app/asset-backfill";

describe("asset-backfill 关卡 bundle 推导", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("flattenBundleName：/ → _、# → __、去扩展名、补 .dat", () => {
    expect(
      flattenBundleName("scenes/obt/rune/level_rune_04-01/level_rune_04-01.ab"),
    ).toBe("scenes_obt_rune_level_rune_04-01_level_rune_04-01.dat");
    expect(flattenBundleName("a/b#c.d")).toBe("a_b__c.dat");
  });

  it("levelBundleCandidates：由 levelId 推导场景与灯光 bundle（实测官方命名规则）", () => {
    const c = levelBundleCandidates("Obt/Rune/level_rune_04-01");
    expect(c).toContain("scenes_obt_rune_level_rune_04-01_level_rune_04-01.dat");
    expect(c).toContain(
      "scenes_obt_rune_level_rune_04-01_level_rune_04-01_lightingdata.dat",
    );
    expect(levelBundleCandidates("")).toEqual([]);
    expect(levelBundleCandidates("  ")).toEqual([]);
  });

  it("officialVersion：Windows 用独立版本，其余回退默认", () => {
    expect(officialVersion("Android")).toBe("26-08-07-14-53-29_30b8f0");
    expect(officialVersion("Windows")).toBe("26-08-07-10-51-39_26e0fc");
    expect(officialVersion("iOS")).toBe("26-08-07-14-53-29_30b8f0");
  });
});

describe("crisisSeasonLevelRefs 赛季关卡解析", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("V1 赛季从 data.seasonInfo[].stages 提取 stageId+levelId", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        data: {
          seasonInfo: [
            {
              seasonId: "rune_season_1_1",
              stages: {
                "level_rune_01-01": {
                  stageId: "level_rune_01-01",
                  levelId: "Obt/Rune/level_rune_01-01",
                },
                "level_rune_01-02": {
                  stageId: "level_rune_01-02",
                  levelId: "Obt/Rune/level_rune_01-02",
                },
              },
            },
          ],
        },
      }),
    );
    const refs = await crisisSeasonLevelRefs("cc1", false);
    expect(refs).toHaveLength(2);
    expect(refs[0]).toEqual({
      stageId: "level_rune_01-01",
      levelId: "Obt/Rune/level_rune_01-01",
    });
  });

  it("V2 赛季从 info.mapStageDataMap 提取", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        info: {
          mapStageDataMap: {
            "crisis_v2_02-01": {
              stageId: "level_crisis_v2_02-01",
              levelId: "Obt/Crisis/V2/level_crisis_v2_02-01",
            },
          },
        },
      }),
    );
    const refs = await crisisSeasonLevelRefs("cc2", true);
    expect(refs[0].stageId).toBe("level_crisis_v2_02-01");
    expect(refs[0].levelId).toBe("Obt/Crisis/V2/level_crisis_v2_02-01");
  });

  it("读取失败返回空数组（不抛错）", async () => {
    mockReadFile.mockRejectedValue(new Error("ENOENT"));
    expect(await crisisSeasonLevelRefs("cc0", false)).toEqual([]);
  });
});

describe("collectActivityLevelRefs 活动关卡收集", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("危机赛季 id 走赛季数据（无需 basicInfo）", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        data: {
          seasonInfo: [
            {
              stages: {
                "level_rune_09-01": { stageId: "level_rune_09-01", levelId: "Obt/Rune/level_rune_09-01" },
              },
            },
          ],
        },
      }),
    );
    // cc9 存在于 data/crisis/ 真实目录 → 赛季分支
    const refs = await collectActivityLevelRefs("cc9");
    expect(refs).toEqual([
      { stageId: "level_rune_09-01", levelId: "Obt/Rune/level_rune_09-01" },
    ]);
  });

  it("未知活动返回空", async () => {
    const refs = await collectActivityLevelRefs("no_such_activity");
    expect(refs).toEqual([]);
  });
});
