/**
 * PlayerDataManager excel 数据端口注入测试
 *
 * 验证 DI 解耦成果（见 app/game/kernel/excel-port.ts）：
 *  - 缺省时端口绑定 `@excel/excel` 单例（行为与迁移前一致）；
 *  - `deps.excel` 可覆写端口，子模块经 `player.excel` 取到替身数据
 *    （以 DungeonManager 读 StageTable 为端到端证据）。
 */
import { describe, it, expect } from "vitest";
import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { mockExcel, mockPlayerData } from "../../helpers";

/** 构造真实 PlayerDataManager 所需的模型（复用 mock helper 的原始数据） */
function freshModel(extra: Record<string, unknown> = {}) {
  const pd: any = mockPlayerData({
    mission: { missions: {} },
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } },
    rlv2: { outer: {}, current: {}, pinned: {} },
    dungeon: { stages: {}, cowLevel: {}, hideStages: {}, mainlineBannedStages: [] },
    ...extra,
  });
  return pd._playerdata as any;
}

describe("PlayerDataManager excel 数据端口", () => {
  it("缺省绑定 @excel/excel 单例（端口可直接当单例用）", () => {
    const player = new PlayerDataManager(freshModel());
    expect(typeof player.excel.makeItem).toBe("function");
    expect(typeof player.excel.charData).toBe("function");
    expect(typeof player.excel.stageData).toBe("function");
  });

  it("deps.excel 覆写端口，子模块经 player.excel 读到注入的表", async () => {
    const fake = mockExcel();
    (fake as any).StageTable = {
      stages: { main_01: { stageId: "main_01" } },
      runeStageGroups: {},
    };

    const player = new PlayerDataManager(freshModel(), undefined, { excel: fake });
    expect(player.excel).toBe(fake);

    // 端到端证据：DungeonManager 通过组合根注入的端口读取 StageTable
    await player.dungeon.initStages();
    expect(Object.keys(player._playerdata.dungeon.stages)).toContain("main_01");
  });

  it("未注入端口的子模块仍走默认单例（与注入并存）", async () => {
    const player = new PlayerDataManager(freshModel(), undefined, { excel: mockExcel() });
    expect(player.excel.stageData("not_exists")).toBeUndefined();
    expect(player.inventory).toBeTruthy();
    expect(player.status).toBeTruthy();
  });
});
