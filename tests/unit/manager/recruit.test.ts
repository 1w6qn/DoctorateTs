import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({ default: {} }));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/types_auto_gen", () => ({}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { RecruitManager } from "@game/manager/recruit";

describe("RecruitManager sync", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      recruit: {
        normal: {
          slots: {
            "0": { state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 1000, durationInSec: 32400, maxFinishTs: 2000, realFinishTs: 1000 },
            "1": { state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 2000, durationInSec: 32400, maxFinishTs: 1234568000, realFinishTs: 1234568000 },
            "2": { state: 1, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: -1, durationInSec: -1, maxFinishTs: -1, realFinishTs: -1 },
          },
        },
      } as any,
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("sync 应将已到期的招募槽位标记为可领取（state=3）", async () => {
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.sync();
    const slots = mockPlayer._playerdata.recruit!.normal.slots;
    // 槽位 0：realFinishTs=1000 <= now，应变为 3
    expect(slots["0"].state).toBe(3);
    // 槽位 1：realFinishTs 未到期，保持 2
    expect(slots["1"].state).toBe(2);
    // 槽位 2：空闲，保持 1
    expect(slots["2"].state).toBe(1);
  });
});

describe("RecruitManager 核心方法", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      recruit: {
        normal: {
          slots: {
            "0": { state: 1, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: -1, durationInSec: -1, maxFinishTs: -1, realFinishTs: -1 },
          },
        },
      } as any,
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("refreshTags 应刷新槽位标签", async () => {
    const { RecruitTools } = await import("@game/manager/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([2, 4, 6, 8, 10] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.refreshTags({ slotId: 0 });
    expect(mockPlayer._playerdata.recruit!.normal.slots["0"].tags).toEqual([2, 4, 6, 8, 10]);
  });

  it("cancel 应重置槽位状态", async () => {
    const { RecruitTools } = await import("@game/manager/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([9, 9, 9, 9, 9] as any);
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [], selectTags: [{ tagId: 1, pick: 1 }], startTs: 100, durationInSec: 32400, maxFinishTs: 200, realFinishTs: 200,
    } as any;
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.cancel({ slotId: 0 });
    const slot = mockPlayer._playerdata.recruit!.normal.slots["0"];
    expect(slot.state).toBe(1);
    expect(slot.selectTags).toEqual([]);
    expect(slot.realFinishTs).toBe(-1);
    expect(slot.tags).toEqual([9, 9, 9, 9, 9]);
  });

  it("normalGacha 应开始招募并消耗招募券", async () => {
    const { RecruitTools } = await import("@game/manager/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([1, 2, 3, 4, 5] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await manager.normalGacha({ slotId: 0, tagList: [1, 3], specialTagId: 0, duration: 32400 });
    const slot = mockPlayer._playerdata.recruit!.normal.slots["0"];
    expect(slot.state).toBe(2);
    expect(slot.selectTags).toEqual([{ tagId: 1, pick: 1 }, { tagId: 3, pick: 1 }]);
    expect(slot.maxFinishTs).toBe(1234567890 + 32400);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "7001", count: 1, type: "TKT_RECRUIT" }]]);
  });

  it("finish 应结算招募并出干员", async () => {
    const { RecruitTools } = await import("@game/manager/recruit");
    vi.spyOn(RecruitTools, "generateValidTags").mockResolvedValue(["char_001", [1]] as any);
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([1, 2, 3, 4, 5] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    // 准备进行中槽位
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [1, 2, 3, 4, 5], selectTags: [{ tagId: 1, pick: 1 }], startTs: 100, durationInSec: 32400, maxFinishTs: 200, realFinishTs: 200,
    } as any;
    let captured: any;
    mockTrigger.on("char:get", (([charId, from, cb]: any) => { captured = { charId, from }; cb?.({ charId }); }) as any);
    const result = await manager.finish({ slotId: 0 });
    expect(captured.charId).toBe("char_001");
    expect(result).toBeDefined();
  });

  it("boost 应立即完成招募", async () => {
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 100, durationInSec: 32400, maxFinishTs: 9999999999, realFinishTs: 9999999999,
    } as any;
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await manager.boost({ slotId: 0, buy: 0 });
    expect(mockPlayer._playerdata.recruit!.normal.slots["0"].realFinishTs).toBe(1234567890);
    expect(emitSpy).toHaveBeenCalledWith("BoostNormalGacha", []);
  });
});
