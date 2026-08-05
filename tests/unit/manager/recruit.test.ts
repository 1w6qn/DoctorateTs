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
