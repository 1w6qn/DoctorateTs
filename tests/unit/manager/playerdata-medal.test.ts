import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

vi.mock("@excel/excel", () => ({
  default: {
    MedalTable: {
      medalList: [
        { medalId: "medal_a", template: "PlayerLevel", unlockParam: ["10"], medalRewardGroup: [] },
      ],
    },
  },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("moment", () => ({ default: () => ({ diff: () => 0 }) }));

import { mockPlayerData } from "../../helpers";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { MedalManager } from "@game/manager/medal";

describe("PlayerDataManager medal 挂载", () => {
  it("构造后 player.medal 应为 MedalManager 实例", () => {
    const pd: any = mockPlayerData({
      rlv2: { outer: {}, current: {}, pinned: {} } as any,
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
      mission: {
        missions: { DAILY: {}, ACTIVITY: {} },
        missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
        missionGroups: {},
      } as any,
    });
    const player = new PlayerDataManager(pd._playerdata as any);
    expect(player.medal).toBeInstanceOf(MedalManager);
  });

  it("init 后 medals 应按玩家数据创建进度实例", async () => {
    const pd: any = mockPlayerData({
      rlv2: { outer: {}, current: {}, pinned: {} } as any,
      medal: {
        medals: {
          medal_a: { id: "medal_a", val: [[5, 10]], fts: 0, rts: -1, reward: "" },
        },
        custom: { currentIndex: "0", customs: {} },
      } as any,
      mission: {
        missions: { DAILY: {}, ACTIVITY: {} },
        missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
        missionGroups: {},
      } as any,
    });
    const player = new PlayerDataManager(pd._playerdata as any);
    await player.medal.init();
    expect(player.medal.medals["medal_a"]).toBeDefined();
  });
});
