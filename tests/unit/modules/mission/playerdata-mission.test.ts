import { describe, it, expect, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    MissionTable: {
      missions: {
        daily_1: { id: "daily_1", template: "CompleteStageAnyType", type: "DAILY", param: ["0", "1", "2"] },
      },
      missionGroups: {},
      periodicalRewards: {},
      dailyMissionPeriodInfo: [],
    },
    MedalTable: { medalList: [], medalTypeData: {} },
    OpenServerTable: { schedule: [], dataMap: {} },
  },
}));

vi.mock("@utils/time", () => ({ now: () => 1234567890, checkBetween: () => true }));
vi.mock("moment", () => ({ default: () => ({ diff: () => 0 }) }));

import { mockPlayerData } from "../../../helpers";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { MissionManager } from "@game/domain/mission/logic";

describe("PlayerDataManager mission 挂载", () => {
  it("构造后 player.mission 应为 MissionManager 实例", () => {
    const pd: any = mockPlayerData({
      rlv2: { outer: {}, current: {}, pinned: {} } as any,
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
      mission: {
        missions: { DAILY: {}, ACTIVITY: {} },
        missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
        missionGroups: {},
      },
    });
    const player = new PlayerDataManager(pd._playerdata as any);
    expect(player.mission).toBeInstanceOf(MissionManager);
  });

  it("init 后 missions 应按玩家数据填充任务进度", async () => {
    const pd: any = mockPlayerData({
      rlv2: { outer: {}, current: {}, pinned: {} } as any,
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
      mission: {
        missions: {
          DAILY: { daily_1: { state: 1, progress: [{ value: 0, target: 1 }] } },
          ACTIVITY: {},
        },
        missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
        missionGroups: {},
      },
    });
    const player = new PlayerDataManager(pd._playerdata as any);
    await player.mission.init();
    expect(player.mission.missions["DAILY"]).toBeDefined();
  });
});
