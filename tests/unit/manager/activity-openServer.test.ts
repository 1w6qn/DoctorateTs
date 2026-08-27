import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    OpenServerTable: {
      schedule: [{ id: "sched_1", startTs: 0, endTs: 9999999999 }],
      dataMap: {
        sched_1: {
          chainLoginData: {
            1: { item: { itemId: "4001", count: 100 } },
            "-1": { item: { itemId: "char_001", count: 1 } },
          },
          checkInData: {
            0: { item: { itemId: "30012", count: 5 } },
            1: { item: { itemId: "30011", count: 3 } },
          },
        },
      },
    },
  },
}));
vi.mock("@utils/time", () => ({
  now: () => 1234567890,
  checkBetween: (ts: number, start: number, end: number) => ts >= start && ts <= end,
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { OpenServerManager } from "@game/domain/activity/checkin/openServer";

describe("OpenServerManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      openServer: {
        chainLogin: { isAvailable: true, nowIndex: 1, history: { 1: 1 } },
        checkIn: { isAvailable: true, history: [1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] },
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

  it("dailyRefresh 应推进连续登录并记录签到", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await manager.dailyRefresh([1234567800]);
    // chainLogin 推进（nowIndex +1 + 历史记录）
    expect(emitSpy).toHaveBeenCalledWith("openserver:chain:login", [1234567800]);
    // checkIn 记录
    expect(mockPlayer._playerdata.openServer!.checkIn.history).toHaveLength(15);
  });

  it("getChainLogInReward 应发放奖励并清除历史", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getChainLogInReward({ index: 1 });
    expect(items).toEqual([{ id: "4001", count: 100 }]);
    expect(mockPlayer._playerdata.openServer!.chainLogin.history[1]).toBe(0);
  });

  it("getChainLogInFinalRewards 应发放最终奖励并关闭", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getChainLogInFinalRewards();
    expect(items).toEqual([{ id: "char_001", count: 1 }]);
    expect(mockPlayer._playerdata.openServer!.chainLogin.isAvailable).toBe(false);
  });

  it("getCheckInReward 应发放签到奖励", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getCheckInReward({ index: 1 });
    expect(items).toEqual([{ id: "30011", count: 3 }]);
    expect(mockPlayer._playerdata.openServer!.checkIn.history[1]).toBe(0);
  });
});
