import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    OpenServerTable: {
      // 活动窗口覆盖 mock 时钟（now = 1234567890）
      schedule: [{ id: "sched_1", startTs: 0, endTs: 9999999999 }],
      dataMap: {
        sched_1: {
          // 官服形状：chainLoginData 键 0..6（第 7 档 order=7 即终奖）
          chainLoginData: {
            1: { item: { itemId: "4001", count: 100 } },
            6: { item: { itemId: "char_001", count: 1 } },
            "-1": { item: { itemId: "char_legacy", count: 1 } },
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
import { OpenServerManager } from "@game/modules/activities/checkin/openServer";

describe("OpenServerManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      openServer: {
        // 第 2 天已达成未领取（history[1] = 1）；累计签到第 2 档可领取
        chainLogin: { isAvailable: true, nowIndex: 1, history: [0, 1] },
        checkIn: { isAvailable: true, history: [1, 1, 1] },
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
    expect(emitSpy).toHaveBeenCalledWith("openserver:chain:login", [1234567800]);
    // 累计签到逐日推进一档（history[i]=1 表示可领取）
    expect(mockPlayer._playerdata.openServer!.checkIn.history).toEqual([1, 1, 1, 1]);
  });

  it("getChainLogInReward 应发放奖励并清除历史", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getChainLogInReward({ index: 1 });
    expect(items).toEqual([{ id: "4001", count: 100 }]);
    expect(mockPlayer._playerdata.openServer!.chainLogin.history[1]).toBe(0);
  });

  it("getChainLogInFinalRewards 应发放第 7 档终奖并标记已领", async () => {
    mockPlayer._playerdata.openServer!.chainLogin.history = [0, 0, 0, 0, 0, 0, 1];
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getChainLogInFinalRewards();
    expect(items).toEqual([{ id: "char_001", count: 1 }]);
    // 已领取标记为 0（isAvailable 是活动开关，不再被领取动作关闭）
    expect(mockPlayer._playerdata.openServer!.chainLogin.history[6]).toBe(0);
  });

  it("getCheckInReward 应发放签到奖励并标记已领", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.getCheckInReward({ index: 1 });
    expect(items).toEqual([{ id: "30011", count: 3 }]);
    expect(mockPlayer._playerdata.openServer!.checkIn.history[1]).toBe(0);
  });

  // ===== Round 26：重复领取与达成度校验（原实现无条件发奖，可无限刷） =====

  it("getChainLogInReward：同一档重复领取被拒（原实现可无限刷）", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    expect(await manager.getChainLogInReward({ index: 1 })).toHaveLength(1);
    expect(await manager.getChainLogInReward({ index: 1 })).toEqual([]);
    expect(await manager.getChainLogInReward({ index: 1 })).toEqual([]);
  });

  it("getChainLogInReward：未达成档位被拒（history 非 1）", async () => {
    mockPlayer._playerdata.openServer!.chainLogin.history = [0, 0];
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    expect(await manager.getChainLogInReward({ index: 1 })).toEqual([]);
  });

  it("getChainLogInFinalRewards：未达成第 7 档时被拒，且不可重复领取", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    // 仅到第 2 天 → 终奖不可领
    expect(await manager.getChainLogInFinalRewards()).toEqual([]);
    mockPlayer._playerdata.openServer!.chainLogin.history = [0, 0, 0, 0, 0, 0, 1];
    expect(await manager.getChainLogInFinalRewards()).toHaveLength(1);
    expect(await manager.getChainLogInFinalRewards()).toEqual([]);
  });

  it("getCheckInReward：同一档重复领取被拒", async () => {
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    expect(await manager.getCheckInReward({ index: 0 })).toHaveLength(1);
    expect(await manager.getCheckInReward({ index: 0 })).toEqual([]);
  });

  it("活动窗口外一律不可领取", async () => {
    const excel = (await import("@excel/excel")).default as any;
    const backup = excel.OpenServerTable.schedule;
    excel.OpenServerTable.schedule = [{ id: "sched_1", startTs: 1, endTs: 2 }];
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    expect(await manager.getChainLogInReward({ index: 1 })).toEqual([]);
    expect(await manager.getCheckInReward({ index: 0 })).toEqual([]);
    expect(await manager.getChainLogInFinalRewards()).toEqual([]);
    excel.OpenServerTable.schedule = backup;
  });

  it("openServer 状态缺失时兜底初始化（原实现直接 500）", async () => {
    delete (mockPlayer._playerdata as any).openServer;
    const manager = new OpenServerManager(mockPlayer as any, mockTrigger as any);
    await expect(manager.dailyRefresh([1234567800])).resolves.not.toThrow();
    const os = mockPlayer._playerdata.openServer!;
    expect(os.chainLogin.history).toEqual([1]);
    expect(os.chainLogin.nowIndex).toBe(0);
    expect(os.checkIn.history).toEqual([1]);
    expect(os.chainLogin.isAvailable).toBe(true); // 活动窗口内
  });
});
