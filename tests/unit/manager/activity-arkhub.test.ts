/**
 * 奇象巡展（ARK_HUB）Phase 1 实现单测：活动播种、8 类任务模板、3 枚勋章模板、
 * arkhub 玩法事件入口（结算/每日物资/生物收录）。2026-08-17。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventBus } from "@game/service/events";

// ---- excel mock（ActivityTable.missionData 用官服真实形状的子集）----
vi.mock("@excel/excel", () => {
  return {
    default: {
      ActivityTable: {
        basicInfo: {
          act1arkhub: {
            id: "act1arkhub", type: "ARK_HUB", name: "奇象巡展",
            startTime: 1786176000, endTime: 1788465599, rewardEndTime: 1788724799,
            templateShopId: "shop_act1arkhub",
            ungroupedMedalIds: ["medal_activity_1arkhub_01", "medal_activity_1arkhub_02"],
          },
        },
        missionGroup: [
          {
            id: "act1arkhub",
            missionIds: [
              "1arkhubActivity_1", "1arkhubActivity_2", "1arkhubActivity_3",
              "1arkhubActivity_4", "1arkhubActivity_7",
              "1arkhubActivity_9", "1arkhubActivity_12",
              "1arkhubActivity_15", "1arkhubActivity_16",
              "1arkhubActivity_17", "1arkhubActivity_20", "1arkhubActivity_22",
              "53sideActivity_1",
            ],
          },
        ],
        missionData: [
          { id: "1arkhubActivity_1", template: "ArkhubMissionCompleted", param: ["0", "act1arkhub", "capture_catch_guide_01", "1"] },
          { id: "1arkhubActivity_2", template: "ArkhubMissionCompleted", param: ["0", "act1arkhub", "capture_catch_guide_02", "1"] },
          { id: "1arkhubActivity_3", template: "ArkhubMissionCompleted", param: ["0", "act1arkhub", "arkdex_battle_guide", "1"] },
          { id: "1arkhubActivity_4", template: "ArkhubDailyMissionCompleted", param: ["0", "act1arkhub", "2026-08-08 16:00:00", "2026-09-04 03:59:59", "1"] },
          { id: "1arkhubActivity_7", template: "ArkhubDailyMissionCompleted", param: ["0", "act1arkhub", "2026-08-18 16:00:00", "2026-09-04 03:59:59", "1"] },
          { id: "1arkhubActivity_9", template: "ArkhubCreatureCollection", param: ["0", "act1arkhub", "3", "arkhubMissionCollection1"] },
          { id: "1arkhubActivity_12", template: "ArkhubCreatureCollection", param: ["0", "act1arkhub", "1", "arkhubMissionCollection2"] },
          { id: "1arkhubActivity_15", template: "ArkhubCreatureCaptured", param: ["0", "act1arkhub", "1", "2"] },
          { id: "1arkhubActivity_16", template: "ArkhubCreatureExchange", param: ["0", "act1arkhub", "1"] },
          { id: "1arkhubActivity_17", template: "ArkhubPassDexBattle", param: ["0", "act1arkhub", "5", "0"] },
          { id: "1arkhubActivity_20", template: "ArkhubPublishPixelArt", param: ["0", "act1arkhub", "1"] },
          { id: "1arkhubActivity_22", template: "ArkhubCollectPixelArt", param: ["0", "act1arkhub", "5"] },
          // 非 arkhub 模板（如 53side）——播种应保持原行为
          { id: "53sideActivity_1", template: "CollectMaterial", param: ["0", "act53side", "10", "0"] },
        ],
        activity: { aRK_HUB: {} },
      },
      MedalTable: {
        medalList: [
          { medalId: "medal_activity_1arkhub_01", medalName: "巡展印象奖章", template: "ActivityArkhubPixelCollect", unlockParam: ["act1arkhub", "0", "4"] },
          { medalId: "medal_activity_1arkhub_02", medalName: "巡展珍奇奖章", template: "ActivityArkhubCreatureCollect", unlockParam: ["act1arkhub", "arkhubMissionCollection1", "10"] },
          { medalId: "medal_activity_1arkhub_025", medalName: "巡展珍奇奖章", template: "ActivityArkhubAlterCollect", unlockParam: ["act1arkhub", "arkhubMissionCollection1", "10", "1"] },
        ],
        medalTypeData: {},
      },
      StageTable: { stages: {} },
      MissionTable: { missions: {}, missionGroups: {} },
      ItemTable: { items: { act1arkhub_token_seal: { itemType: "ACTIVITY_ITEM" } } },
      CharWordTable: {},
      GameDataConst: {},
      GachaTable: {},
      CharacterTable: {},
      ShopClientTable: {},
    },
  };
});

// @utils/time 不 mock——真实 userTimestamp 支持冻结时间（config.developer.timestamp ≤ now 时返回冻结值），
// 与 activity-unlock.test.ts 同款做法：测试通过设置 config.developer 控制播种/门控时间。

import config from "../../../app/config";
import { mockPlayerData } from "../../helpers";
import { unlockActivity } from "@game/service/player/unlockActivity";
import { MissionProgress } from "@game/service/mission/logic";
import { MedalProgress } from "@game/service/player/medal";
import {
  arkhubOnDuelSettle,
  arkhubOnDailySupply,
  arkhubCreatureCollected,
  arkhubCreatureCaptured,
  arkhubCreatureExchange,
  arkhubPixelCollected,
  ARKHUB_ACT_ID,
  arkhubCompletedGuideFlags,
  arkhubProgressiveGuideFlags,
  arkhubResolveGuideFlags,
  arkhubAdvanceGuide,
  ARKHUB_GUIDE_ACTOR_FLAGS,
} from "@game/service/activity/arkhub/arkhub";

/** 冻结时间（2026-08-15 12:00 +8：活动窗口内、8/18 更新前） */
const FROZEN_TS = 1786766400;
const original = config.developer;

afterEach(() => {
  config.developer = original;
  vi.clearAllMocks();
});

describe("unlockActivity 奇象巡展播种", () => {
  function mockPlayer() {
    const reloadActivity = vi.fn().mockResolvedValue(undefined);
    const player = mockPlayerData({
      status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
      activity: { ARK_HUB: {} },
      mission: { missions: { ACTIVITY: {} } },
      medal: { medals: {}, custom: { currentIndex: "", customs: {} } },
      dungeon: { stages: {} },
      arkodc: { topics: {} },
    });
    (player as any).mission = { reloadActivity };
    return { player, reloadActivity };
  }

  it("播种 8 类模板真实进度：引导完成、收集/对战/像素 0/N、非 arkhub 保持原行为", async () => {
    config.developer = { timestamp: FROZEN_TS };
    const { player, reloadActivity } = mockPlayer();
    await unlockActivity(player as any);

    const am = (player._playerdata as any).mission.missions.ACTIVITY;
    // 引导任务：播种即完成（本服引导为完成态）
    expect(am["1arkhubActivity_1"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    expect(am["1arkhubActivity_3"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    // 每日物资：0/N
    expect(am["1arkhubActivity_4"]).toEqual({ state: 2, progress: [{ value: 0, target: 1 }] });
    // 收集生物/拟合/像素：0/N
    expect(am["1arkhubActivity_9"]).toEqual({ state: 2, progress: [{ value: 0, target: 3 }] });
    expect(am["1arkhubActivity_17"]).toEqual({ state: 2, progress: [{ value: 0, target: 5 }] });
    expect(am["1arkhubActivity_22"]).toEqual({ state: 2, progress: [{ value: 0, target: 5 }] });
    // 非 arkhub 任务：保持原"全可领"行为
    expect(am["53sideActivity_1"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    // 播种后重建任务监听器
    expect(reloadActivity).toHaveBeenCalled();
  });

  it("8/18 更新后任务（param 起点在未来）播种为锁定态 state:0", async () => {
    config.developer = { timestamp: FROZEN_TS };
    const { player } = mockPlayer();
    await unlockActivity(player as any);
    const am = (player._playerdata as any).mission.missions.ACTIVITY;
    expect(am["1arkhubActivity_7"]).toEqual({ state: 0, progress: [{ value: 0, target: 1 }] });
  });

  it("播种 ARK_HUB 状态扩展计数器 + ungroupedMedalIds 两枚勋章（025 镀层不播种）", async () => {
    config.developer = { timestamp: FROZEN_TS };
    const { player } = mockPlayer();
    await unlockActivity(player as any);

    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.duelCount).toBe(0);
    expect(hub.dailySupplyDays).toBe(0);
    expect(hub.creatureCollected).toBe(0);
    expect(hub.activeCreatureCollected).toBe(0);
    expect(hub.alterCollected).toBe(0);
    expect(hub.pixelCollected).toBe(0);
    expect(hub.pixelPublished).toBe(0);

    const medals = (player._playerdata as any).medal.medals;
    expect(medals["medal_activity_1arkhub_01"]).toEqual({ id: "medal_activity_1arkhub_01", val: [[0, 4]], fts: 0, rts: -1 });
    expect(medals["medal_activity_1arkhub_02"]).toEqual({ id: "medal_activity_1arkhub_02", val: [[0, 10]], fts: 0, rts: -1 });
    expect(medals["medal_activity_1arkhub_025"]).toBeUndefined();
  });

  it("已播种任务不覆盖（存量存档保持不动）", async () => {
    config.developer = { timestamp: FROZEN_TS };
    const { player } = mockPlayer();
    (player._playerdata as any).mission.missions.ACTIVITY["1arkhubActivity_9"] = {
      state: 3, progress: [{ value: 3, target: 3 }], confirmed: 1,
    };
    await unlockActivity(player as any);
    const am = (player._playerdata as any).mission.missions.ACTIVITY;
    expect(am["1arkhubActivity_9"]).toEqual({ state: 3, progress: [{ value: 3, target: 3 }], confirmed: 1 });
  });
});

describe("奇象巡展任务模板（MissionProgress + 真实 EventBus）", () => {
  function missionFixture(missionId: string, excelMock: any) {
    const bus = new EventBus();
    const player = mockPlayerData({
      status: { uid: 1 } as any,
      mission: { missions: { ACTIVITY: { [missionId]: { state: 2, progress: [] } } } },
      activity: { ARK_HUB: { act1arkhub: {} } },
    });
    (player as any)._trigger = bus;
    const mission = new MissionProgress(missionId, "ACTIVITY", player as any);
    return { player, bus, mission };
  }

  it("ArkhubCreatureCollection：collectionKey 匹配时取 max，不匹配不推进", async () => {
    const { player, bus, mission } = missionFixture("1arkhubActivity_9", {});
    await mission.init();
    expect(mission.valid).toBe(true);
    expect(mission.progress[0]).toEqual({ value: 0, target: 3 });
    await bus.emit("ArkhubCreatureCollection", [
      { activityId: ARKHUB_ACT_ID, count: 2, collectionKey: "arkhubMissionCollection1" },
    ]);
    expect(mission.progress[0].value).toBe(2);
    // collectionKey 不匹配（活动频繁）不推进
    await bus.emit("ArkhubCreatureCollection", [
      { activityId: ARKHUB_ACT_ID, count: 5, collectionKey: "arkhubMissionCollection2" },
    ]);
    expect(mission.progress[0].value).toBe(2);
    // 达到 target → state 3
    await bus.emit("ArkhubCreatureCollection", [
      { activityId: ARKHUB_ACT_ID, count: 3, collectionKey: "arkhubMissionCollection1" },
    ]);
    expect(mission.progress[0].value).toBe(3);
    expect((player._playerdata as any).mission.missions.ACTIVITY["1arkhubActivity_9"].state).toBe(3);
  });

  it("ArkhubPassDexBattle：累计对战次数取 max", async () => {
    const { player, bus, mission } = missionFixture("1arkhubActivity_17", {});
    await mission.init();
    await bus.emit("ArkhubPassDexBattle", [{ activityId: ARKHUB_ACT_ID, count: 5 }]);
    expect(mission.progress[0].value).toBe(5);
    expect((player._playerdata as any).mission.missions.ACTIVITY["1arkhubActivity_17"].state).toBe(3);
  });

  it("ArkhubCreatureCaptured / ArkhubCreatureExchange：事件每次触发 +1", async () => {
    const { player, bus, mission } = missionFixture("1arkhubActivity_15", {});
    await mission.init();
    await bus.emit("ArkhubCreatureCaptured", [{ activityId: ARKHUB_ACT_ID }]);
    expect(mission.progress[0].value).toBe(1);
    expect((player._playerdata as any).mission.missions.ACTIVITY["1arkhubActivity_15"].state).toBe(3);

    const exch = missionFixture("1arkhubActivity_16", {});
    await exch.mission.init();
    await exch.bus.emit("ArkhubCreatureExchange", [{ activityId: ARKHUB_ACT_ID }]);
    expect(exch.mission.progress[0].value).toBe(1);
  });

  it("ArkhubDailyMissionCompleted：窗口内推进，8/18 任务在窗口起点前不推进", async () => {
    config.developer = { timestamp: FROZEN_TS };
    // 任务 4（窗口 08-08 起）：推进
    const m4 = missionFixture("1arkhubActivity_4", {});
    await m4.mission.init();
    await m4.bus.emit("ArkhubDailyMissionCompleted", [{ activityId: ARKHUB_ACT_ID, days: 1 }]);
    expect(m4.mission.progress[0].value).toBe(1);
    // 任务 7（窗口 08-18 起，当前 08-15）：不推进
    const m7 = missionFixture("1arkhubActivity_7", {});
    await m7.mission.init();
    await m7.bus.emit("ArkhubDailyMissionCompleted", [{ activityId: ARKHUB_ACT_ID, days: 3 }]);
    expect(m7.mission.progress[0].value).toBe(0);
  });

  it("ArkhubPublishPixelArt / ArkhubCollectPixelArt：取 max", async () => {
    const p = missionFixture("1arkhubActivity_20", {});
    await p.mission.init();
    await p.bus.emit("ArkhubPublishPixelArt", [{ activityId: ARKHUB_ACT_ID, count: 1 }]);
    expect(p.mission.progress[0].value).toBe(1);

    const c = missionFixture("1arkhubActivity_22", {});
    await c.mission.init();
    await c.bus.emit("ArkhubCollectPixelArt", [{ activityId: ARKHUB_ACT_ID, count: 5 }]);
    expect(c.mission.progress[0].value).toBe(5);
  });
});

describe("奇象巡展勋章模板（MedalProgress + 真实 EventBus）", () => {
  function medalFixture(medalId: string) {
    const bus = new EventBus();
    const markDirty = vi.fn();
    // item.val 取播种形状 [[0, target]]——构造函数绑定存档数组并自动 init 注册监听
    // （with-val 分支：init 构建的 scratch 被丢弃，val 以 item.val 为准）
    const target = medalId === "medal_activity_1arkhub_01" ? 4 : 10;
    const item = {
      id: medalId,
      val: [[0, target]],
      rts: -1,
      fts: 0,
      reward: "",
    };
    const medal = new MedalProgress(item as any, bus, markDirty);
    return { bus, medal, item, markDirty };
  }

  it("ActivityArkhubPixelCollect：收集画像数取 max（target=param[2]=4）", async () => {
    const { bus, medal, markDirty } = medalFixture("medal_activity_1arkhub_01");
    expect(medal.val[0]).toEqual([0, 4]);
    await bus.emit("ActivityArkhubPixelCollect", [{ activityId: ARKHUB_ACT_ID, count: 2 }]);
    expect(medal.val[0][0]).toBe(2);
    await bus.emit("ActivityArkhubPixelCollect", [{ activityId: ARKHUB_ACT_ID, count: 4 }]);
    expect(medal.val[0][0]).toBe(4);
    expect(medal.fts).toBeGreaterThan(0);
    expect(markDirty).toHaveBeenCalled();
  });

  it("ActivityArkhubCreatureCollect：收录 10 种达标", async () => {
    const { bus, medal } = medalFixture("medal_activity_1arkhub_02");
    expect(medal.val[0]).toEqual([0, 10]);
    await bus.emit("ActivityArkhubCreatureCollect", [
      { activityId: ARKHUB_ACT_ID, count: 10, collectionKey: "arkhubMissionCollection1" },
    ]);
    expect(medal.val[0][0]).toBe(10);
  });

  it("ActivityArkhubAlterCollect：10 种 + 至少 1 亚种（镀层双条件）", async () => {
    const { bus, medal } = medalFixture("medal_activity_1arkhub_025");
    expect(medal.val[0]).toEqual([0, 10]);
    // 10 种但无亚种：进度锁 0（有亚种才积累）
    await bus.emit("ActivityArkhubAlterCollect", [{ activityId: ARKHUB_ACT_ID, count: 10, alterCount: 0 }]);
    expect(medal.val[0][0]).toBe(0);
    // 9 种 + 1 亚种：积累 9，但未达 10 不完成
    await bus.emit("ActivityArkhubAlterCollect", [{ activityId: ARKHUB_ACT_ID, count: 9, alterCount: 1 }]);
    expect(medal.val[0][0]).toBe(9);
    expect(medal.fts).toBe(0);
    // 10 种 + 1 亚种：达标完成
    await bus.emit("ActivityArkhubAlterCollect", [{ activityId: ARKHUB_ACT_ID, count: 10, alterCount: 1 }]);
    expect(medal.val[0][0]).toBe(10);
    expect(medal.fts).toBeGreaterThan(0);
  });
});

describe("arkhub 玩法事件入口（arkhub.ts）", () => {
  function hubPlayer(overrides: Record<string, any> = {}) {
    const bus = new EventBus();
    const player = mockPlayerData({
      status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
      activity: { ARK_HUB: { act1arkhub: { coin: 0, ...overrides } } },
      tshop: { shop_act1arkhub: { coin: 0 } },
    });
    (player as any)._trigger = bus;
    return player;
  }

  it("arkhubOnDuelSettle：对战计数 +1、发 15 券、币同步、发任务事件", async () => {
    const player = hubPlayer();
    const seen: any[] = [];
    (player._trigger as EventBus).on("ArkhubPassDexBattle", (args: any[]) => seen.push(args[0]));
    await arkhubOnDuelSettle(player as any);

    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.duelCount).toBe(1);
    expect(hub.coin).toBe(15);
    expect((player._playerdata as any).tshop.shop_act1arkhub.coin).toBe(15);
    expect(seen).toEqual([{ activityId: ARKHUB_ACT_ID, count: 1 }]);
    // 二次结算累计（update 会整体替换 activity 引用，需重新读取）
    await arkhubOnDuelSettle(player as any);
    const hub2 = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub2.duelCount).toBe(2);
    expect(hub2.coin).toBe(30);
  });

  it("arkhubOnDailySupply：每日限 1 次、累计天数 +1、发 100 券", async () => {
    const player = hubPlayer();
    const seen: any[] = [];
    (player._trigger as EventBus).on("ArkhubDailyMissionCompleted", (args: any[]) => seen.push(args[0]));
    await arkhubOnDailySupply(player as any);
    await arkhubOnDailySupply(player as any); // 同日第二次 → 跳过

    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.dailySupplyDays).toBe(1);
    expect(hub.coin).toBe(100);
    expect(seen).toEqual([{ activityId: ARKHUB_ACT_ID, days: 1 }]);
  });

  it("arkhubCreatureCollected：计数落状态 + 双 collectionKey 事件 + 勋章事件", async () => {
    const player = hubPlayer();
    const seen: string[] = [];
    const bus = player._trigger as EventBus;
    bus.on("ArkhubCreatureCollection", (args: any[]) => seen.push(`m:${args[0].collectionKey}:${args[0].count}`));
    bus.on("ActivityArkhubCreatureCollect", () => seen.push("medal02"));
    bus.on("ActivityArkhubAlterCollect", () => seen.push("medal025"));

    await arkhubCreatureCollected(player as any, { count: 3, activeCount: 1, alterCount: 1 });
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.creatureCollected).toBe(3);
    expect(hub.activeCreatureCollected).toBe(1);
    expect(hub.alterCollected).toBe(1);
    expect(seen).toContain("m:arkhubMissionCollection1:3");
    expect(seen).toContain("m:arkhubMissionCollection2:1");
    expect(seen).toContain("medal02");
    expect(seen).toContain("medal025");
  });

  it("arkhubCreatureCaptured / Exchange / PixelCollected 事件发射", async () => {
    const player = hubPlayer();
    const seen: string[] = [];
    const bus = player._trigger as EventBus;
    bus.on("ArkhubCreatureCaptured", () => seen.push("captured"));
    bus.on("ArkhubCreatureExchange", () => seen.push("exchange"));
    bus.on("ArkhubCollectPixelArt", (args: any[]) => seen.push(`pixel:${args[0].count}`));
    bus.on("ActivityArkhubPixelCollect", () => seen.push("medal01"));

    await arkhubCreatureCaptured(player as any);
    await arkhubCreatureExchange(player as any);
    await arkhubPixelCollected(player as any, 4);
    expect((player._playerdata as any).activity.ARK_HUB.act1arkhub.pixelCollected).toBe(4);
    expect(seen).toEqual(["captured", "exchange", "pixel:4", "medal01"]);
  });
});

describe("arkhub 渐进引导/剧情推进（GuideFlags，2026-08-19）", () => {
  function guidePlayer(overrides: Record<string, any> = {}) {
    const bus = new EventBus();
    const player = mockPlayerData({
      status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
      activity: { ARK_HUB: { act1arkhub: { coin: 0 } } },
      mission: { missions: {} },
      ...overrides,
    });
    (player as any)._trigger = bus;
    return { player, bus };
  }

  it("渐进初始态：关键引导 flag=0，非引导/防卡 flag 保持完成态", () => {
    const complete = arkhubCompletedGuideFlags();
    expect(complete.capture_catch_guide_02).toBe(2);
    expect(complete.arkdex_battle_guide).toBe(2);
    expect(complete.arkhub_login).toBe(1);

    const prog = arkhubProgressiveGuideFlags();
    // 渐进 = 完成态 + 引导类置 0
    expect(prog.arkhub_login).toBe(0);
    expect(prog.terminal_guide).toBe(0);
    expect(prog.capture_catch_guide_02).toBe(0);
    expect(prog.arkdex_battle_guide).toBe(0);
    expect(prog.pixel_unlock).toBe(0);
    expect(prog.pixel_unlock_system).toBe(0);
    // 防卡/未知 actor 项保持完成态
    expect(prog.capture_catch_guide_01).toBe(2);
    expect(prog.area_1_block).toBe(1);
    expect(prog.area_2_guard).toBe(1);
  });

  it("resolveGuideFlags：持久化优先（合并完成态兜底）/ 无持久化回退 progressive 或完成态", () => {
    // 无持久化：progressive=false → 完成态
    const p1 = guidePlayer();
    expect(arkhubResolveGuideFlags(p1.player as any)).toEqual(arkhubCompletedGuideFlags());
    // 无持久化：progressive=true → 渐进初始态
    expect(arkhubResolveGuideFlags(p1.player as any, true)).toEqual(arkhubProgressiveGuideFlags());
    // 有持久化：部分 flag → 合并完成态兜底
    const p2 = guidePlayer({ activity: { ARK_HUB: { act1arkhub: { guideFlags: { arkdex_battle_guide: 2 } } } } });
    const merged = arkhubResolveGuideFlags(p2.player as any, true);
    expect(merged.arkdex_battle_guide).toBe(2);
    expect(merged.capture_catch_guide_02).toBe(0); // 未持久化项走渐进初始态
    expect(merged.area_1_block).toBe(1);
  });

  it("推进 mmkabi_01b：捕抓引导完成 + 设施解锁 + ArkhubMissionCompleted(任务2 flag)", async () => {
    const { player, bus } = guidePlayer();
    const seen: any[] = [];
    bus.on("ArkhubMissionCompleted", (args: any[]) => seen.push(args[0] as { flag: string }));
    await arkhubAdvanceGuide(player as any, "arkhub_capture1_mmkabi_01b");
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.guideFlags.capture_catch_guide_02).toBe(2);
    expect(hub.guideFlags.pixel_unlock).toBe(1);
    expect(hub.guideFlags.pixel_unlock_system).toBe(1);
    // 事件 flag 列表（任务 2 模板监听 param[2]===flag）
    expect(seen.map((e) => e.flag).sort()).toEqual(["capture_catch_guide_02", "pixel_unlock", "pixel_unlock_system"]);
    // 幂等：重复调用不重复计数/事件
    seen.length = 0;
    await arkhubAdvanceGuide(player as any, "arkhub_capture1_mmkabi_01b");
    expect(seen).toEqual([]);
    expect(hub.guideFlags.capture_catch_guide_02).toBe(2);
  });

  it("推进 bryota_01c：对决引导完成（任务3 flag）", async () => {
    const { player, bus } = guidePlayer();
    const seen: any[] = [];
    bus.on("ArkhubMissionCompleted", (args: any[]) => seen.push(args[0] as { flag: string }));
    await arkhubAdvanceGuide(player as any, "arkhub_main_bryota_01c");
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.guideFlags.arkdex_battle_guide).toBe(2);
    expect(seen.map((e) => e.flag)).toEqual(["arkdex_battle_guide"]);
  });

  it("未知 actor no-op（不落状态不发射事件）", async () => {
    const { player, bus } = guidePlayer();
    const seen: any[] = [];
    bus.on("ArkhubMissionCompleted", (args: any[]) => seen.push(args[0]));
    await arkhubAdvanceGuide(player as any, "arkhub_main_daily_task_02a");
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.guideFlags).toBeUndefined();
    expect(seen).toEqual([]);
  });

  it("引导 actor 映射表：mmkabi 推进 3 flag（含设施解锁），bryota 推进对决引导", () => {
    expect(ARKHUB_GUIDE_ACTOR_FLAGS.arkhub_capture1_mmkabi_01b).toEqual({
      capture_catch_guide_02: 2,
      pixel_unlock: 1,
      pixel_unlock_system: 1,
    });
    expect(ARKHUB_GUIDE_ACTOR_FLAGS.arkhub_main_bryota_01c).toEqual({ arkdex_battle_guide: 2 });
  });
});

describe("unlockActivity 播种 × 渐进引导开关（config.arkhub.guideProgressive）", () => {
  function mockPlayer2() {
    const reloadActivity = vi.fn().mockResolvedValue(undefined);
    const player = mockPlayerData({
      status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
      activity: { ARK_HUB: {} },
      mission: { missions: { ACTIVITY: {} } },
      medal: { medals: {}, custom: { currentIndex: "", customs: {} } },
      dungeon: { stages: {} },
      arkodc: { topics: {} },
    });
    (player as any).mission = { reloadActivity };
    return { player };
  }

  it("guideProgressive=true：任务 2/3 播种进行中（0/1），任务 1 保持完成态", async () => {
    config.developer = { timestamp: FROZEN_TS };
    config.arkhub = { guideProgressive: true };
    const { player } = mockPlayer2();
    await unlockActivity(player as any);
    const am = (player._playerdata as any).mission.missions.ACTIVITY;
    // 任务 2（捕抓引导 capture_catch_guide_02）：进行中 0/1
    expect(am["1arkhubActivity_2"]).toEqual({ state: 2, progress: [{ value: 0, target: 1 }] });
    // 任务 3（对决引导 arkdex_battle_guide）：进行中 0/1
    expect(am["1arkhubActivity_3"]).toEqual({ state: 2, progress: [{ value: 0, target: 1 }] });
    // 任务 1（夏妮 capture_catch_guide_01）：保持完成态（actor 未确认）
    expect(am["1arkhubActivity_1"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
  });

  it("guideProgressive=false（默认）：引导任务全部播种完成态（回归）", async () => {
    config.developer = { timestamp: FROZEN_TS };
    config.arkhub = { guideProgressive: false };
    const { player } = mockPlayer2();
    await unlockActivity(player as any);
    const am = (player._playerdata as any).mission.missions.ACTIVITY;
    expect(am["1arkhubActivity_1"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    expect(am["1arkhubActivity_2"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    expect(am["1arkhubActivity_3"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
  });
});
