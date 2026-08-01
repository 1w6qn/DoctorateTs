import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  mockEventBus,
  mockTypedEventEmitter,
  mockPlayerData,
  mockExcel,
} from "./index";

describe("MockEventBus", () => {
  it("应该创建一个 EventBus 实例", () => {
    const bus = mockEventBus();
    expect(bus).toBeDefined();
    expect(typeof bus.on).toBe("function");
    expect(typeof bus.emit).toBe("function");
    expect(typeof bus.off).toBe("function");
    expect(typeof bus.subscribe).toBe("function");
  });

  it("应该支持事件监听和触发", async () => {
    const bus = mockEventBus();
    let called = false;

    bus.on("mission:complete", () => {
      called = true;
    });

    await bus.emit("mission:complete", { missionId: "test-1" });
    expect(called).toBe(true);
  });

  it("应该支持 subscribe 返回取消函数", async () => {
    const bus = mockEventBus();
    let count = 0;

    const unsub = bus.subscribe("mission:complete", () => count++);
    await bus.emit("mission:complete", { missionId: "a" });
    await bus.emit("mission:complete", { missionId: "b" });
    expect(count).toBe(2);

    unsub();
    await bus.emit("mission:complete", { missionId: "c" });
    expect(count).toBe(2);
  });

  it("应该支持优先级", async () => {
    const bus = mockEventBus();
    const order: string[] = [];

    bus.on("mission:complete", () => order.push("low"), 2);
    bus.on("mission:complete", () => order.push("high"), 0);
    bus.on("mission:complete", () => order.push("medium"), 1);

    await bus.emit("mission:complete", { missionId: "test" });
    expect(order).toEqual(["high", "medium", "low"]);
  });
});

describe("MockTypedEventEmitter", () => {
  it("应该创建一个 TypedEventEmitter 实例", () => {
    const emitter = mockTypedEventEmitter();
    expect(emitter).toBeDefined();
    expect(typeof emitter.on).toBe("function");
    expect(typeof emitter.emit).toBe("function");
  });
});

describe("MockPlayerData", () => {
  it("应该创建带有默认值的 mock", () => {
    const pd = mockPlayerData();
    expect(pd).toBeDefined();
    expect(pd.update).toBeDefined();
    expect(pd.get).toBeDefined();
    expect(pd.toJSON).toBeDefined();
    expect(pd.uid).toBe(10000);
  });

  it("应该可以使用 update 修改数据", async () => {
    const pd = mockPlayerData();
    await pd.update((draft: any) => {
      draft.status.nickName = "UpdatedName";
    });
    const json = pd.toJSON();
    expect(json.status.nickName).toBe("UpdatedName");
  });

  it("update 应该返回 recipe 的返回值", async () => {
    const pd = mockPlayerData();
    const result = await pd.update(() => "hello");
    expect(result).toBe("hello");
  });

  it("应该可以提供自定义初始数据", () => {
    const pd = mockPlayerData({
      status: { uid: 9999, nickName: "Custom", nickNumber: 1, level: 10, exp: 0 } as any,
    });
    expect(pd.uid).toBe(9999);
  });

  it("_trigger 应该有基本的事件方法", () => {
    const pd = mockPlayerData();
    expect(typeof pd._trigger.emit).toBe("function");
    expect(typeof pd._trigger.on).toBe("function");
  });

  it("delta 应该返回默认结构", () => {
    const pd = mockPlayerData();
    expect(pd.delta).toEqual({ playerDataDelta: {} });
  });
});

describe("MockExcel", () => {
  it("应该包含 MissionTable 基础结构", () => {
    const excel = mockExcel();
    expect(excel.MissionTable).toBeDefined();
    expect(excel.MissionTable.missions).toEqual({});
    expect(Array.isArray(excel.MissionTable.dailyMissionPeriodInfo)).toBe(true);
  });

  it("应该包含 MedalTable 基础结构", () => {
    const excel = mockExcel();
    expect(excel.MedalTable).toBeDefined();
    expect(Array.isArray(excel.MedalTable.medalList)).toBe(true);
  });

  it("应该包含 StageTable 基础结构", () => {
    const excel = mockExcel();
    expect(excel.StageTable).toBeDefined();
    expect(excel.StageTable.stages).toEqual({});
    expect(excel.StageTable.apProtectZoneInfo).toEqual({});
  });

  it("应该包含其他常用表", () => {
    const excel = mockExcel();
    expect(excel.GachaTable).toBeDefined();
    expect(excel.GameDataConst).toBeDefined();
    expect(excel.CharacterTable).toBeDefined();
    expect(excel.ItemTable).toBeDefined();
    expect(excel.ShopClientTable).toBeDefined();
    expect(excel.SkillDataBundle).toBeDefined();
  });

  it("应该允许测试修改 mock 数据", () => {
    const excel = mockExcel();
    excel.MissionTable.missions["test-mission"] = { id: "test-mission" } as any;
    expect(excel.MissionTable.missions["test-mission"]).toBeDefined();
  });
});
