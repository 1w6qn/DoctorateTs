import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EventBus, Priority, globalEventBus } from "@game/model/events";

describe("EventBus", () => {
  let bus: EventBus;

  beforeEach(() => {
    bus = new EventBus();
  });

  describe("优先级调度", () => {
    it("应该按 HIGH -> MEDIUM -> LOW 顺序执行", async () => {
      const order: string[] = [];

      bus.on("mission:complete", () => order.push("low"), Priority.LOW);
      bus.on("mission:complete", () => order.push("high"), Priority.HIGH);
      bus.on("mission:complete", () => order.push("medium"), Priority.MEDIUM);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["high", "medium", "low"]);
    });

    it("同一优先级按注册顺序执行", async () => {
      const order: string[] = [];

      bus.on("mission:complete", () => order.push("first"), Priority.HIGH);
      bus.on("mission:complete", () => order.push("second"), Priority.HIGH);
      bus.on("mission:complete", () => order.push("third"), Priority.HIGH);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["first", "second", "third"]);
    });

    it("混合优先级应正确排序", async () => {
      const order: string[] = [];

      bus.on("mission:complete", () => order.push("a"), Priority.MEDIUM);
      bus.on("mission:complete", () => order.push("b"), Priority.LOW);
      bus.on("mission:complete", () => order.push("c"), Priority.HIGH);
      bus.on("mission:complete", () => order.push("d"), Priority.MEDIUM);
      bus.on("mission:complete", () => order.push("e"), Priority.LOW);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["c", "a", "d", "b", "e"]);
    });
  });

  describe("subscribe/unsubscribe", () => {
    it("应该正确注册和移除监听器", async () => {
      let called = false;
      const unsub = bus.subscribe("mission:complete", () => {
        called = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });
      expect(called).toBe(true);

      called = false;
      unsub();
      await bus.emit("mission:complete", { missionId: "test" });
      expect(called).toBeFalsy();
    });

    it("subscribe 应使用默认 MEDIUM 优先级", async () => {
      const order: string[] = [];

      bus.subscribe("mission:complete", () => order.push("subscribed"));
      bus.on("mission:complete", () => order.push("high"), Priority.HIGH);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["high", "subscribed"]);
    });

    it("off 应该移除指定优先级的监听器", async () => {
      const order: string[] = [];
      const listener = () => order.push("medium");

      bus.on("mission:complete", listener, Priority.MEDIUM);
      bus.on("mission:complete", () => order.push("high"), Priority.HIGH);

      bus.off("mission:complete", listener, Priority.MEDIUM);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["high"]);
    });

    it("off 不指定优先级时应移除所有优先级匹配的监听器", async () => {
      const order: string[] = [];
      const listener = () => order.push("listener");

      bus.on("mission:complete", listener, Priority.HIGH);
      bus.on("mission:complete", listener, Priority.LOW);

      bus.off("mission:complete", listener);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual([]);
    });
  });

  describe("once 方法", () => {
    it("监听器应该只执行一次", async () => {
      let count = 0;

      bus.once("mission:complete", () => {
        count++;
      });

      await bus.emit("mission:complete", { missionId: "test1" });
      await bus.emit("mission:complete", { missionId: "test2" });

      expect(count).toBe(1);
    });

    it("once 应该使用指定优先级", async () => {
      const order: string[] = [];

      bus.once("mission:complete", () => order.push("once-high"), Priority.HIGH);
      bus.on("mission:complete", () => order.push("medium"), Priority.MEDIUM);

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["once-high", "medium"]);
    });

    it("once 触发后应自动移除", async () => {
      let count = 0;

      bus.once("mission:complete", () => {
        count++;
      });

      await bus.emit("mission:complete", { missionId: "test1" });
      expect(count).toBe(1);

      const before = bus.getListenerCount("mission:complete");
      expect(before).toBe(0);

      await bus.emit("mission:complete", { missionId: "test2" });
      expect(count).toBe(1);
    });
  });

  describe("中间件", () => {
    it("before 中间件应该在事件前执行", async () => {
      const order: string[] = [];

      bus.useMiddleware({
        before() {
          order.push("before");
        },
      });

      bus.on("mission:complete", () => order.push("listener"));

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["before", "listener"]);
    });

    it("after 中间件应该在事件后执行", async () => {
      const order: string[] = [];

      bus.useMiddleware({
        after() {
          order.push("after");
        },
      });

      bus.on("mission:complete", () => order.push("listener"));

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual(["listener", "after"]);
    });

    it("多个中间件应按注册顺序执行", async () => {
      const order: string[] = [];

      bus.useMiddleware({
        before() {
          order.push("mw1-before");
        },
        after() {
          order.push("mw1-after");
        },
      });

      bus.useMiddleware({
        before() {
          order.push("mw2-before");
        },
        after() {
          order.push("mw2-after");
        },
      });

      bus.on("mission:complete", () => order.push("listener"));

      await bus.emit("mission:complete", { missionId: "test" });

      expect(order).toEqual([
        "mw1-before",
        "mw2-before",
        "listener",
        "mw1-after",
        "mw2-after",
      ]);
    });

    it("before 返回 false 应阻止事件传播", async () => {
      let listenerCalled = false;

      bus.useMiddleware({
        before() {
          return false;
        },
      });

      bus.on("mission:complete", () => {
        listenerCalled = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(listenerCalled).toBeFalsy();
    });

    it("before 返回 false 时后续中间件也不应执行", async () => {
      let mw2BeforeCalled = false;

      bus.useMiddleware({
        before() {
          return false;
        },
      });

      bus.useMiddleware({
        before() {
          mw2BeforeCalled = true;
        },
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(mw2BeforeCalled).toBeFalsy();
    });

    it("after 中间件在阻止时不应执行", async () => {
      let afterCalled = false;

      bus.useMiddleware({
        before() {
          return false;
        },
        after() {
          afterCalled = true;
        },
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(afterCalled).toBeFalsy();
    });
  });

  describe("日志功能", () => {
    it("启用日志后应输出日志", async () => {
      const logs: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
        logs.push(args.join(" "));
      });

      bus.enableLogging();
      bus.on("mission:complete", () => {});
      await bus.emit("mission:complete", { missionId: "test" });

      spy.mockRestore();

      expect(logs.length).toBeGreaterThan(0);
      expect(logs.some((l) => l.includes("[EventBus]"))).toBe(true);
    });

    it("禁用日志后不应输出日志", async () => {
      const logs: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
        logs.push(args.join(" "));
      });

      bus.enableLogging();
      bus.disableLogging();
      bus.on("mission:complete", () => {});
      await bus.emit("mission:complete", { missionId: "test" });

      spy.mockRestore();

      expect(logs.length).toBe(0);
    });

    it("日志应包含事件名和参数", async () => {
      const logs: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
        logs.push(args.join(" "));
      });

      bus.enableLogging();
      bus.on("mission:complete", () => {});
      await bus.emit("mission:complete", { missionId: "test-123" });

      spy.mockRestore();

      const matched = logs.find((l) => l.includes("emit: mission:complete"));
      expect(matched).toBeTruthy();
      expect(matched!.includes("mission:complete")).toBe(true);
      expect(matched!.includes("test-123")).toBe(true);
    });
  });

  describe("验证器功能", () => {
    it("验证通过时事件应正常触发", async () => {
      let called = false;

      bus.addValidator("mission:complete", () => true);
      bus.on("mission:complete", () => {
        called = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(called).toBe(true);
    });

    it("验证失败时默认仅警告不阻止事件", async () => {
      let called = false;

      bus.addValidator("mission:complete", () => false);
      bus.on("mission:complete", () => {
        called = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(called).toBe(true);
    });

    it("严格模式下验证失败应阻止事件", async () => {
      let called = false;

      bus.setStrictValidation(true);
      bus.addValidator("mission:complete", () => false);
      bus.on("mission:complete", () => {
        called = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(called).toBeFalsy();
    });

    it("严格模式开关应正确切换", () => {
      expect(bus.isStrictValidation()).toBeFalsy();

      bus.setStrictValidation(true);
      expect(bus.isStrictValidation()).toBe(true);

      bus.setStrictValidation(false);
      expect(bus.isStrictValidation()).toBeFalsy();
    });

    it("移除验证器后事件应正常触发", async () => {
      let called = false;

      bus.setStrictValidation(true);
      bus.addValidator("mission:complete", () => false);
      bus.removeValidator("mission:complete");
      bus.on("mission:complete", () => {
        called = true;
      });

      await bus.emit("mission:complete", { missionId: "test" });

      expect(called).toBe(true);
    });

    it("验证器应接收正确的参数", async () => {
      let receivedArgs: unknown = null;

      bus.addValidator("mission:complete", (args) => {
        receivedArgs = args;
        return true;
      });

      bus.on("mission:complete", () => {});
      await bus.emit("mission:complete", { missionId: "verify-test" });

      expect(JSON.stringify(receivedArgs)).toEqual(
        JSON.stringify([{ missionId: "verify-test" }])
      );
    });
  });

  describe("订阅取消函数", () => {
    it("取消订阅后监听器不应被调用", async () => {
      let called = false;
      const unsub = bus.subscribe("mission:complete", () => {
        called = true;
      });

      unsub();
      await bus.emit("mission:complete", { missionId: "test" });

      expect(called).toBeFalsy();
    });

    it("取消订阅应返回 void", () => {
      const unsub = bus.subscribe("mission:complete", () => {});
      const result = unsub();
      expect(result === undefined).toBe(true);
    });

    it("多次调用取消函数应安全无副作用", async () => {
      let called = false;
      const unsub = bus.subscribe("mission:complete", () => {
        called = true;
      });

      unsub();
      unsub();
      unsub();

      await bus.emit("mission:complete", { missionId: "test" });
      expect(called).toBeFalsy();
    });
  });

  describe("getListenerCount", () => {
    it("应正确统计指定事件的监听器数量", () => {
      bus.on("mission:complete", () => {});
      bus.on("mission:complete", () => {});
      bus.on("item:get", () => {});

      expect(bus.getListenerCount("mission:complete")).toBe(2);
      expect(bus.getListenerCount("item:get")).toBe(1);
    });

    it("未指定事件时应统计所有监听器", () => {
      bus.on("mission:complete", () => {});
      bus.on("mission:complete", () => {});
      bus.on("item:get", () => {});

      expect(bus.getListenerCount()).toBe(3);
    });

    it("空总线应返回 0", () => {
      expect(bus.getListenerCount()).toBe(0);
      expect(bus.getListenerCount("mission:complete")).toBe(0);
    });
  });

  describe("getRegisteredEvents", () => {
    it("应返回所有注册过的事件名", () => {
      bus.on("mission:complete", () => {});
      bus.on("item:get", () => {});

      const events = bus.getRegisteredEvents();
      expect(events.length).toBe(2);
      expect(events).toContain("mission:complete");
      expect(events).toContain("item:get");
    });

    it("空总线应返回空数组", () => {
      const events = bus.getRegisteredEvents();
      expect(events.length).toBe(0);
    });
  });

  describe("globalEventBus 单例", () => {
    it("应该是 EventBus 的实例", () => {
      expect(globalEventBus instanceof EventBus).toBe(true);
    });

    it("应该可以正常使用", async () => {
      let called = false;
      const unsub = globalEventBus.subscribe("mission:complete", () => {
        called = true;
      });

      await globalEventBus.emit("mission:complete", { missionId: "singleton-test" });
      expect(called).toBe(true);

      unsub();
      called = false;
      await globalEventBus.emit("mission:complete", { missionId: "singleton-test" });
      expect(called).toBeFalsy();
    });
  });

  describe("向后兼容性", () => {
    it("on/off 应兼容 Emittery 原生用法", async () => {
      let called = false;
      const listener = () => {
        called = true;
      };

      bus.on("mission:complete", listener);
      await bus.emit("mission:complete", { missionId: "test" });
      expect(called).toBe(true);

      called = false;
      bus.off("mission:complete", listener);
      await bus.emit("mission:complete", { missionId: "test" });
      expect(called).toBeFalsy();
    });

    it("emit 应接受可变参数", async () => {
      let receivedArgs: unknown = null;

      bus.on("item:get", (...args: unknown[]) => {
        receivedArgs = args;
      });

      const items = [{ id: 1 }, { id: 2 }];
      await bus.emit("item:get", { items: items as any });

      expect(receivedArgs).toEqual([{ items: items }]);
    });
  });
});
