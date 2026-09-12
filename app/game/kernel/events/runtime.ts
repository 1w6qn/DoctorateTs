/**
 * 游戏事件总线(运行时实现)
 *
 * 领域事件契约(EventMap/各事件映射)在 domain/events/ 定义;本文件保留全部
 * 运行时实现:TypedEventEmitter / EventBus / globalEventBus / Priority 转发 /
 * 中间件 / 验证器。对外导出符号与迁移前 @game/model/events 完全一致。
 *
 * 基于 Emittery 实现类型安全的事件发布/订阅机制。
 */
import { Priority } from "./";
import type { EventMap } from "./";
import Emittery from "emittery";
import { logger } from "@utils/logger";

/**
 * 类型化事件发射器类
 *
 * 继承自 Emittery,提供类型安全的事件发布和订阅功能。
 */
export class TypedEventEmitter extends Emittery<EventMap> {}

export { Priority } from "./";

/**
 * 事件中间件接口
 *
 * 用于在事件触发前/后执行自定义逻辑,可用于日志、校验、拦截等场景。
 */
export interface EventMiddleware<T extends keyof EventMap> {
  before?(
    eventName: T,
    args: EventMap[T]
  ): void | boolean | Promise<void | boolean>;
  after?(eventName: T, args: EventMap[T]): void | Promise<void>;
}

/**
 * 事件验证器类型
 *
 * 用于在事件触发前验证参数合法性,返回 false 则阻止事件触发。
 */
export type EventValidator<T extends keyof EventMap> = (
  args: EventMap[T]
) => boolean;

/**
 * 优先级监听器存储结构
 *
 * 外层 Map 的键为事件名称,内层 Map 的键为优先级,值为该优先级下的监听器集合。
 */
type PriorityListenerMap = Map<string, Map<Priority, Set<Function>>>;

/**
 * 事件总线类
 *
 * 继承自 TypedEventEmitter,在 Emittery 基础上扩展优先级监听器管理能力。
 * 支持 HIGH / MEDIUM / LOW 三种优先级,事件派发时按优先级顺序依次执行:
 * HIGH → MEDIUM → LOW,同一优先级内的监听器按注册顺序执行。
 *
 * 保留对 Emittery 原有 API(on / off / emit 等)的完全兼容性,
 * 未指定优先级的监听器继续通过 Emittery 内部机制处理。
 */
export class EventBus extends TypedEventEmitter {
  /**
   * 优先级监听器存储
   *
   * 以事件名为键,值为该事件不同优先级的监听器映射。
   */
  private priorityListeners: PriorityListenerMap = new Map();

  /**
   * 中间件存储
   *
   * 按注册顺序存储所有事件中间件,在事件派发前后执行。
   */
  private middlewares: EventMiddleware<keyof EventMap>[] = [];

  /**
   * 日志开关
   *
   * 默认为关闭状态,需要通过 enableLogging() 主动开启。
   */
  private loggingEnabled: boolean = false;

  /**
   * 验证器存储
   *
   * 以事件名为键,值为该事件注册的验证器集合。
   */
  private validators: Map<string, EventValidator<keyof EventMap>> = new Map();

  /**
   * 严格验证模式开关
   *
   * 默认为 false。开启后,验证失败会阻止事件派发;
   * 关闭时仅输出警告日志,不阻止事件。
   */
  private strictValidation: boolean = false;

  /**
   * 注册带优先级的事件监听器
   *
   * 覆盖父类 Emittery 的 on 方法,默认使用 MEDIUM 优先级。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级,默认为 {@link Priority.MEDIUM}
   */
  // @ts-expect-error Emittery 父类签名包含复杂泛型(数组事件名、predicate 等),
  // 此处收窄为单一事件名 + 优先级参数,行为上向后兼容。
  on<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): void {
    this.addPriorityListener(eventName, listener as Function, priority);
  }

  /**
   * 移除带优先级的事件监听器
   *
   * 若未指定 priority,则在所有优先级中查找并移除匹配的监听器。
   *
   * @param eventName 事件名称
   * @param listener  要移除的监听器函数
   * @param priority  可选,指定要移除的优先级
   */
  // @ts-expect-error 同 on,签名收窄。
  off<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority?: Priority
  ): void {
    const listenerMap = this.priorityListeners.get(eventName as string);
    if (!listenerMap) return;

    const target = listener as Function;

    if (priority !== undefined) {
      const set = listenerMap.get(priority);
      if (set) {
        set.delete(target);
        if (set.size === 0) {
          listenerMap.delete(priority);
        }
      }
    } else {
      for (const [, set] of listenerMap) {
        set.delete(target);
      }
    }

    if (listenerMap.size === 0) {
      this.priorityListeners.delete(eventName as string);
    }
  }

  /**
   * 发射事件
   *
   * 先按 HIGH → MEDIUM → LOW 的顺序依次执行带优先级的监听器
   * (同一优先级内按注册顺序执行),随后调用父类 Emittery 的 emit
   * 以保持与原有 API 的完全兼容。
   *
   * @param eventName 事件名称
   * @param args      事件参数
   */
  async emit<T extends keyof EventMap>(
    eventName: T,
    ...args: EventMap[T]
  ): Promise<void> {
    const startTime = this.loggingEnabled ? performance.now() : 0;

    const validator = this.validators.get(eventName as string);
    if (validator) {
      const passed = validator(args);
      if (!passed) {
        logger.warn(
          "EventBus",
          `Validation failed for event: ${eventName} args: ${JSON.stringify(args)}`,
        );
        if (this.strictValidation) {
          if (this.loggingEnabled) {
            const duration = (performance.now() - startTime).toFixed(3);
            logger.info(
              "EventBus",
              `emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms (blocked by validation)`,
            );
          }
          return;
        }
      }
    }

    for (const mw of this.middlewares) {
      if (mw.before) {
        const result = await mw.before(eventName, args);
        if (result === false) {
          if (this.loggingEnabled) {
            const duration = (performance.now() - startTime).toFixed(3);
            logger.info(
              "EventBus",
              `emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms (blocked)`,
            );
          }
          return;
        }
      }
    }

    const listenerMap = this.priorityListeners.get(eventName as string);
    if (listenerMap) {
      const orderedPriorities: Priority[] = [
        Priority.HIGH,
        Priority.MEDIUM,
        Priority.LOW,
      ];
      for (const priority of orderedPriorities) {
        const set = listenerMap.get(priority);
        if (!set) continue;
        for (const listener of Array.from(set)) {
          await (listener as (...a: unknown[]) => void)(...(args as unknown[]));
        }
      }
    }
    // 透传给 Emittery 原生路径时只带首参——这是刻意行为：
    // 本项目的 EventMap 契约是多参签名（如 "char:get": [string, {...}, cb?]），
    // 而带优先级的监听器全部走 priorityListeners 分支（on/off/once 均被覆写），
    // 参数完整。Emittery 原生订阅路径仅作为兼容逃生口存在，若未来有代码绕过
    // on() 直接用 Emittery API 订阅多参事件，将只能收到首参——新增订阅一律走 on()。
    await Emittery.prototype.emit.call(
      this,
      eventName,
      args[0]
    );

    for (const mw of this.middlewares) {
      if (mw.after) {
        await mw.after(eventName, args);
      }
    }

    if (this.loggingEnabled) {
      const duration = (performance.now() - startTime).toFixed(3);
      logger.info(
        "EventBus",
        `emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms`,
      );
    }
  }

  /**
   * 订阅事件,返回取消订阅函数
   *
   * 便于使用 `const unsub = bus.subscribe('x', fn); unsub();` 的模式。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级,默认为 {@link Priority.MEDIUM}
   * @returns 取消订阅函数,调用后将移除该监听器
   */
  subscribe<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): () => void {
    this.on(eventName, listener, priority);
    return () => this.off(eventName, listener, priority);
  }

  /**
   * 注册一次性监听器
   *
   * 监听器首次触发后会自动移除。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级,默认为 {@link Priority.MEDIUM}
   */
  // @ts-expect-error Emittery 父类 once 返回 Promise 且签名不同,此处重新定义。
  once<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): void {
    const wrapper = ((...args: unknown[]) => {
      this.off(eventName, wrapper as (...a: EventMap[T]) => void, priority);
      (listener as (...a: unknown[]) => void)(...args);
    }) as (...args: EventMap[T]) => void;
    this.on(eventName, wrapper, priority);
  }

  /**
   * 注册事件中间件
   *
   * 中间件可在事件派发前(before)和派发后(after)执行自定义逻辑,
   * before 返回 false 可阻止事件继续传播。
   * 中间件按注册顺序执行。
   *
   * @param middleware 事件中间件
   */
  useMiddleware<T extends keyof EventMap>(
    middleware: EventMiddleware<T>
  ): void {
    this.middlewares.push(
      middleware as EventMiddleware<keyof EventMap>
    );
  }

  enableLogging(): void {
    this.loggingEnabled = true;
  }

  disableLogging(): void {
    this.loggingEnabled = false;
  }

  /**
   * 启用或关闭严格验证模式
   *
   * 开启后,验证失败会阻止事件继续派发;关闭时仅输出警告日志。
   *
   * @param enabled 是否开启严格模式
   */
  setStrictValidation(enabled: boolean): void {
    this.strictValidation = enabled;
  }

  /**
   * 当前是否处于严格验证模式
   */
  isStrictValidation(): boolean {
    return this.strictValidation;
  }

  /**
   * 为指定事件添加验证器
   *
   * 事件派发前会先调用验证器校验参数合法性。
   * 若验证器返回 false,根据严格模式决定是否阻止事件派发。
   *
   * @param eventName 事件名称
   * @param validator 验证器函数
   */
  addValidator<T extends keyof EventMap>(
    eventName: T,
    validator: EventValidator<T>
  ): void {
    this.validators.set(eventName as string, validator as EventValidator<keyof EventMap>);
  }

  /**
   * 移除指定事件的验证器
   *
   * @param eventName 事件名称
   */
  removeValidator<T extends keyof EventMap>(eventName: T): void {
    this.validators.delete(eventName as string);
  }

  /**
   * 构建当前 EventBus 对应的验证中间件
   *
   * 返回的中间件会读取当前 validators 与 strictValidation 状态,
   * 可通过 {@link useMiddleware} 注册到同一 EventBus 或其他总线实例上。
   */
  createValidationMiddleware(): EventMiddleware<keyof EventMap> {
    return createValidationMiddleware(this.validators, this.strictValidation);
  }

  getListenerCount(eventName?: keyof EventMap): number {
    let count = 0;

    if (eventName) {
      const listenerMap = this.priorityListeners.get(eventName as string);
      if (listenerMap) {
        for (const [, set] of listenerMap) {
          count += set.size;
        }
      }
      count += super.listenerCount(eventName);
    } else {
      for (const [, listenerMap] of this.priorityListeners) {
        for (const [, set] of listenerMap) {
          count += set.size;
        }
      }
      count += super.listenerCount();
    }

    return count;
  }

  getRegisteredEvents(): string[] {
    const eventSet = new Set<string>();

    for (const [eventName] of this.priorityListeners) {
      eventSet.add(eventName);
    }

    return Array.from(eventSet);
  }

  /**
   * 添加一个带优先级的监听器到内部存储
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级
   */
  private addPriorityListener(
    eventName: string,
    listener: Function,
    priority: Priority
  ): void {
    let listenerMap = this.priorityListeners.get(eventName);
    if (!listenerMap) {
      listenerMap = new Map();
      this.priorityListeners.set(eventName, listenerMap);
    }
    let set = listenerMap.get(priority);
    if (!set) {
      set = new Set();
      listenerMap.set(priority, set);
    }
    set.add(listener);
  }
}

export const globalEventBus = new EventBus();

export function createLoggingMiddleware(): EventMiddleware<keyof EventMap> {
  let startTime: number = 0;

  return {
    before(eventName, args) {
      startTime = performance.now();
      logger.debug(
        "EventBus",
        `emit: ${eventName} args: ${JSON.stringify(args)}`,
      );
    },
    after(eventName, args) {
      const duration = (performance.now() - startTime).toFixed(3);
      logger.debug("EventBus", `complete: ${eventName} time: ${duration}ms`);
    },
  };
}

/**
 * 创建验证中间件
 *
 * 中间件在事件派发前检查是否存在注册的验证器:
 * - 若无验证器,直接放行;
 * - 若有验证器且校验通过,放行;
 * - 若校验失败,输出警告信息,并根据 strictValidation 决定是否阻止事件。
 *
 * @param validators       验证器映射(通常来自 EventBus 内部 validators)
 * @param strictValidation 是否启用严格模式,默认 false
 */
export function createValidationMiddleware(
  validators: Map<string, EventValidator<keyof EventMap>>,
  strictValidation: boolean = false
): EventMiddleware<keyof EventMap> {
  return {
    before(eventName, args) {
      const validator = validators.get(eventName as string);
      if (!validator) return;

      const passed = validator(args);
      if (!passed) {
        logger.warn(
          "EventBus",
          `Validation failed for event: ${eventName} args: ${JSON.stringify(args)}`,
        );
        if (strictValidation) {
          return false;
        }
      }
    },
  };
}
