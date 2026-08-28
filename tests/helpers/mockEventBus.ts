import { EventBus, TypedEventEmitter } from "@game/kernel/events/runtime";

/**
 * 创建一个测试用的 EventBus 实例
 * 基于真实 EventBus，可用于模拟事件发射器
 */
export function mockEventBus(): EventBus {
  return new EventBus();
}

/**
 * 创建一个轻量的 TypedEventEmitter 实例
 * 适用于不需要 EventBus 优先级/中间件特性的简单场景
 */
export function mockTypedEventEmitter(): TypedEventEmitter {
  return new TypedEventEmitter();
}
