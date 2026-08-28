/**
 * 事件优先级枚举
 *
 * 定义事件的优先级，用于事件调度和处理顺序控制。
 * 独立成文件以便 EventBus 与领域事件映射解耦引用。
 */
export enum Priority {
  HIGH = 0,
  MEDIUM = 1,
  LOW = 2,
}