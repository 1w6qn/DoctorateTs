/**
 * 领域事件契约组合（EventMap）
 *
 * 领域层事件契约:组合各领域事件映射为总契约,供 service 层事件总线
 * (service/events.ts)与订阅方类型化引用。
 * 本目录仅含纯类型,无运行时实现(总线/中间件/验证器在 service 侧)。
 *
 * 新增事件:在对应领域文件追加;跨领域共享事件放 core.ts。
 */
import { Priority } from "./priority";
import type { EventMapActivity } from "./activity";
import type { EventMapCore } from "./core";
import type { EventMapMission } from "./mission";
import type { EventMapMedal } from "./medal";
import type { EventMapRlv2 } from "./rlv2";

/** 事件映射总契约(键为事件名,值为事件参数数组) */
export type EventMap = EventMapCore & EventMapMission & EventMapMedal & EventMapRlv2 & EventMapActivity;

export { Priority } from "./priority";
export type { EventMapActivity } from "./activity";
export type { EventMapCore } from "./core";
export type { EventMapMission } from "./mission";
export type { EventMapMedal } from "./medal";
export type { EventMapRlv2 } from "./rlv2";

export * from "./runtime";
