/**
 * 协议公共类型模块
 *
 * 与服务端 playerDataDelta 增量结构、通用响应基类对应的类型定义。
 * 参考客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.PlayerDeltaResponse 等基类。
 *
 * 2026-08-19 官服对齐：新增 pushMessage 支持（原刻意省略）。官服 rlv2 响应
 * 顶层可带 pushMessage 数组（如 createGame 必含 {path:"rlv2ScrapLimit",payload:{}}），
 * 客户端据此触发入场剧情/提示等。本服务端现按主题（rogue_6 黑流树海）选择性下发。
 */

/** 服务端增量数据（Immer patch 转换结果：modified / deleted 两部分） */
export interface PlayerDataDelta {
  modified: { [key: string]: unknown };
  deleted: { [key: string]: unknown };
}

/** 官服推送消息（rlv2 各阶段的入场剧情/提示/状态变更通知） */
export interface RoguelikePushMessage {
  path: string;
  payload: unknown;
}

/**
 * 带玩家增量数据的响应基类
 * 对应 CS: Torappu.PlayerDeltaResponse。
 * 官服对齐新增 `pushMessage?`：为非空时才下发（多数路由无，避免破坏客户端合并）。
 */
export interface PlayerDeltaResponse {
  playerDataDelta: PlayerDataDelta;
  pushMessage?: RoguelikePushMessage[];
}
