/**
 * 协议公共类型模块
 *
 * 与服务端 playerDataDelta 增量结构、通用响应基类对应的类型定义。
 * 参考客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.PlayerDeltaResponse 等基类；
 * 本服务端从不发送 pushMessage，故响应基类仅含 playerDataDelta。
 */

/** 服务端增量数据（Immer patch 转换结果：modified / deleted 两部分） */
export interface PlayerDataDelta {
  modified: { [key: string]: unknown };
  deleted: { [key: string]: unknown };
}

/**
 * 带玩家增量数据的响应基类
 * 对应 CS: Torappu.PlayerDeltaResponse（服务端省略 pushMessage 字段）
 */
export interface PlayerDeltaResponse {
  playerDataDelta: PlayerDataDelta;
}
