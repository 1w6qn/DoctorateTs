/**
 * Immer Patch 转换工具模块
 * 
 * 提供将 Immer 库产生的 Patch 数组转换为结构化对象的功能，
 * 用于生成玩家数据的增量更新（delta）。
 */

import { Patch } from "immer";

/**
 * 设置嵌套对象的值
 * 
 * 根据路径数组在目标对象上设置值，如果路径不存在则自动创建中间对象。
 * 
 * @param obj - 目标对象
 * @param origin - 原始对象，用于处理数组类型的路径
 * @param path - 属性路径数组
 * @param value - 要设置的值
 */
const setNestedValue = (obj: any, origin: any, path: (string | number)[], value: any) => {
  let current = obj;
  let originCurrent = origin;

  for (let index = 0; index < path.length; index++) {
    const key = path[index];
    if (Array.isArray(originCurrent)) {
      setNestedValue(obj, origin, path.slice(0, index), originCurrent);
      break;
    }
    if (index === path.length - 1) {
      current[key] = value;
    } else {
      if (!current[key]) {
        current[key] = {};
      }
      current = current[key];
      originCurrent = originCurrent[key] || {};
    }
  }
};

/**
 * 将 Patch 数组转换为结构化对象
 * 
 * 将 Immer 产生的 Patch 数组转换为包含 modified 和 deleted 两个部分的对象，
 * 便于客户端进行增量数据更新。
 * 
 * @param patch - Immer Patch 数组
 * @param origin - 原始数据对象
 * @returns 包含 modified 和 deleted 的结构化对象
 */
export function patchesToObject(patch: Patch[], origin: any) {
  const result = {
    modified: {},
    deleted: {},
  };
  patch.forEach((op) => {
    const path = op.path;
    if (op.op === "remove") {
      setNestedValue(result.deleted, origin, path, null);
    } else {
      setNestedValue(result.modified, origin, path, op.value);
    }
  });
  return result;
}

/**
 * syncData 增量字段子集（对齐官服输出，2026-08-07 抓包校准）
 *
 * 官服 /account/syncData 的 playerDataDelta.modified 固定包含以下 16 个字段，
 * 其中大部分为 user 的子集（增量同步：客户端本地已有其余部分）。
 * null 表示整字段全量下发；数组表示只下发该字段的指定子 key。
 */
export const SYNC_DATA_DELTA_KEYS: { [field: string]: string[] | null } = {
  building: ["roomSlots", "rooms", "music"],
  pushFlags: null,
  troop: ["chars"],
  shop: ["GP", "CLASSIC", "HS"],
  activity: ["TYPE_ACT53SIDE"],
  dungeon: ["cowLevel", "sixStar"],
  status: null,
  mainline: null,
  nameCardStyle: null,
  crisisV2: ["nst", "shop"],
  rlv2: ["outer"],
  sandboxPerm: ["summary"],
  campaignsV2: null,
  crisis: ["shop"],
  // 官方 tshop 只下发当前开启的活动商店（22 个 key），非全量 112 个
  tshop: [
    "shop_act31side", "shop_act1mainss", "shop_act35side", "shop_act38side",
    "shop_act44side", "shop_act43side", "shop_act42side", "shop_act2mainss",
    "shop_act40side", "shop_act41side", "shop_act39side", "shop_act37side",
    "shop_act34side", "shop_act33side", "shop_act3mainss", "shop_act46side",
    "shop_act47side", "shop_act48side", "shop_act49side", "shop_act51side",
    "shop_act4mainss", "shop_act53side",
  ],
};

/**
 * 构建 syncData 的 playerDataDelta（对齐官服 16 字段子集）
 *
 * 勿用 ...player.delta（Immer patches 单点）：客户端 syncData 需要完整字段子集，
 * 只下发单点 patch 是客户端进不了游戏的根因之一。
 *
 * @param playerData - 玩家数据对象（_playerdata）
 * @returns { modified, deleted } 结构的增量对象
 */
export function buildSyncDataDelta(playerData: any): {
  modified: Record<string, unknown>;
  deleted: Record<string, unknown>;
} {
  const modified: Record<string, unknown> = {};
  for (const [field, keys] of Object.entries(SYNC_DATA_DELTA_KEYS)) {
    const src = playerData?.[field];
    if (src === undefined) continue;
    if (keys === null) {
      // 整字段全量下发
      modified[field] = src;
    } else {
      const sub: Record<string, unknown> = {};
      for (const k of keys) {
        if (src[k] !== undefined) sub[k] = src[k];
      }
      modified[field] = sub;
    }
  }
  return { modified, deleted: {} };
}