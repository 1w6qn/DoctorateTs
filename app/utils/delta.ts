/**
 * Immer Patch 转换工具模块
 * 
 * 提供将 mutative 库产生的 Patch 数组转换为结构化对象的功能，
 * 用于生成玩家数据的增量更新（delta）。
 */

import { Patch } from "mutative";

/**
 * 深拷贝 patch 值（仅拷贝对象/数组，标量原样返回）
 *
 * 修复：AccountManager 在加载时对玩家数据 deepFreezeExcept（除 rlv2/medal/dungeon/
 * status/mission 外全部冻结，含 activity）。mutative 对冻结 base 结构共享产生的 patch
 * 值可能是冻结（不可扩展）对象，若被缓存为 result.modified 的节点，后续补丁向该节点
 * 扩展属性会抛 "object is not extensible"，导致 syncData 500。存入前深拷贝使其可扩展。
 * @param value - patch 值
 * @returns 可扩展的深拷贝副本（标量原样）
 */
const cloneData = <T>(value: T): T => {
  if (value === null || typeof value !== "object") return value;
  return structuredClone(value) as T;
};

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
      // 深拷贝后存储：避免冻结的 patch 值成为不可扩展节点
      current[key] = cloneData(value);
    } else {
      if (!current[key]) {
        current[key] = {};
      } else if (!Object.isExtensible(current[key])) {
        // 中间节点为冻结对象（先前 patch 值或 base 冻结子树）：克隆为可扩展副本
        current[key] = cloneData(current[key]);
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
export function patchesToObject(patch: Patch<true>[], origin: any) {
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
