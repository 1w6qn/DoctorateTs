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