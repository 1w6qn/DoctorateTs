/**
 * Immer Patch 转换工具模块
 * 
 * 提供将 mutative 库产生的 Patch 数组转换为结构化对象的功能，
 * 用于生成玩家数据的增量更新（delta）。
 */

import { Patch } from "mutative";

/**
 * 补丁叶子值（patch 值深拷贝后落树；最终随响应 JSON 序列化下发）
 */
export type DeltaLeafValue =
  | string
  | number
  | boolean
  | null
  | DeltaLeafValue[]
  | { [key: string]: DeltaLeafValue };

/**
 * delta 补丁树（modified / deleted 的递归结构）
 *
 * 中间节点为对象（路径下钻容器，可为数组），叶子为 patch 值。
 * core 侧自持定义：core 不得依赖 game/excel（架构守卫 R1），而 excel 的
 * JsonValue 语义正是本模块的输出形状。
 */
export type DeltaTree = { [key: string]: DeltaTree | DeltaLeafValue };

/** delta 视图：modified / deleted 两棵补丁树（可直接 JSON 序列化下发） */
export interface DeltaView {
  modified: DeltaTree;
  deleted: DeltaTree;
}

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
  // 兜底：mutative 补丁值可能是 draft proxy/冻结对象等 structuredClone 拒绝的类型
  // （历史出现 "null could not be cloned" 500）——克隆失败回退 JSON 深拷贝
  try {
    return structuredClone(value) as T;
  } catch {
    try {
      return JSON.parse(JSON.stringify(value)) as T;
    } catch {
      return value;
    }
  }
};

/**
 * 读取 origin 树的子节点（patch 路径下钻）
 *
 * origin 是调用方业务模型（如 PlayerDataModel），本工具只按 mutative 生成的 path
 * 做属性/下标读取，不假设任何业务字段。标量/缺失节点一律回退空对象——与历史
 * `originCurrent[key] || {}` 对「本函数唯一用途（Array.isArray 判定）」等价。
 * @param node - 当前 origin 节点
 * @param key - 路径键
 * @returns 子节点；非容器时为空对象
 */
const originChild = <T>(node: T, key: string | number): T => {
  if (node === null || typeof node !== "object") return {} as T;
  return (node as Record<string | number, T>)[key] ?? ({} as T);
};

/**
 * 设置嵌套对象的值
 * 
 * 根据路径数组在目标对象上设置值，如果路径不存在则自动创建中间对象。
 * 
 * @param obj - 目标补丁树（原地修改）
 * @param origin - 原始数据对象，仅用于「路径前缀在原件中是否为数组」判定
 * @param path - 属性路径数组
 * @param value - 要设置的值
 */
const setNestedValue = <TOrigin>(
  obj: DeltaTree,
  origin: TOrigin,
  path: (string | number)[],
  value: DeltaLeafValue,
): void => {
  let current: DeltaTree = obj;
  let originCurrent: TOrigin = origin;

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
      // patch 路径由 mutative 生成，中间节点必为容器（对象/数组）
      current = current[key] as DeltaTree;
      originCurrent = originChild(originCurrent, key);
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
 * @param origin - 原始数据对象（业务模型，仅按 path 读取，不修改）
 * @returns 包含 modified 和 deleted 的结构化对象
 */
export function patchesToObject<TOrigin>(
  patch: Patch<true>[],
  origin: TOrigin,
): DeltaView {
  const result: DeltaView = {
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
