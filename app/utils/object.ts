/**
 * 对象工具（零依赖，替代 lodash 的 pick/omit——项目仅用到这两个能力）
 */

/** 从对象中挑选指定键组成新对象（键不存在时跳过；lodash.pick 的零依赖替代） */
export function pickKeys<T extends object, K extends keyof T>(
  obj: T,
  keys: readonly K[],
): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const k of keys) {
    if (k in obj) out[k] = obj[k];
  }
  return out;
}

/**
 * 挑选键（动态键名版）：keys 为运行时字符串（如客户端传入的排序键），返回 Partial<T>。
 * 不存在的键静默跳过——与 lodash.pick 行为一致。
 */
export function pickLoose<T extends object>(obj: T, keys: readonly string[]): Partial<T> {
  const rec = obj as Record<string, unknown>;
  const dst: Record<string, unknown> = {};
  for (const k of keys) {
    if (k in rec) dst[k] = rec[k];
  }
  return dst as Partial<T>;
}

/** 返回排除指定键后的浅拷贝（lodash.omit 的零依赖替代） */
export function omitKeys<T extends object, K extends keyof T>(
  obj: T,
  keys: readonly K[],
): Omit<T, K> {
  const out: Record<string, unknown> = { ...obj } as Record<string, unknown>;
  for (const k of keys) delete out[k as string];
  return out as Omit<T, K>;
}
