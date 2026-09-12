/**
 * 活动 excel 未建模 JSON 读取辅助
 *
 * 生成类型里 `ActivityTable.activity` 是 `{ [typeKey: string]: JsonValue }`——异构活动详情，
 * 客户端模型未声明各活动的子形状。此前消费侧用 `as any` / `as {...}` 直达，
 * 把类型系统整段关掉；本文件把「按已知形状读取只读表数据」收口到一处：
 *
 * - {@link activityDetailJson} 做 `activity[typeKey][actId]` 的逐级对象收窄；
 * - {@link asRecord} / {@link asArray} / {@link asShape} 把 JSON 值读成调用方声明的
 *   局部视图类型（`T` 由调用方按消费面给出），仍然是精确类型而非 `any`。
 *
 * **用途仅限只读 excel 表数据**：形状由官方数据保证、服务端不写回。
 * 玩家存档内未建模字段禁止 JsonValue（mutative Draft 会 TS2589），存档一律走
 * `playerdata-server-adapt.ts` 的具名成员登记 + `ServerPayload`。
 *
 * 本文件不 import `@excel/excel` 单例（excel 端口守卫棘轮禁止新增直连）——
 * `activity` 字典由调用方传入。
 */
import { isJsonObject, type JsonObject, type JsonValue } from "@excel/json-value";

/**
 * `JsonValue | undefined` → JSON 对象收窄
 *
 * `json-value.ts` 的 {@link isJsonObject} 只接受 `JsonValue`（undefined 不在 JSON 域内），
 * 而可选链取值天然产生 `JsonValue | undefined`，故在此收口。
 * @param value - 待判定值
 * @returns 是否为 JSON 对象
 */
export function isJsonObjectValue(value: JsonValue | undefined): value is JsonObject {
  return value !== undefined && isJsonObject(value);
}

/**
 * 取活动详情对象（`activity[typeKey][actId]`）
 * @param activity - excel `ActivityTable.activity` 字典（调用方传入，避免单例直连）
 * @param typeKey - `activity` 字典的实际键（调用方经 activityDictKey 容错解析）
 * @param actId - 活动 id
 * @returns 活动详情对象（任一环缺失/非对象返回 undefined）
 */
export function activityDetailJson(
  activity: JsonObject,
  typeKey: string,
  actId: string,
): JsonObject | undefined {
  const typeDict = activity[typeKey];
  if (!isJsonObjectValue(typeDict)) return undefined;
  const detail = typeDict[actId];
  return isJsonObjectValue(detail) ? detail : undefined;
}

/**
 * JSON 值 → 字符串键字典视图（非对象按空表处理）
 * @param value - 原始 JSON 值
 * @returns 调用方声明的条目类型字典
 */
export function asRecord<T>(value: JsonValue | undefined): Record<string, T> {
  return (isJsonObjectValue(value) ? value : {}) as Record<string, T>;
}

/**
 * JSON 值 → 数组视图（非数组按空数组处理）
 * @param value - 原始 JSON 值
 * @returns 调用方声明的条目类型数组
 */
export function asArray<T>(value: JsonValue | undefined): T[] {
  return (Array.isArray(value) ? value : []) as T[];
}

/**
 * JSON 值 → 对象视图（非对象返回 undefined）
 * @param value - 原始 JSON 值
 * @returns 调用方声明的对象类型
 */
export function asShape<T>(value: JsonValue | undefined): T | undefined {
  return isJsonObjectValue(value) ? (value as T) : undefined;
}
