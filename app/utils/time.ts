/**
 * 时间工具模块
 * 
 * 提供时间相关的工具函数，基于 moment 库封装。
 */

import moment from "moment";
import config from "../config";
// 类型别名（Node 原生 transform-types 不支持 import= 语法）
type StartOf = moment.unitOfTime.StartOf;

/**
 * 获取当前时间戳（秒）
 * 
 * @returns 当前 Unix 时间戳（秒）
 */
export function now(): number {
  return moment().unix();
}

/**
 * 获取客户端可见服务器时间戳（秒）——activity 切换（DoctoratePy 移植）
 *
 * `config.developer.timestamp`：-1（缺省）= 真实时间；数值 = 冻结到该时间戳
 * （仅允许过去时间——若值大于当前真实时间则回退真实时间，避免未来日期存档异常）。
 * 用于 syncData/gate 等客户端可见时钟（活动按 server ts 判定开放）。
 */
export function userTimestamp(): number {
  const nowTs = now();
  const userTs = config.developer?.timestamp ?? -1;
  if (userTs === -1 || userTs > nowTs) {
    return nowTs;
  }
  return userTs;
}

/**
 * 检查时间戳是否在指定范围内
 * 
 * @param ts - 待检查的时间戳
 * @param start - 开始时间戳
 * @param end - 结束时间戳
 * @returns 在范围内返回 true，否则返回 false
 */
export function checkBetween(ts: number, start: number, end: number): boolean {
  return ts >= start && ts <= end;
}

/**
 * 检查两个时间戳是否属于不同的时间单位
 * 
 * 用于判断是否进入新的周期（如每日、每周任务刷新）。
 * 
 * @param ts1 - 第一个时间戳
 * @param ts2 - 第二个时间戳
 * @param type - 时间单位类型（day, week, month 等）
 * @param delta - 时间偏移量（毫秒），默认为 14400000（4小时）
 * @returns 属于不同周期返回 true，否则返回 false
 */
export function checkNew(
  ts1: number,
  ts2: number,
  type: StartOf,
  delta = 14400000,
): boolean {
  // 修复：时间戳可能是秒级（now() 返回 moment().unix()，~1.7e9）或毫秒级
  //（moment().valueOf()，~1.7e12）。原实现把秒直接传给 moment(number)（按毫秒解析）
  // → 相邻两天（86400s）被当作同一"天"，每日/每周/每月刷新永不触发。
  // 按量级自动归一：> 1e11 视为毫秒，否则视为秒 ×1000；delta 语义为毫秒（默认 4h）。
  const ms1 = ts1 > 1e11 ? ts1 - delta : ts1 * 1000 - delta;
  const ms2 = ts2 > 1e11 ? ts2 - delta : ts2 * 1000 - delta;
  return !moment(ms1).isSame(moment(ms2), type);
}