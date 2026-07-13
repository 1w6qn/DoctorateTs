/**
 * 时间工具模块
 * 
 * 提供时间相关的工具函数，基于 moment 库封装。
 */

import moment from "moment";
import StartOf = moment.unitOfTime.StartOf;

/**
 * 获取当前时间戳（秒）
 * 
 * @returns 当前 Unix 时间戳（秒）
 */
export function now(): number {
  return moment().unix();
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
  return !moment(ts1 - delta).isSame(moment(ts2 - delta), type);
}