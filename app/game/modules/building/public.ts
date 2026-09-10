/**
 * building 模块对外门面（R3 模块边界：跨模块只可 import 对方 public.ts）
 *
 * 目前仅导出宿舍氛围信用结算——`SocialManager` 每日刷新时需要在 social 侧写入
 * `social.yesterdayReward.comfortAmount`（PRTS「信用」：宿舍氛围信用属「每日结算的
 * 信用」，次日于信用交易所手动领取），故由 building 提供纯计算入口。
 */
export { dormComfortCredit as settleDormComfortCredit } from "./logic/accrue";
