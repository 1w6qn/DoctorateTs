/**
 * 基建 Buff 模板注册表
 *
 * 每个 buff 类别一个模板类（buffs/*.ts），按 buffId/结构匹配分发：
 * - ControlGlobalTpl：control_* 控制中枢全局
 * - RoomSpeedTpl：输出型房间速度/产量（efficiency/vup%）
 * - DormRecoveryTpl：dorm_* 宿舍心情恢复
 * - MoodCostTpl：描述含「消耗」的心情消耗
 *
 * 新增技能：在 buffs/ 新建模板类（继承 BaseBuffTpl，JSDoc 内嵌官方效果原文），
 * 加入 TPLS 列表即可——引擎调用点统一经 buffTplFor 分发，未命中回退既有引擎。
 */
import { BaseBuffTpl } from "../buff-tpl";
import type { BuildingBuffLike } from "../buff-parse";
import { ControlGlobalTpl } from "./control-global";
import { RoomSpeedTpl } from "./room-speed";
import { DormRecoveryTpl } from "./dorm-recovery";
import { MoodCostTpl } from "./mood-cost";

/** 模板类构造签名（实例化 + 静态 matches） */
interface BuffTplCtor {
  new (raw: BuildingBuffLike): BaseBuffTpl;
  matches(buff: BuildingBuffLike): boolean;
}

/** 模板类注册表（按声明顺序匹配；matches 互斥） */
const TPLS: BuffTplCtor[] = [
  ControlGlobalTpl,
  RoomSpeedTpl,
  DormRecoveryTpl,
  MoodCostTpl,
];

/**
 * 按 buff 结构分发模板实例
 * @param buff - 原始 buff 对象（excel.BuildingData.buffs[buffId]）
 * @returns 命中的模板实例；无匹配返回 null（调用方回退既有引擎）
 */
export function buffTplFor(
  buff: BuildingBuffLike | null | undefined,
): BaseBuffTpl | null {
  if (!buff || typeof buff !== "object") return null;
  for (const T of TPLS) {
    if (T.matches(buff)) return new T(buff);
  }
  return null;
}
