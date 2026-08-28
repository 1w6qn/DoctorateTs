/**
 * 控制中枢全局 buff 模板（control_* 前缀）
 *
 * 官方效果原文示例：
 * 「进驻控制中枢时，每个<岁>干员进驻在宿舍以外的设施则<人间烟火>+0.15（最多4名）」——
 * 描述含 <$cc.*> 条件标签的走特殊技能语义（fraction/token），由 special.ts 计算。
 *
 * 匹配：buffId 以 control_ 开头（含 control_token_）。
 * 效果：control_* 全局作用于目标房间（按 CONTROL_TARGET_PREFIX 前缀映射），
 * 跨干员同种效果取最高——value() 返回单 buff 的乘法系数（targets 匹配由引擎处理）。
 */
import { BaseBuffTpl } from "../buff-tpl";
import { buffValueForTarget } from "../buff-parse";
import { isConditionSkill, specialBuffValue } from "../special";
import type { SpecialSkillContext } from "../special";

export class ControlGlobalTpl extends BaseBuffTpl {
  readonly kind = "CONTROL_GLOBAL";

  static matches(buff: any): boolean {
    const id = buff?.buffId ?? "";
    return id.startsWith("control_");
  }

  /**
   * 对目标房间的全局加成（乘法系数）：target 由引擎按 CONTROL_TARGET_PREFIX
   * 前缀映射传入（如 control_dorm_* → DORMITORY，无 % 时取心情恢复原值）。
   * @param targetRoom - 目标房间类型
   */
  valueForTarget(targetRoom: string): number {
    return buffValueForTarget(this.raw, targetRoom);
  }

  value(ctx?: unknown): number {
    const c = ctx as SpecialSkillContext | undefined;
    if (isConditionSkill(this.raw?.description)) {
      return specialBuffValue(this.raw, c) ?? 0;
    }
    return 0;
  }
}
