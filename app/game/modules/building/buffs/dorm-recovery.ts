/**
 * 宿舍心情恢复 buff 模板（dorm_* 前缀）
 *
 * 官方效果原文示例：
 * 「进驻<宿舍>时，自身心情每小时恢复+0.15」——描述 <@cc.vup>+0.15</> 无 %，
 * 按宿舍语境取原值（点/小时）。
 *
 * 匹配：buffId 以 dorm_ 开头。
 * 效果：心情恢复（点/小时），同种效果跨干员取最高；涣散干员进驻宿舍同样恢复
 * （休息语境，由引擎 allowDispersed 传入）。
 */
import { BaseBuffTpl } from "../buff-tpl";
import { buffValueForTarget } from "../buff-parse";

export class DormRecoveryTpl extends BaseBuffTpl {
  readonly kind = "DORM_RECOVER";

  static matches(buff: any): boolean {
    const id = buff?.buffId ?? "";
    return id.startsWith("dorm_");
  }

  value(): number {
    // DORMITORY 语境：无 % 的 vup 取原值（点/小时）
    return buffValueForTarget(this.raw, "DORMITORY");
  }
}
