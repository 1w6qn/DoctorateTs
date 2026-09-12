/**
 * 房间速度/产量 buff 模板（输出型：制造/贸易/发电等）
 *
 * 官方效果原文示例：
 * 「进驻<制造站>时，生产力+15%」——efficiency=15（百分比整数），
 * 或描述含 <@cc.vup>+15%</> 富文本数值标签。
 *
 * 匹配：带 efficiency（>0）或描述含 vup% 标签、roomType 为输出型房间的 buff。
 * 效果：乘法系数（efficiency/100 或 vup%/100）；含条件标签走特殊技能语义。
 */
import { BaseBuffTpl } from "../buff-tpl";
import { buffValue } from "../buff-parse";
import type { BuildingBuffLike } from "../buff-parse";
import { isConditionSkill, specialBuffValue } from "../special";
import type { SpecialSkillContext } from "../special";

const OUTPUT_ROOMS = ["MANUFACTURE", "TRADING", "POWER", "WORKSHOP", "TRAINING", "HIRE", "MEETING"];

export class RoomSpeedTpl extends BaseBuffTpl {
  readonly kind = "ROOM_SPEED";

  static matches(buff: BuildingBuffLike): boolean {
    const id = buff?.buffId ?? "";
    if (id.startsWith("control_")) return false; // 控制中枢全局归 ControlGlobalTpl
    if (id.startsWith("dorm_")) return false; // 宿舍恢复归 DormRecoveryTpl
    const eff = buff?.efficiency;
    if (typeof eff === "number" && eff > 0) return true;
    return OUTPUT_ROOMS.includes(buff?.roomType ?? "") && /<@cc\.vup>/.test(buff?.description ?? "");
  }

  value(ctx?: SpecialSkillContext): number {
    if (isConditionSkill(this.raw?.description)) {
      return specialBuffValue(this.raw, ctx) ?? 0;
    }
    return buffValue(this.raw);
  }
}
