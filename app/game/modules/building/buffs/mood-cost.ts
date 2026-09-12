/**
 * 干员心情消耗 buff 模板（消耗语境：描述含「消耗」关键字）
 *
 * 官方效果原文示例：
 * 「进驻<控制中枢>时，自身心情每小时消耗+0.25」——描述含"消耗"，
 * <@cc.vdown>+0.25</> → 消耗 +0.25 点/小时（changeScale 负向修正 -25）。
 *
 * 匹配：描述含「消耗」且带 vup/vdown/vdo 数值标签的 buff。
 * 效果：心情额外消耗（点/小时，正=消耗、负=减免）。
 */
import { BaseBuffTpl } from "../buff-tpl";
import { parseMoodCostValue } from "../buff-parse";
import type { BuildingBuffLike } from "../buff-parse";

export class MoodCostTpl extends BaseBuffTpl {
  readonly kind = "MOOD_COST";

  static matches(buff: BuildingBuffLike): boolean {
    const desc = buff?.description ?? "";
    return desc.includes("消耗") && /<@cc\.(?:vup|vdown|vdo)>/.test(desc);
  }

  value(): number {
    return parseMoodCostValue(this.raw?.description) ?? 0;
  }
}
