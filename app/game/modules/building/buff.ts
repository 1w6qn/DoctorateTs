/**
 * 基建干员技能（buff）计算引擎
 *
 * 数据源：excel.BuildingData.buffs（760 个）——数值字段 efficiency（百分比整数，15=15%），
 * 无 efficiency 的 buff（控制中枢/宿舍心情类）数值嵌在描述 <@cc.vup>/<@cc.vdo> 富文本标签内。
 * 干员技能定义：BuildingData.chars[charId].buffChar[].buffData[] = { buffId, cond:{level,phase} }。
 *
 * 规则（数值/单位对齐真实存档校准，2026-08-12）：
 * - 激活条件：干员 level ≥ cond.level、evolvePhase ≥ cond.phase；buff.roomType === 进驻房间
 * - 数值解析：efficiency>0 用 efficiency/100；否则描述 <@cc.vup> 带 % 按 /100；
 *   宿舍（DORMITORY）无 % 的 vup 为心情恢复（点/小时）原值；其余无 % 数值（机器人/阈值等）
 *   含义不可靠 → 不贡献（避免生产速度虚高）
 * - 叠加：输出型（MANUFACTURE/TRADING/…）跨干员累加，同一技能（buffId 去 [] 后缀）取最高档
 *   （干员槽位内多个 buffData 为同一技能的不同解锁档，如 train_spd_doubleProf[100]/[110]）
 * - 控制中枢/宿舍型：跨干员"同种效果取最高"（与描述标注一致）
 * - 控制中枢干员的 control_* buff 全局作用于目标房间（按 buffId 前缀映射），同种取最高
 */
import excel from "@excel/excel";
import {
  isConditionSkill,
  specialBuffValue,
  SpecialSkillContext,
} from "./special";
import { isDispersedAp } from "./mood";
import {
  phaseRank,
  type DescTagValue,
  parseDescTags,
  parseVupValue,
  parsePlainPercent,
  parseMoodCostValue,
  buffGroupKey,
  buffValue,
  buffValueForTarget,
  maxByGroup,
} from "./buff-parse";
import { buffTplFor } from "./buffs";

/** 干员 buff 激活所需信息（取自 troop.chars） */
export interface CharBuffSource {
  charId: string;
  level: number;
  evolvePhase: number;
  /**
   * 干员当前心情（raw AP，building.chars[].ap）。缺失视为满心情。
   * 注意力涣散（ap ≤ 0）时技能失效（官方：后勤技能与基础效率大部分失效）。
   */
  ap?: number | null;
}

// 纯解析函数已迁移至 ./buff-parse（避免 buffs/ 模板类与 buff.ts 循环依赖）；
// 以下 re-export 保持导出面不变，外部调用方零改动。
export {
  phaseRank,
  parseDescTags,
  parseVupValue,
  parsePlainPercent,
  parseMoodCostValue,
  buffGroupKey,
  buffValue,
  buffValueForTarget,
  maxByGroup,
};
export type { DescTagValue };


/**
 * 干员在指定房间类型下激活的 buff 列表（条件 level/phase + roomType 匹配）。
 * 注意力涣散（ap ≤ 0）的干员默认不激活任何 buff（官方：涣散时后勤技能失效）；
 * 宿舍恢复等休息语境传 options.allowDispersed=true 跳过该判定。
 */
export function getActiveCharBuffs(
  char: CharBuffSource,
  roomType: string,
  options?: { allowDispersed?: boolean },
): any[] {
  if (!options?.allowDispersed && isDispersedAp(char?.ap)) return [];
  const building = excel.BuildingData as any;
  const slots = building?.chars?.[char?.charId]?.buffChar;
  if (!Array.isArray(slots)) return [];
  const out: any[] = [];
  for (const slot of slots) {
    for (const item of slot?.buffData ?? []) {
      const buffId = item?.buffId;
      const cond = item?.cond;
      if (!buffId) continue;
      const buff = building?.buffs?.[buffId];
      if (!buff) continue;
      if (cond?.level != null && (char?.level ?? 0) < cond.level) continue;
      if (cond?.phase && phaseRank(char?.evolvePhase) < phaseRank(cond.phase)) continue;
      if (buff.roomType && buff.roomType !== roomType) continue;
      out.push(buff);
    }
  }
  return out;
}

/**
 * 房间速度/产量加成（乘法系数总和，≥0）：
 * 遍历进驻干员，取其在 roomType 下激活的 buff；targets 非空时仅匹配指定配方类型。
 * 含条件标签的特殊技能（<$cc.*>，fraction/token）走 specialBuffValue 条件/数量计算，
 * 不再把描述中 vup% 当无条件固定加成（修复薇薇安娜/布丁等干员加成虚高）。
 * @param ctx - 特殊技能上下文（各房间干员，用于 fraction/token 条件判定）
 */
export function roomSpeedBonus(
  chars: CharBuffSource[],
  roomType: string,
  targets?: string[],
  ctx?: SpecialSkillContext,
): number {
  let total = 0;
  for (const char of chars ?? []) {
    const buffs = getActiveCharBuffs(char, roomType).filter((b) => {
      const t = b?.targets;
      if (!Array.isArray(t) || t.length === 0) return true;
      if (!targets || targets.length === 0) return true;
      return targets.some((x) => t.includes(x));
    });
    total += maxByGroup(buffs, (b) => {
      // 模板注册表优先（仅接受 ROOM_SPEED 类，其余回退既有逻辑——
      // 避免消耗/恢复类 buff 被速度模板误读）
      const tpl = buffTplFor(b);
      if (tpl?.kind === "ROOM_SPEED") return tpl.value(ctx);
      if (isConditionSkill(b?.description)) {
        return specialBuffValue(b, ctx) ?? 0;
      }
      return buffValue(b);
    });
  }
  return total;
}

/** 控制中枢 control_* buff → 目标房间类型（按 buffId 前缀） */
const CONTROL_TARGET_PREFIX: Array<[RegExp, string]> = [
  [/^control_prod_/, "MANUFACTURE"],
  [/^control_token_prod_/, "MANUFACTURE"],
  [/^control_bd_spd/, "MANUFACTURE"],
  [/^control_tra_/, "TRADING"],
  [/^control_token_tra_/, "TRADING"],
  [/^control_dorm_/, "DORMITORY"],
  [/^control_meeting|^control_upMeeting/, "MEETING"],
  [/^control_hire_/, "HIRE"],
];

/**
 * 控制中枢全局加成（按目标房间类型，乘法系数）：control_* buff 中同种效果跨干员取最高。
 * 仅映射生产/贸易/宿舍/会客/人力五类前缀（心情/费用类 control_mp_* 等不影响生产）。
 * 含条件标签的特殊技能（<$cc.*>，如 control_prod_fraction「每个骑士+7%」、
 * control_token_prod_spd「≥2台作业平台在发电站时+2%」）走 specialBuffValue
 * 条件/数量计算（需 ctx 提供各房间干员）。
 */
export function controlGlobalBonus(
  controlChars: CharBuffSource[],
  ctx?: SpecialSkillContext,
): Record<string, number> {
  const byTarget = new Map<string, Map<string, number>>();
  for (const char of controlChars ?? []) {
    for (const b of getActiveCharBuffs(char, "CONTROL")) {
      const prefix = b?.buffId ?? "";
      const target = CONTROL_TARGET_PREFIX.find(([re]) => re.test(prefix))?.[1];
      if (!target) continue;
      const key = buffGroupKey(prefix);
      const groups = byTarget.get(target) ?? new Map<string, number>();
      // 模板注册表优先（ControlGlobalTpl 覆盖 control_*，valueForTarget 走前缀映射）；
      // 未命中回退既有逻辑
      const tpl = buffTplFor(b);
      const val = tpl?.kind === "CONTROL_GLOBAL"
        ? isConditionSkill(b?.description)
          ? tpl.value(ctx)
          : tpl.valueForTarget(target)
        : isConditionSkill(b?.description)
          ? specialBuffValue(b, ctx) ?? 0
          : buffValueForTarget(b, target);
      groups.set(key, Math.max(groups.get(key) ?? 0, val));
      byTarget.set(target, groups);
    }
  }
  const out: Record<string, number> = {};
  for (const [target, groups] of byTarget) {
    out[target] = [...groups.values()].reduce((s, v) => s + v, 0);
  }
  return out;
}

/**
 * 宿舍恢复加成（点/小时）：进驻宿舍干员的 dorm_* buff，同种取最高。
 * 宿舍为休息语境——涣散干员进驻宿舍同样恢复（官方“休息中”状态），
 * 不受涣散失效影响。
 */
export function dormRecoveryBonus(dormChars: CharBuffSource[]): number {
  const buffs: any[] = [];
  for (const char of dormChars ?? []) {
    buffs.push(...getActiveCharBuffs(char, "DORMITORY", { allowDispersed: true }));
  }
  return maxByGroup(buffs, (b) =>
    buffTplFor(b)?.kind === "DORM_RECOVER" ? buffTplFor(b)!.value() : buffValue(b),
  );
}

/**
 * 干员在指定房间的心情额外消耗（changeScale 负向修正量，正数 = 消耗、负数 = 减免）。
 * 单位校准（真实存档，2026-08-12）：消耗语境 vup/vdown 数值（点/小时）× 100 = AP/秒——
 * 如 manu_formula_spd&cost 消耗<@cc.vdown>+0.25</> → -25；trade_ord_spd&cost 消耗<@cc.vup>-0.25</> → +25。
 */
export function charMoodCost(char: CharBuffSource, roomType: string): number {
  let cost = 0;
  for (const b of getActiveCharBuffs(char, roomType)) {
    // 模板注册表优先（仅接受 MOOD_COST 类，其余回退既有解析）
    const tpl = buffTplFor(b);
    const v = tpl?.kind === "MOOD_COST" ? tpl.value() : parseMoodCostValue(b?.description);
    if (v != null) cost += v * 100;
  }
  return cost;
}
