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

/** 干员 buff 激活所需信息（取自 troop.chars） */
export interface CharBuffSource {
  charId: string;
  level: number;
  evolvePhase: number;
}

/** "PHASE_2" → 2；未知/缺失 → 0（同时接受数字原值） */
export function phaseRank(phase?: string | number | null): number {
  if (phase == null) return 0;
  if (typeof phase === "number") return phase;
  const m = /PHASE_(\d+)/.exec(phase);
  return m ? Number(m[1]) : 0;
}

/** 富文本数值标签（官方基建技能描述格式）：vup=提升 / vdown=降低 / vdo=每单位 */
const CC_TAG_RE = /<@cc\.(vup|vdown|vdo)>\s*([+-]?\d+(?:\.\d+)?)\s*(%?)\s*<\/?\s*>/g;

/** 描述中单个富文本数值标签 */
export interface DescTagValue {
  /** 标签名：vup | vdown | vdo */
  tag: string;
  /** 数值（保留符号，如 +0.25 / -0.52） */
  value: number;
  /** 是否带 %（真实加成标记） */
  hasPct: boolean;
  /** 是否带 +/- 符号 */
  signed: boolean;
}

/**
 * 通用解析：提取描述中全部 <@cc.vup>/<@cc.vdown>/<@cc.vdo> 数值标签。
 * 官方描述数值嵌在富文本标签内（如"心情每小时消耗<@cc.vdown>+0.25</>"），
 * 一个描述可含多个标签（如"每<@cc.vup>16</>个机器人+<@cc.vup>4%</>"）。
 * @param desc - 技能描述文本
 * @returns 按出现顺序的标签值数组（无标签返回 []）
 */
export function parseDescTags(desc?: string | null): DescTagValue[] {
  const out: DescTagValue[] = [];
  let m: RegExpExecArray | null;
  while ((m = CC_TAG_RE.exec(desc ?? ""))) {
    out.push({
      tag: m[1],
      value: parseFloat(m[2]),
      hasPct: !!m[3],
      signed: /[+-]/.test(m[2]),
    });
  }
  return out;
}

/**
 * 描述 <@cc.vup> 标签中的有效数值：
 * 多个标签时优先带 % 的（真实加成，如"每<@cc.vup>16</>个机器人+<@cc.vup>4%</>"→4），
 * 其次带符号的（+0.15），最后无符号数字；无 vup 标签返回 null。
 */
export function parseVupValue(desc?: string | null): number | null {
  const all = parseDescTags(desc).filter((t) => t.tag === "vup");
  if (all.length === 0) return null;
  return (
    all.find((x) => x.hasPct) ??
    all.find((x) => x.signed) ??
    all[0]
  ).value;
}

/**
 * 纯文本百分比兜底：描述不含富文本标签时直接提取文本中的百分数
 * （如"生产力+15%"→15、"-20.5%"→-20.5）；无百分比返回 null。
 */
export function parsePlainPercent(desc?: string | null): number | null {
  const m = /([+-]?\d+(?:\.\d+)?)\s*%/.exec(desc ?? "");
  return m ? parseFloat(m[1]) : null;
}

/**
 * 心情消耗值：取描述"消耗"之后第一个 <@cc.vup>/<@cc.vdown>/<@cc.vdo> 数值
 * （带符号，点/小时）。
 * 真实数据（2026-08-12 校准）：正 = 消耗（vdown +0.25 → changeScale -25），
 * 负 = 减免（vup -0.25 → changeScale +25）；无消耗语境返回 null。
 */
export function parseMoodCostValue(desc?: string | null): number | null {
  const idx = (desc ?? "").indexOf("消耗");
  if (idx === -1) return null;
  const m = /<@cc\.(?:vup|vdown|vdo)>\s*([+-]?\d+(?:\.\d+)?)/.exec(
    (desc ?? "").slice(idx),
  );
  return m ? parseFloat(m[1]) : null;
}

/** 同技能分组 key：buffId 去掉 [] 后缀（control_prod_spd[000] → control_prod_spd） */
export function buffGroupKey(buffId: string): string {
  return buffId.replace(/\[.*\]$/, "");
}

/**
 * buff 数值（乘法系数）：
 * - efficiency > 0 → efficiency/100（输出型精确字段）
 * - 否则描述 <@cc.vup>：带 % → /100；DORMITORY 无 % → 心情恢复原值（点/小时）
 * - 其余无 %（机器人/阈值/计数）→ 0（不贡献，避免误读）
 */
export function buffValue(buff: any): number {
  return buffValueForTarget(buff, buff?.roomType);
}

/**
 * buff 数值（按目标房间语境）：同 buffValue，但无 % 时若目标为 DORMITORY
 * 取原值（心情恢复 点/小时）——用于控制中枢 control_dorm_* 全局（buff.roomType 为 CONTROL）。
 * 兜底链路：efficiency → vup 标签 → vdown/vdo 带 % 标签 → 纯文本百分比 → 0
 * （计数/阈值类如"每 N 个机器人"不贡献，避免生产速度虚高）。
 */
export function buffValueForTarget(buff: any, targetRoom?: string | null): number {
  if (buff == null) return 0;
  const eff = buff.efficiency;
  if (typeof eff === "number" && eff > 0) return eff / 100;
  const desc = buff.description ?? "";
  // 1) vup 标签（首选真实加成标记）
  const vup = parseVupValue(desc);
  if (vup != null) {
    if (/%/.test(desc)) return vup / 100;
    if (targetRoom === "DORMITORY") return vup;
    return 0;
  }
  // 2) vdown/vdo 标签：仅带 % 视为加成（如"消耗降低<@cc.vdown>0.25%</>"）；
  //    无 % 的（机器人/阈值/计数）不可靠 → 不贡献
  const tag = parseDescTags(desc).find((t) => t.hasPct);
  if (tag) return tag.value / 100;
  // 3) 纯文本百分比兜底（老数据/无标签描述）
  const plain = parsePlainPercent(desc);
  if (plain != null) return plain / 100;
  return 0;
}

/** 干员在指定房间类型下激活的 buff 列表（条件 level/phase + roomType 匹配） */
export function getActiveCharBuffs(
  char: CharBuffSource,
  roomType: string,
): any[] {
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

/** 列表内按同技能分组取最高后的总和（用于"同种效果取最高/槽位多档技能"） */
function maxByGroup(buffs: any[], resolver: (b: any) => number): number {
  const best = new Map<string, number>();
  for (const b of buffs ?? []) {
    const key = buffGroupKey(b?.buffId ?? "");
    best.set(key, Math.max(best.get(key) ?? 0, resolver(b)));
  }
  return [...best.values()].reduce((s, v) => s + v, 0);
}

/**
 * 房间速度/产量加成（乘法系数总和，≥0）：
 * 遍历进驻干员，取其在 roomType 下激活的 buff；targets 非空时仅匹配指定配方类型。
 */
export function roomSpeedBonus(
  chars: CharBuffSource[],
  roomType: string,
  targets?: string[],
): number {
  let total = 0;
  for (const char of chars ?? []) {
    const buffs = getActiveCharBuffs(char, roomType).filter((b) => {
      const t = b?.targets;
      if (!Array.isArray(t) || t.length === 0) return true;
      if (!targets || targets.length === 0) return true;
      return targets.some((x) => t.includes(x));
    });
    total += maxByGroup(buffs, buffValue);
  }
  return total;
}

/** 控制中枢 control_* buff → 目标房间类型（按 buffId 前缀） */
const CONTROL_TARGET_PREFIX: Array<[RegExp, string]> = [
  [/^control_prod_/, "MANUFACTURE"],
  [/^control_tra_/, "TRADING"],
  [/^control_dorm_/, "DORMITORY"],
  [/^control_meeting|^control_upMeeting/, "MEETING"],
  [/^control_hire_/, "HIRE"],
];

/**
 * 控制中枢全局加成（按目标房间类型，乘法系数）：control_* buff 中同种效果跨干员取最高。
 * 仅映射生产/贸易/宿舍/会客/人力五类前缀（心情/费用类 control_mp_* 等不影响生产）。
 */
export function controlGlobalBonus(
  controlChars: CharBuffSource[],
): Record<string, number> {
  const byTarget = new Map<string, Map<string, number>>();
  for (const char of controlChars ?? []) {
    for (const b of getActiveCharBuffs(char, "CONTROL")) {
      const prefix = b?.buffId ?? "";
      const target = CONTROL_TARGET_PREFIX.find(([re]) => re.test(prefix))?.[1];
      if (!target) continue;
      const key = buffGroupKey(prefix);
      const groups = byTarget.get(target) ?? new Map<string, number>();
      groups.set(key, Math.max(groups.get(key) ?? 0, buffValueForTarget(b, target)));
      byTarget.set(target, groups);
    }
  }
  const out: Record<string, number> = {};
  for (const [target, groups] of byTarget) {
    out[target] = [...groups.values()].reduce((s, v) => s + v, 0);
  }
  return out;
}

/** 宿舍恢复加成（点/小时）：进驻宿舍干员的 dorm_* buff，同种取最高 */
export function dormRecoveryBonus(dormChars: CharBuffSource[]): number {
  const buffs: any[] = [];
  for (const char of dormChars ?? []) {
    buffs.push(...getActiveCharBuffs(char, "DORMITORY"));
  }
  return maxByGroup(buffs, buffValue);
}

/**
 * 干员在指定房间的心情额外消耗（changeScale 负向修正量，正数 = 消耗、负数 = 减免）。
 * 单位校准（真实存档，2026-08-12）：消耗语境 vup/vdown 数值（点/小时）× 100 = AP/秒——
 * 如 manu_formula_spd&cost 消耗<@cc.vdown>+0.25</> → -25；trade_ord_spd&cost 消耗<@cc.vup>-0.25</> → +25。
 */
export function charMoodCost(char: CharBuffSource, roomType: string): number {
  let cost = 0;
  for (const b of getActiveCharBuffs(char, roomType)) {
    const v = parseMoodCostValue(b?.description);
    if (v != null) cost += v * 100;
  }
  return cost;
}
