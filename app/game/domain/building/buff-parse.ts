/**
 * 基建 buff 纯解析函数（从 buff.ts 拆出，供 buff.ts 引擎与 buffs/ 模板类共用）
 *
 * 拆分动机：buffs/ 模板类（建议 3）需要解析函数而不与 buff.ts 形成循环依赖
 * （buff.ts → buffs/index 单向），故把无 IO 的纯解析收敛于此。
 * 实现为迁移前 buff.ts 的逐字副本（2026-08-26），导出面与迁移前一致
 * （buff.ts 在此 re-export，外部调用方零改动）。
 */

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

/** 列表内按同技能分组取最高后的总和（用于"同种效果取最高/槽位多档技能"） */
export function maxByGroup(buffs: any[], resolver: (b: any) => number): number {
  const best = new Map<string, number>();
  for (const b of buffs ?? []) {
    const key = buffGroupKey(b?.buffId ?? "");
    best.set(key, Math.max(best.get(key) ?? 0, resolver(b)));
  }
  return [...best.values()].reduce((s, v) => s + v, 0);
}
