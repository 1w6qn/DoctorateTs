/**
 * 基建特殊技能适配模块
 *
 * 官方基建 buff 中有一批"特殊技能"——描述含条件标签 <$cc.tag.X> / <$cc.g.X> /
 * <$cc.m.X> / <$cc.tra.X>，加成语义为条件/数量依赖，与普通固定加成不同：
 * - fraction（"每个"）：每个符合条件标签的干员提供 +Y%（如薇薇安娜
 *   「每个进驻在制造站的<骑士>干员生产力+7%」→ 加成 = 7% × 制造站骑士数）
 * - token（条件触发）：条件满足才 +Y%（如布丁「有2台以上<作业平台>进驻发电站时
 *   制造站+2%」、麒麟R夜刀「与<怪物猎人小队>干员同驻控制中枢时+2%」）
 * 若按普通 buffValue 解析会把其中的 vup% 当无条件固定加成 → 生产/贸易速度虚高。
 *
 * 数据源（100% 官方在库）：
 * - excel.GameDataConst.termDescriptionDict：cc.tag.x / cc.g.x / cc.m.x / cc.tra.x 术语
 *   → 干员名单（中文名/特殊名，196 名 100% 可映射到 character_table）
 * - excel.CharacterTable：干员名 → charId 索引
 *
 * 注意：本模块不 import buff.ts（避免与 buff.ts → special 形成循环依赖导致
 * vite 下函数绑定失效）——百分比提取在此独立实现。
 *
 * 集成点（buff.ts）：roomSpeedBonus / controlGlobalBonus 对含条件标签的 buff
 * 改走 specialBuffValue（条件/数量计算），不再普通取 vup%。
 */
import excel from "@excel/excel";

/** 特殊技能判定所需上下文（各房间进驻干员 charId） */
export interface SpecialSkillContext {
  /** 当前目标房间干员（调用方房间） */
  roomCharIds?: string[];
  /** 制造站进驻干员 */
  manufactureCharIds?: string[];
  /** 贸易站进驻干员 */
  tradingCharIds?: string[];
  /** 宿舍进驻干员 */
  dormCharIds?: string[];
  /** 发电站进驻干员 */
  powerCharIds?: string[];
  /** 控制中枢进驻干员 */
  controlCharIds?: string[];
}

/** 描述中 <@cc.vup/vdown/vdo> 标签的百分比数值（本地实现，避免与 buff.ts 循环依赖） */
function parseBuffPercent(desc?: string | null): number | null {
  const re = /<@cc\.(?:vup|vdown|vdo)>\s*([+-]?\d+(?:\.\d+)?)\s*%/g;
  const all: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(desc ?? ""))) all.push(parseFloat(m[1]));
  if (all.length === 0) return null;
  // 优先带 + 号（明确加成语义）；无则取首个
  return all.find((v) => v > 0) ?? all[0];
}

/** 干员显示名 → charId 惰性索引（character_table.name） */
let _nameIndex: Map<string, string> | null = null;
function nameIndex(): Map<string, string> {
  if (_nameIndex) return _nameIndex;
  const idx = new Map<string, string>();
  const table = (excel as any).CharacterTable as any;
  for (const [id, c] of Object.entries(table ?? {})) {
    const name = (c as any)?.name;
    if (typeof name === "string" && name) idx.set(name, id);
  }
  _nameIndex = idx;
  return idx;
}

/** 术语 → 干员 charId 集合（惰性缓存；termDescriptionDict 描述第二行起为名单） */
const _termCharCache = new Map<string, Set<string>>();

/**
 * 术语（cc.tag / cc.g / cc.m / cc.tra 前缀）对应的干员 charId 集合。
 * 名单来自 gamedata_const.termDescriptionDict.description（"包含以下干员\n名字1、名字2…"），
 * 经 character_table.name 索引映射；术语未定义/名单为空返回空集。
 */
export function termCharIds(termId: string): Set<string> {
  const cached = _termCharCache.get(termId);
  if (cached) return cached;
  const out = new Set<string>();
  const term = (excel as any).GameDataConst?.termDescriptionDict?.[termId];
  const names = (term?.description ?? "")
    .split("\n")
    .slice(1)
    .flatMap((l: string) =>
      l.split(/[、，,]/).map((s: string) => s.trim()).filter(Boolean),
    );
  const idx = nameIndex();
  for (const n of names) {
    const id = idx.get(n);
    if (id) out.add(id);
  }
  _termCharCache.set(termId, out);
  return out;
}

/**
 * 描述中的条件标签 termId 列表：`<$cc.tag.knight>` → `cc.tag.knight`、
 * `<$cc.g.bs>` → `cc.g.bs`（排除 <@cc.kw>/<@cc.vup> 等数值/关键词标签）。
 */
export function parseConditionTerms(desc?: string | null): string[] {
  const out: string[] = [];
  const re = /<\$cc\.([a-zA-Z_][\w.]*)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(desc ?? ""))) out.push(`cc.${m[1]}`);
  return out;
}

/** 干员是否命中术语（标签/阵营/队伍） */
export function charMatchesTerm(charId: string, termId: string): boolean {
  return termCharIds(termId).has(charId);
}

/** 描述是否含条件标签（特殊技能判据） */
export function isConditionSkill(desc?: string | null): boolean {
  return /<\$cc\./.test(desc ?? "");
}

/** 描述中"进驻在X"的目标房间（剥 <@cc.kw> 标签后匹配）；无精确匹配返回 null */
const ROOM_TARGET_RE = /进驻在(?:<[^>]*>)*(制造站|贸易站|宿舍|发电站|控制中枢)/;
function roomTargetFromDesc(desc: string): string | null {
  const m = ROOM_TARGET_RE.exec(desc);
  return m ? m[1] : null;
}

/** 目标房间干员池：优先取"进驻在X"精确位置；无则按关键词兜底 */
function targetCharIds(
  desc: string,
  ctx?: SpecialSkillContext,
): string[] {
  const room = roomTargetFromDesc(desc);
  switch (room) {
    case "制造站":
      return ctx?.manufactureCharIds ?? ctx?.roomCharIds ?? [];
    case "贸易站":
      return ctx?.tradingCharIds ?? ctx?.roomCharIds ?? [];
    case "宿舍":
      return ctx?.dormCharIds ?? ctx?.roomCharIds ?? [];
    case "发电站":
      return ctx?.powerCharIds ?? [];
    case "控制中枢":
      return ctx?.controlCharIds ?? [];
  }
  // 兜底：无"进驻在X"（如"与X进驻控制中枢一起工作"）→ 关键词匹配
  if (desc.includes("发电站")) return ctx?.powerCharIds ?? [];
  if (desc.includes("控制中枢")) return ctx?.controlCharIds ?? [];
  if (desc.includes("制造站"))
    return ctx?.manufactureCharIds ?? ctx?.roomCharIds ?? [];
  if (desc.includes("贸易站"))
    return ctx?.tradingCharIds ?? ctx?.roomCharIds ?? [];
  if (desc.includes("宿舍")) return ctx?.dormCharIds ?? ctx?.roomCharIds ?? [];
  return ctx?.roomCharIds ?? [];
}

/** 目标房间内命中条件标签的干员数 */
function matchedCount(
  desc: string,
  terms: string[],
  ctx?: SpecialSkillContext,
): number {
  return targetCharIds(desc, ctx).filter((id) =>
    terms.some((t) => charMatchesTerm(id, t)),
  ).length;
}

/**
 * token 条件判定：数量条件（"N台以上"）或同驻条件（"与X一起/当与X"）。
 * 数量条件：命中干员数 ≥ N；同驻条件：命中干员数 ≥ 1。
 * 数量词可能被 <@cc.kw>N</> 标签包裹 → 先剥标签再匹配。
 */
function tokenSatisfied(
  desc: string,
  terms: string[],
  ctx?: SpecialSkillContext,
): boolean {
  const matched = matchedCount(desc, terms, ctx);
  const plain = desc.replace(/<@cc\.kw>(\d+)<\/>/g, "$1");
  const count = /(\d+)\s*台以上|(\d+)\s*名以上/.exec(plain);
  if (count) {
    return matched >= Number(count[1] || count[2]);
  }
  return matched >= 1;
}

/**
 * 特殊技能加成（乘法系数）：条件/数量依赖的 buff 加成。
 * - 非条件技能返回 null（调用方走普通 buffValue）
 * - 条件但无数值（pepe/closure 独占订单类）返回 0（不贡献速度）
 * - fraction（"每个"）：加成 = vup% / 100 × 目标房间命中干员数
 * - token：条件满足 → vup% / 100，否则 0
 */
export function specialBuffValue(
  buff: any,
  ctx?: SpecialSkillContext,
): number | null {
  const desc = buff?.description ?? "";
  if (!isConditionSkill(desc)) return null;
  const terms = parseConditionTerms(desc);
  const v = parseBuffPercent(desc);
  if (v == null || terms.length === 0) return 0;
  // fraction："每个进驻在X的Y干员+Z%"——按匹配干员数 × 加成
  if (/每个/.test(desc)) {
    return (v / 100) * matchedCount(desc, terms, ctx);
  }
  // token：条件满足 → Z%；不满足 → 0
  return tokenSatisfied(desc, terms, ctx) ? v / 100 : 0;
}
