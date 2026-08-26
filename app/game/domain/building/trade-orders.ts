/**
 * 贸易站订单生成引擎（纯函数，无 IO——概率配置启动时从 data/building/trade-order-dist.json 一次性加载）
 *
 * 官方机制（prts.wiki 贸易站页，2026-08-25 全量对齐）：
 * - 贵金属订单交付数按站级概率分布：Lv1 {2金:100%}；Lv2 {2:60%,3:40%}；
 *   Lv3 {2:30%,3:50%,4:20%}（替代原均匀随机 1~4）
 * - 暖机概率改写（裁缝/手工艺品类，buff trade_ord_wt&cost）：
 *   α（小幅提升）累积工作 3 小时后 → {4:55%,3:30%,2:15%}；
 *   β（提升）累积 5 小时后 → {4:85%,3:10%,2:5%}；
 *   双 α 叠加 → {4:65%,3:22%,2:13%}（玩家实测，中置信）；α+β → 按 β。
 *   干员离岗/换工位累积清零（由 mood 基座 warmupSec 维护）。
 * - 收益 = 交付赤金数 × 汇率（goldItems 3003，现 500 龙门币/条）
 */

import { readJsonSync } from "@utils/file";

/**
 * 贸易站订单概率配置（data/building/trade-order-dist.json，启动时一次性加载）。
 * 数值来自 PRTS 贸易站页（见文件头注释），excel building_data.tradingData 无此数据。
 */
const ORDER_CONFIG = readJsonSync<{
  warmupAlphaHours: number;
  warmupBetaHours: number;
  goldOrderDistribution: Record<string, GoldDistEntry[]>;
  distAlpha: GoldDistEntry[];
  distBeta: GoldDistEntry[];
  distAlphaAlpha: GoldDistEntry[];
}>(`${__dirname}/../../../../data/building/trade-order-dist.json`);

/** 订单交付数分布条目（权重百分比） */
export interface GoldDistEntry {
  /** 赤金交付数 */
  gold: number;
  /** 权重（百分比） */
  weight: number;
}

/** 站级基础概率表（贸易站页；JSON 键为字符串，此处转型保持既有数字索引类型） */
export const GOLD_ORDER_DISTRIBUTION = ORDER_CONFIG.goldOrderDistribution as unknown as Record<
  number,
  GoldDistEntry[]
>;

/** 暖机激活所需累积工时（小时）：α 小幅提升 3h、β 提升 5h（贸易站页） */
export const WARMUP_ALPHA_HOURS = ORDER_CONFIG.warmupAlphaHours;
export const WARMUP_BETA_HOURS = ORDER_CONFIG.warmupBetaHours;

/** α 激活分布：4金55% / 3金30% / 2金15%（贸易站页） */
const DIST_ALPHA: GoldDistEntry[] = ORDER_CONFIG.distAlpha;
/** β 激活分布：4金85% / 3金10% / 2金5%（贸易站页） */
const DIST_BETA: GoldDistEntry[] = ORDER_CONFIG.distBeta;
/** 双 α 叠加分布：4金65% / 3金22% / 2金13%（玩家实测期望 3.46，中置信） */
const DIST_ALPHA_ALPHA: GoldDistEntry[] = ORDER_CONFIG.distAlphaAlpha;

/** 已激活暖机技能数量（达到对应工时阈值的干员数） */
export interface WarmupActive {
  /** α（小幅提升，3h）激活干员数 */
  alpha: number;
  /** β（提升，5h）激活干员数 */
  beta: number;
}

/**
 * 订单交付数概率分布：
 * β 激活 → β 分布（α+β 同站时按 β）；否则 ≥2 个 α → 双α 分布；
 * 1 个 α → α 分布；无暖机 → 站级基础表（越界等级回退 1~3）。
 */
export function goldOrderDistribution(
  roomLevel: number,
  warmup?: WarmupActive,
): GoldDistEntry[] {
  if ((warmup?.beta ?? 0) >= 1) return DIST_BETA;
  const alpha = warmup?.alpha ?? 0;
  if (alpha >= 2) return DIST_ALPHA_ALPHA;
  if (alpha === 1) return DIST_ALPHA;
  const lv = Math.min(Math.max(roomLevel ?? 1, 1), 3);
  return GOLD_ORDER_DISTRIBUTION[lv];
}

/**
 * 按权重抽取赤金交付数。
 * @param dist - 概率分布
 * @param roll - 随机数 [0,1)，可注入便于测试
 */
export function pickGoldCount(dist: GoldDistEntry[], roll: number = Math.random()): number {
  const total = dist.reduce((s, e) => s + e.weight, 0);
  let r = roll * total;
  for (const e of dist) {
    r -= e.weight;
    if (r <= 0) return e.gold;
  }
  return dist[dist.length - 1]?.gold ?? 2;
}

/**
 * 暖机技能档位判定（buff trade_ord_wt&cost 后缀）：
 * [00x] = α（小幅提升）、[01x] = β（提升）；非暖机技能返回 null。
 */
export function warmupSkillTier(buffId: string): "alpha" | "beta" | null {
  if (/^trade_ord_wt&cost\[00/.test(buffId)) return "alpha";
  if (/^trade_ord_wt&cost\[01/.test(buffId)) return "beta";
  return null;
}
