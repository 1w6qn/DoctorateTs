/**
 * act1vhalfidle（次生预案）活动配置读取
 *
 * 数据源：excel `ActivityTable.activity.halfidleVerify1.act1vhalfidle`
 * （`basicInfo.act1vhalfidle.type === "HALFIDLE_VERIFY1"`，实际键名经 `activityDictKey` 容错命中）。
 * 该对象含 gachaPoolData / stageProductionData / constData / charMaxRankData / techTreeData 等权威配置；
 * 原实现的 `vhalfidle.ts` 硬编码池（VHALFIDLE_POOLS）与真实任命卡池无对应关系，且不含消耗与产出数据。
 */
import excel from "@excel/excel";

import { activityDictKey } from "../shared/unlockActivity";
import { activityDetailJson, asShape } from "../shared/activity-json";
import type { JsonValue } from "@excel/json-value";

/** 活动 id（客户端 activityId） */
export const VHALFIDLE_ACT_ID = "act1vhalfidle";

/** 任命卡池配置（gachaPoolData[poolId]） */
export interface VHalfIdleGachaPool {
  poolId: string;
  itemId: string;
  poolType: string;
  name: string;
  charData: string[];
  consumeData: { gachaTimes: number; consume: number }[];
}

/** 单关产出配置（stageProductionData[stageId]） */
export interface VHalfIdleStageProduction {
  stageId: string;
  fixedProduction: string[];
  productionData: Record<
    string,
    { itemId: string; efficiencyMax: number; isFixed: boolean; maxDropValue: number }
  >;
}

/** 科技树节点（techTreeData[nodeId]） */
export interface VHalfIdleTechNode {
  nodeId: string;
  nodeType?: string;
  prevNodeId?: string[] | null;
  tokenCost?: number;
  name?: string;
}

/** 稀有度档位上限（charMaxRankData[TIER_n]） */
export interface VHalfIdleRankCap {
  maxEvolvePhase: number;
  maxRankData: Record<string, { evolvePhase: number; maxLevel: number; maxSkillRank: number }>;
}

/** 归一化后的 act1vhalfidle 配置 */
export interface VHalfIdleConfig {
  gachaPoolData: Record<string, VHalfIdleGachaPool>;
  gachaCharData: Record<string, { charId: string; isLinkageChar: boolean }>;
  stageProductionData: Record<string, VHalfIdleStageProduction>;
  stageIds: string[];
  techTreeData: Record<string, VHalfIdleTechNode>;
  productMaxEfficiencyDict: Record<string, number>;
  charMaxRankData: Record<string, VHalfIdleRankCap>;
  milestoneList: { milestoneId: string; orderId: number; tokenNum: number }[];
  milestoneId: string;
  techCostItemId: string;
  levelExpItemId: string;
  skillExpItemId: string;
  /** 产出结算间隔（秒）：efficiencyMax 为每小时产出，按该间隔折算 */
  produceCd: number;
  /** 离线产出累计时长上限（秒，默认 48h） */
  efficiencyDurationMax: number;
}

/** act1vhalfidle 活动详情消费面（excel `activity` 字典是未建模 JSON） */
type VHalfIdleDetailJson = {
  gachaPoolData?: Record<string, VHalfIdleGachaPool>;
  gachaCharData?: VHalfIdleConfig["gachaCharData"];
  stageProductionData?: VHalfIdleConfig["stageProductionData"];
  techTreeData?: Record<string, VHalfIdleTechNode>;
  charMaxRankData?: Record<string, VHalfIdleRankCap>;
  milestoneList?: VHalfIdleConfig["milestoneList"];
  constData?: Record<string, JsonValue>;
};

/** act1vhalfidle constData 消费面 */
type VHalfIdleConstJson = {
  normalStageIds?: string[];
  hardStageIds?: string[];
  productMaxEfficiencyDict?: Record<string, number>;
  milestoneId?: string;
  techCostItemId?: string;
  levelExpItemId?: string;
  skillExpItemId?: string;
  produceCd?: number;
  efficiencyDurationMax?: number;
};

/**
 * 读取 act1vhalfidle 活动配置（只读）
 * @returns 归一化配置；excel 未加载该活动时返回 undefined
 */
export function vhalfidleConfig(): VHalfIdleConfig | undefined {
  const key = activityDictKey("HALFIDLE_VERIFY1") ?? "halfidleVerify1";
  const detail = asShape<VHalfIdleDetailJson>(
    activityDetailJson(excel.ActivityTable.activity, key, VHALFIDLE_ACT_ID),
  );
  if (!detail) return undefined;
  const cd: VHalfIdleConstJson =
    asShape<VHalfIdleConstJson>(detail.constData) ?? {};
  return {
    gachaPoolData: detail.gachaPoolData ?? {},
    gachaCharData: detail.gachaCharData ?? {},
    stageProductionData: detail.stageProductionData ?? {},
    stageIds: [...(cd.normalStageIds ?? []), ...(cd.hardStageIds ?? [])],
    techTreeData: detail.techTreeData ?? {},
    productMaxEfficiencyDict: cd.productMaxEfficiencyDict ?? {},
    charMaxRankData: detail.charMaxRankData ?? {},
    milestoneList: detail.milestoneList ?? [],
    milestoneId: String(cd.milestoneId ?? "act1vhalfidle_token_point"),
    techCostItemId: String(cd.techCostItemId ?? "strategy_point"),
    levelExpItemId: String(cd.levelExpItemId ?? "level_exp"),
    skillExpItemId: String(cd.skillExpItemId ?? "skill_exp"),
    produceCd: Number(cd.produceCd ?? 900) || 900,
    efficiencyDurationMax: Number(cd.efficiencyDurationMax ?? 172800) || 172800,
  };
}

/**
 * 计算连续 count 次任命的道具总消耗
 *
 * consumeData 是「第 N 次任命消耗多少」的分档表（特约任命随次数递增：100/150/150/200），
 * 超出分档表的次数沿用最后一档。
 * @param pool - 卡池配置
 * @param usedTimes - 该池已任命次数（recruit.poolTimes）
 * @param count - 本次任命次数
 * @returns 需要消耗的道具数量
 */
export function gachaCost(pool: VHalfIdleGachaPool, usedTimes: number, count: number): number {
  const tiers = [...(pool.consumeData ?? [])].sort((a, b) => a.gachaTimes - b.gachaTimes);
  if (!tiers.length) return count;
  let total = 0;
  for (let i = 1; i <= count; i++) {
    const n = usedTimes + i;
    const tier = tiers.find((t) => t.gachaTimes >= n) ?? tiers[tiers.length - 1];
    total += Number(tier.consume ?? 0);
  }
  return total;
}

/**
 * 活动物品短键 → 官服物品 id（token_point 等已带前缀的键原样返回）
 * @param key - 活动库存键（level_exp / gacha_normal / act1vhalfidle_token_point ...）
 * @returns 官服 itemTable 物品 id
 */
export function vhalfidleItemId(key: string): string {
  return key.startsWith("act1vhalfidle_") ? key : "act1vhalfidle_" + key;
}

/**
 * 取某关卡每小时产出表（efficiencyMax，只取大于 0 的条目）
 *
 * 数据事实：全部关卡同名物品的 efficiencyMax 之和恰好等于 constData.productMaxEfficiencyDict[item]
 * （13 项逐一验证比例 1.000），因此 efficiencyMax 是「每小时产出」，上限为各物品的总量上限。
 * @param cfg - 活动配置
 * @param stageId - 关卡 id
 * @returns 物品键 → 每小时产出
 */
export function stageProductionRate(
  cfg: VHalfIdleConfig,
  stageId: string,
): Record<string, number> {
  const prod = cfg.stageProductionData?.[stageId];
  const rate: Record<string, number> = {};
  for (const [item, d] of Object.entries(prod?.productionData ?? {})) {
    const v = Number(d?.efficiencyMax ?? 0);
    if (v > 0) rate[item] = v;
  }
  return rate;
}
