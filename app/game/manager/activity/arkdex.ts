/**
 * 奇象巡展 ARKDEX 寻迹玩法（私服扩展，2026-08-17）
 *
 * 承载【奇象寻迹】的服务端状态与玩法函数：巡展道具（诱引剂/信息素）购买与使用、
 * 生物扫描成功/失败结算、数据库收录、扫描仪内存、数据集换、保护区解锁。
 *
 * 数据来源（2026-08-17 实锤：官方数据一直在服务器 excel 里）：
 * - `data/excel/activity_table.json → activity.arkHub.act1arkhub.moduleData.arkdexModule`
 *   含 37 种生物（creatureData）、3 属性克制（advantageTypeData/CounterMap，1.3/0.7）、
 *   10 种对决模式（modeData）、16 种道具（itemEffectData）、9 特质（traitData）、
 *   10 NPC（npcInfoData）、13 组对决策略（npcDuelStrategyData）、12 捕获区（captureAreaData）
 * - 已导出为 `data/arkhub/arkdex.json`（excel.ArkhubCreatureTable 懒加载读取）
 * - 道具价格逆向自官服 ARKDUEL 商店价格表（design-spec §28）；未在价格表的道具价格按同类推断并标注
 * - 六维换算为攻略明文（进攻×20≈攻击、守备×2≈防御、耐久×100≈HP、法抗×0.5、攻速=间隔倒数×10）
 */
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { logger } from "@utils/logger";
import { ARKHUB_ACT_ID, arkhubCreatureCollected } from "./arkhub";

/** 扫描仪内存上限（ArkdexConstData.arkdexCreatureBagMaxNum） */
export const ARKDEX_BAG_MAX = 400;
/** 单次扫描最多遭遇个体数（攻略：10） */
export const ARKDEX_MAX_ENCOUNTER = 10;
/** 扫描成功奖励：巡展纪念章 ×15（攻略：扫描成功结算 15 券） */
export const ARKDEX_SCAN_REWARD: ItemBundle = {
  id: "act1arkhub_token_seal",
  count: 15,
  type: "ACTIVITY_ITEM",
};

/**
 * 巡展道具定义（itemNumId/名称/单价/类型/每日库存）。
 * 名称与效果来自 arkdexModule.itemEffectData（16 种）；价格逆向自 ARKDUEL 商店
 * 价格表 §28（5004/5005/5006/5009/5010/5015/5021），其余按同类推断并标注：
 * - 味道诱引剂（5007/5008/5009/5010/5011，特质定向）= 60
 * - 信息素（5014/5015/5016 珍奇度 1/2/3 引出）= 60
 * - 特质信息素（5017-5021）= 60
 * 类型：lure=诱引剂（使用后遭遇目标条件生物）、pheromone=信息素（直接引出生物）。
 */
export interface ArkdexPropDef {
  itemNumId: number;
  name: string;
  price: number;
  /** 每日固定库存（稀有诱引剂 2，其余 5——对齐官服价格表 avail 字段） */
  dailyStock: number;
  type: "lure" | "pheromone";
}

/** 道具定义（价格来源：§28 价格表确认 / 推断标注） */
export const ARKDEX_PROPS: Record<number, ArkdexPropDef> = {
  5004: { itemNumId: 5004, name: "标准诱引剂", price: 40, dailyStock: 99, type: "lure" },
  5005: { itemNumId: 5005, name: "专业诱引剂", price: 60, dailyStock: 99, type: "lure" },
  5006: { itemNumId: 5006, name: "稀有诱引剂", price: 250, dailyStock: 2, type: "lure" },
  5007: { itemNumId: 5007, name: "酸味诱引剂", price: 60, dailyStock: 5, type: "lure" }, // 价格推断
  5008: { itemNumId: 5008, name: "甜味诱引剂", price: 60, dailyStock: 5, type: "lure" }, // 价格推断
  5009: { itemNumId: 5009, name: "甜味诱引剂", price: 60, dailyStock: 5, type: "lure" },
  5010: { itemNumId: 5010, name: "辣味诱引剂", price: 60, dailyStock: 5, type: "lure" },
  5011: { itemNumId: 5011, name: "苦味诱引剂", price: 60, dailyStock: 5, type: "lure" }, // 价格推断
  5014: { itemNumId: 5014, name: "标准信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5015: { itemNumId: 5015, name: "专业信息素", price: 60, dailyStock: 5, type: "pheromone" },
  5016: { itemNumId: 5016, name: "稀有信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5017: { itemNumId: 5017, name: "酸味信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5018: { itemNumId: 5018, name: "甜味信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5019: { itemNumId: 5019, name: "辣味信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5020: { itemNumId: 5020, name: "苦味信息素", price: 60, dailyStock: 5, type: "pheromone" }, // 价格推断
  5021: { itemNumId: 5021, name: "苦味信息素", price: 60, dailyStock: 5, type: "pheromone" },
};

/**
 * 属性克制数据（arkdexModule.advantageTypeData / advantageCounterMap 实锤）
 * 克制环：A(奇术)→B(本能)→C(百变)→A(奇术)；克制伤害 130%，被克 70%（damageScaleMap）。
 */
export const ARKDEX_ADVANTAGE_TYPES = ["奇术", "本能", "百变"] as const;
export type ArkdexAdvantageType = (typeof ARKDEX_ADVANTAGE_TYPES)[number];

/** 属性 id ↔ 中文名（advantageTypeData.name） */
export const ARKDEX_ADVANTAGE_ID_NAMES: Record<string, string> = {
  arkdex_advantage_A: "奇术",
  arkdex_advantage_B: "本能",
  arkdex_advantage_C: "百变",
};

/** 克制映射：攻击方属性 → 被克制的目标属性（advantageCounterMap 形状） */
export const ARKDEX_ADVANTAGE_COUNTER: Record<ArkdexAdvantageType, ArkdexAdvantageType> = {
  奇术: "本能",
  本能: "百变",
  百变: "奇术",
};

/** 伤害倍率：damageScaleMap 形状（克 1.3 / 被克 0.7 / 同级 1.0；中文属性名） */
export function arkdexDamageScale(attack: string, defend: string): number {
  if (ARKDEX_ADVANTAGE_COUNTER[attack as ArkdexAdvantageType] === defend) return 1.3;
  if (ARKDEX_ADVANTAGE_COUNTER[defend as ArkdexAdvantageType] === attack) return 0.7;
  return 1.0;
}

/** 伤害倍率（真实属性 id：arkdex_advantage_A/B/C；从 advantageTypeData.damageScaleMap 读） */
export function arkdexDamageScaleById(attackId: string, defendId: string): number {
  const types = (excel.ArkhubCreatureTable as any)?.advantageTypeData;
  const scale = types?.[attackId]?.damageScaleMap?.[defendId];
  if (typeof scale === "number") return scale;
  return 1.0;
}

/**
 * 六维 → 战斗数值换算（攻略明文；供 ARKDUEL 结算/客户端数据展示用）
 * 进攻性能×20≈攻击、守备性能×2≈防御、耐久性能×100≈最大生命、法术抗性×0.5≈法抗、
 * 进攻速率≈攻击间隔倒数的 10 倍、移动速度以 1.1 为基准。
 */
export function arkdexSixStatsToCombat(stats: {
  atk?: number; // 进攻性能
  def?: number; // 守备性能
  hp?: number; // 耐久性能
  mag?: number; // 法术抗性
  atkSpeed?: number; // 进攻速率
  moveSpeed?: number; // 移动速度
}): { attack: number; defense: number; maxHp: number; magicResist: number; attackInterval: number; moveSpeed: number } {
  const atk = stats.atk ?? 0;
  const def = stats.def ?? 0;
  const hp = stats.hp ?? 0;
  const mag = stats.mag ?? 0;
  const atkSpeed = stats.atkSpeed ?? 0;
  const moveSpeed = stats.moveSpeed ?? 0;
  return {
    attack: atk * 20,
    defense: def * 2,
    maxHp: hp * 100,
    magicResist: mag * 0.5,
    attackInterval: atkSpeed > 0 ? 10 / atkSpeed : 1,
    moveSpeed,
  };
}

/* ---------- arkdexModule 数据访问（excel.ArkhubCreatureTable = data/arkhub/arkdex.json） ---------- */

/** 生物数据（按 creatureNumId；不存在返回 undefined） */
export function arkdexCreature(numId: number): any {
  return (excel.ArkhubCreatureTable as any)?.creatureData?.[String(numId)];
}

/** 全部生物列表 */
export function arkdexCreatures(): any[] {
  return Object.values((excel.ArkhubCreatureTable as any)?.creatureData ?? {});
}

/** 生物属性中文名（advantageType id → 奇术/本能/百变；未知返回原 id） */
export function arkdexAdvantageName(numId: number): string {
  const c = arkdexCreature(numId);
  return ARKDEX_ADVANTAGE_ID_NAMES[c?.advantageType] ?? c?.advantageType ?? "";
}

/**
 * 对决模式规则（modeData：快速 singleRound / 常规 BO3 / 多人 4Player）
 * @returns numPlayers（参战人数）、rounds（轮数）、npcCount（NPC 敌数）、isMatching（全服匹配）
 */
export function arkdexModeRules(modeId: string): {
  numPlayers: number;
  rounds: number;
  npcCount: number;
  isMatching: boolean;
  isMultiplayer: boolean;
} {
  const m = (excel.ArkhubCreatureTable as any)?.modeData?.[modeId] ?? {};
  return {
    numPlayers: m.numMax ?? 2,
    rounds: m.maxRoundNumber ?? 1,
    npcCount: m.battleNpcCount ?? 0,
    isMatching: !!m.isMatching,
    isMultiplayer: !!m.isMultiplayer,
  };
}

/**
 * NPC 对决策略敌队（npcDuelStrategyData[strategyGroupId].creatureData）
 * 注意解码怪癖：活动表 FlatBuffers→JSON 把每条策略包装为
 * `{ groupId: {真数据}, 伪键: null }`——需先取嵌套同名键再取 creatureData。
 * @returns [{creatureNumId, traitMask}]；未知策略组返回空数组
 */
export function arkdexEnemySquad(strategyGroupId: string): Array<{ creatureNumId: number; traitMask: number }> {
  const group = (excel.ArkhubCreatureTable as any)?.npcDuelStrategyData?.[strategyGroupId];
  if (!group) return [];
  // 嵌套同名键（解码包装）优先；否则直接读
  const data = Array.isArray(group?.creatureData)
    ? group.creatureData
    : Array.isArray(group?.[strategyGroupId]?.creatureData)
      ? group[strategyGroupId].creatureData
      : [];
  return data ?? [];
}

/** ARKDEX 常量（dexConstData，如 bag 上限/队伍大小/稀有度上限） */
export function arkdexConst(key: string): number {
  return (excel.ArkhubCreatureTable as any)?.dexConstData?.[key] ?? 0;
}

/** 读 ARK_HUB 状态（update 配方外只读） */
function hub(player: PlayerDataManager): any {
  return (player._playerdata.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
}

/** 发放 token_seal（入背包 + coin/tshop 同步，复用 arkhub.ts 内部形状） */
async function grantSeal(player: PlayerDataManager, reward: ItemBundle): Promise<void> {
  await player.update(async (draft) => {
    const h = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (h) h.coin = (h.coin ?? 0) + reward.count;
    const shop = (draft.tshop as any)?.["shop_act1arkhub"];
    if (shop) shop.coin = (shop.coin ?? 0) + reward.count;
  });
  await player._trigger.emit("items:get", [[reward]]);
}

/**
 * 数据库收录辅助：按 dex 重新计算种类/活动频繁/亚种计数并发射任务+勋章事件。
 * dex 形状：{ [speciesKey]: { numId, isAlter, active? } }——isAlter 标记亚种记录
 * （亚种种类与本体是不同记录，镀层按亚种记录数计），active 标记"活动频繁"生物
 * （任务 12-14 的 arkhubMissionCollection2）。
 */
export async function arkhubDexRecount(player: PlayerDataManager): Promise<void> {
  const d = hub(player)?.dex ?? {};
  const entries = Object.values(d) as Array<{ isAlter?: boolean; active?: boolean }>;
  const count = entries.length;
  const alterCount = entries.filter((e) => e.isAlter).length;
  const activeCount = entries.filter((e) => e.active).length;
  await player.update(async (draft) => {
    const h = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!h) return;
    h.creatureCollected = count;
    h.activeCreatureCollected = activeCount;
    h.alterCollected = alterCount;
  });
  await arkhubCreatureCollected(player, { count, activeCount, alterCount });
}

/**
 * 扫描成功结算（攻略：扫描至少 1 个生物即成功，结算 15 券 + 个体数据入库）
 * @param creatureNumIds - 本次扫描捕获的生物种类 id 列表（去重由调用方保证）
 * @param alterOf - 亚种映射（{ [creatureNumId]: 本体种类 id }，非亚种不传）
 * @param active - 活动频繁标记（{ [creatureNumId]: boolean }）
 * @returns 是否成功（空列表 = 扫描失败）
 */
export async function arkhubScanSucceed(
  player: PlayerDataManager,
  args: {
    creatureNumIds: number[];
    alterOf?: Record<number, number>;
    active?: Record<number, boolean>;
  },
): Promise<boolean> {
  const { creatureNumIds } = args;
  if (!creatureNumIds || creatureNumIds.length === 0) {
    logger.info("arkdex", "扫描失败（未捕获任何生物）——无结算奖励");
    return false;
  }
  await grantSeal(player, ARKDEX_SCAN_REWARD);
  await player.update(async (draft) => {
    const h = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!h) return;
    h.dex = h.dex ?? {};
    h.scanBag = h.scanBag ?? [];
    h.scanSeq = h.scanSeq ?? 0;
    for (const numId of creatureNumIds.slice(0, ARKDEX_MAX_ENCOUNTER)) {
      const key = String(numId);
      if (!h.dex[key]) {
        h.dex[key] = {
          numId,
          isAlter: !!args.alterOf?.[numId],
          ...(args.alterOf?.[numId] ? { alterOf: args.alterOf[numId] } : {}),
          ...(args.active?.[numId] ? { active: true } : {}),
        };
      }
      if (h.scanBag.length >= ARKDEX_BAG_MAX) break; // 内存满：不再入袋
      h.scanSeq += 1;
      h.scanBag.push({
        id: h.scanSeq,
        numId,
        isAlter: !!args.alterOf?.[numId],
        ...(args.alterOf?.[numId] ? { alterOf: args.alterOf[numId] } : {}),
        fav: false,
        sourceUid: (draft.status as any)?.uid ?? "",
      });
    }
  });
  await arkhubDexRecount(player);
  logger.info("arkdex", `扫描成功: ${creatureNumIds.length} 只入库，+15 券`);
  return true;
}

/** 扫描失败（什么都不获得；事件占位——任务无失败计数） */
export async function arkhubScanFail(_player: PlayerDataManager): Promise<void> {
  // 攻略：扫描失败结算时什么都不会获得（无券、无个体数据）
}

/**
 * 信息素诱引生物扫描（任务 15 ArkhubCreatureCaptured）
 * 攻略：信息素引出的生物广播给区域内所有游客，每位游客最多扫 1 次；
 * 私服单机简化：调用即视为完成一次信息素扫描。
 */
export async function arkhubPheromoneScan(player: PlayerDataManager): Promise<void> {
  await player._trigger.emit("ArkhubCreatureCaptured", [{ activityId: ARKHUB_ACT_ID }]);
}

/**
 * 购买巡展道具（ARKDUEL 商店；扣 coin → 道具箱 +生效次数）
 * 攻略：所有工作人员共享库存、每日刷新；诱引剂/信息素使用后消耗生效次数，
 * 离开会场不清除。购买帧 subID 待官服抓包，此函数供帧回调/路由复用。
 * @param count - 购买数量（缺省 1）
 * @returns 是否成功（道具未知/库存不足/券不足返回 false）
 */
export async function arkhubBuyProp(
  player: PlayerDataManager,
  itemNumId: number,
  count: number = 1,
): Promise<boolean> {
  const def = ARKDEX_PROPS[itemNumId];
  if (!def || count < 1) return false;
  const totalPrice = def.price * count;
  const h = hub(player);
  if ((h?.coin ?? 0) < totalPrice) return false;
  // 库存限购（按自然日，跨日重置——简化：每日首购清零记录）
  const today = new Date().toDateString();
  let ok = false;
  await player.update(async (draft) => {
    const hh = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hh) return;
    const stockKey = `${itemNumId}`;
    const sold = hh.propSoldToday ?? {};
    if (sold.date !== today) {
      // 新的一天：重置每日售出记录
      hh.propSoldToday = { date: today, sold: {} };
    }
    const soldCount = hh.propSoldToday?.sold?.[stockKey] ?? 0;
    if (soldCount + count > def.dailyStock) return; // 库存不足
    hh.coin = (hh.coin ?? 0) - totalPrice;
    const shop = (draft.tshop as any)?.["shop_act1arkhub"];
    if (shop) shop.coin = Math.max(0, (shop.coin ?? 0) - totalPrice);
    hh.props = hh.props ?? {};
    const p = (hh.props[stockKey] = hh.props[stockKey] ?? { count: 0, uses: 0 });
    p.count += count;
    p.uses += count; // 诱引剂/信息素：每次使用消耗 1 次生效次数
    hh.propSoldToday.sold[stockKey] = soldCount + count;
    ok = true;
  });
  if (ok) {
    logger.info("arkdex", `购买道具 ${def.name}×${count}（单价 ${def.price}）`);
  }
  return ok;
}

/**
 * 使用巡展道具（消耗 1 次生效次数）
 * @returns 是否可用（道具不存在/生效次数用完返回 false；扣减在 update 内完成）
 */
export async function arkhubUseProp(
  player: PlayerDataManager,
  itemNumId: number,
): Promise<boolean> {
  const def = ARKDEX_PROPS[itemNumId];
  const key = String(itemNumId);
  let ok = false;
  await player.update(async (draft) => {
    const hh = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    const p = hh?.props?.[key];
    if (!def || !p || (p.uses ?? 0) < 1) return;
    p.uses -= 1;
    ok = true;
  });
  if (ok) {
    logger.info("arkdex", `使用道具 ${def.name}（剩余生效次数 ${hub(player)?.props?.[key]?.uses ?? 0}）`);
  }
  return ok;
}

/**
 * 设置交换需求（数据仪-交换站；攻略：只能指定想要的生物种类、同时 1 条）
 * @param wantSpecies - 想要的生物种类 id（null = 清除需求）
 * @param offerNumIds - 准备交换出去的生物个体种类列表
 */
export async function arkhubSetTrade(
  player: PlayerDataManager,
  wantSpecies: number | null,
  offerNumIds: number[] = [],
): Promise<void> {
  await player.update(async (draft) => {
    const h = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!h) return;
    h.trade = { wantSpecies: wantSpecies === null ? null : Number(wantSpecies), offerNumIds: offerNumIds ?? [] };
  });
}

/**
 * 发起/完成一次生物数据交换（任务 16 ArkhubCreatureExchange）
 * 私服单机简化：调用即视为发起 1 次交换（来源游客留空，交换站仅 1 条需求）。
 */
export async function arkhubDoTrade(player: PlayerDataManager): Promise<void> {
  await player._trigger.emit("ArkhubCreatureExchange", [{ activityId: ARKHUB_ACT_ID }]);
}

/**
 * 保护区解锁（攻略：与守门人的奇象拟合对战中获胜开放，含珍奇度 3 个体）
 * @param areaId - 保护区 area id（captureAreaData 键；私服用 CAPTURE 场景序数 1/2/3）
 */
export async function arkhubUnlockArea(
  player: PlayerDataManager,
  areaId: number | string,
): Promise<void> {
  await player.update(async (draft) => {
    const h = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!h) return;
    h.unlockedAreas = h.unlockedAreas ?? {};
    h.unlockedAreas[String(areaId)] = 1;
  });
  logger.info("arkdex", `保护区解锁: area=${areaId}`);
}
