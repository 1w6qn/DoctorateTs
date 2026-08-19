/**
 * 奇象巡展（ARK_HUB）玩法事件入口（私服扩展，2026-08-17）
 *
 * 统一承载 ARK_HUB 玩法的计数更新与事件发射：ARKDUEL 结算、每日物资领取、
 * 生物数据收录、画像收集/发布。任务（8 类 Arkhub 模板，ActivityTable.missionData）
 * 与勋章（巡展印象/珍奇/镀层，medal_table）的进度都监听这些事件——计数写入
 * activity.ARK_HUB.act1arkhub 的私服扩展字段（官服快照无这些字段，客户端不读）。
 *
 * 调用方：网关回调（index.ts 注入 arkhub-gateway-local）、Phase 2 的 ARKDEX/
 * ARKPIXEL 玩法路由。所有函数幂等可重复调用（计数取 max/累加）。
 */
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { logger } from "@utils/logger";

/** ARK_HUB 活动 id（activity.basicInfo.act1arkhub） */
export const ARKHUB_ACT_ID = "act1arkhub";

/** 每日物资奖励：巡展纪念章 ×100（与网关 HUB_REWARD_MAP daily_task 对齐） */
export const ARKHUB_DAILY_SUPPLY_REWARD: ItemBundle = {
  id: "act1arkhub_token_seal",
  count: 100,
  type: "ACTIVITY_ITEM",
};

/**
 * 奇象拟合对战奖励：胜 15 券（官方：胜 15 / 负 7 + 概率道具）。
 * 结算帧胜负字段未确认（当前帧仅 battleId 回显），暂按胜利发放；
 * 待抓包确认胜负字段后接入 15/7 分支。
 */
export const ARKHUB_DUEL_WIN_REWARD: ItemBundle = {
  id: "act1arkhub_token_seal",
  count: 15,
  type: "ACTIVITY_ITEM",
};

/** 读 ARK_HUB 状态（防缺省；非 update 配方内只读用） */
function hubState(player: PlayerDataManager): any {
  return (player._playerdata.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
}

/** 自然日键（本地时区；每日物资/每日限次用） */
function dayKey(ts: number): string {
  return new Date(ts).toDateString();
}

/** 发放 token_seal（入背包 + ARK_HUB.coin / tshop.coin 同步，对齐活动任务领取形状） */
async function grantTokenSeal(
  player: PlayerDataManager,
  reward: ItemBundle,
): Promise<void> {
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (hub) hub.coin = (hub.coin ?? 0) + reward.count;
    const shop = (draft.tshop as any)?.["shop_act1arkhub"];
    if (shop) shop.coin = (shop.coin ?? 0) + reward.count;
  });
  await player._trigger.emit("items:get", [[reward]]);
}

/**
 * ARKDUEL 战斗结算（网关战斗结算帧后调用）
 * 累计对战次数（任务 17-19）+ 发放胜利奖励 + 同步币。
 */
export async function arkhubOnDuelSettle(
  player: PlayerDataManager,
): Promise<void> {
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    hub.duelCount = (hub.duelCount ?? 0) + 1;
  });
  await grantTokenSeal(player, ARKHUB_DUEL_WIN_REWARD);
  await player._trigger.emit("ArkhubPassDexBattle", [
    { activityId: ARKHUB_ACT_ID, count: hubState(player)?.duelCount ?? 0 },
  ]);
  logger.info("arkhub", `ARKDUEL 结算: duelCount=${hubState(player)?.duelCount}`);
}

/**
 * 每日物资领取（网关 daily_task 交互领奖后调用）
 * 每日限 1 次（按自然日），累计领取天数（任务 4-8）+ 发放 100 券。
 */
export async function arkhubOnDailySupply(
  player: PlayerDataManager,
): Promise<void> {
  let claimed = false;
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    const today = dayKey(Date.now());
    if (hub.dailySupplyLastDay === today) return; // 今日已领
    hub.dailySupplyLastDay = today;
    hub.dailySupplyDays = (hub.dailySupplyDays ?? 0) + 1;
    claimed = true;
  });
  if (!claimed) {
    logger.debug("arkhub", "每日物资今日已领取，跳过");
    return;
  }
  await grantTokenSeal(player, ARKHUB_DAILY_SUPPLY_REWARD);
  await player._trigger.emit("ArkhubDailyMissionCompleted", [
    { activityId: ARKHUB_ACT_ID, days: hubState(player)?.dailySupplyDays ?? 0 },
  ]);
  logger.info("arkhub", `每日物资领取: dailySupplyDays=${hubState(player)?.dailySupplyDays}`);
}

/**
 * 生物数据收录（ARKDEX 扫描入库后调用）
 * @param count - 已收录生物种类总数（任务 9-11/勋章 02）
 * @param activeCount - 已收录"活动频繁"种类数（任务 12-14）
 * @param alterCount - 已收录亚种数（勋章 025 镀层）
 */
export async function arkhubCreatureCollected(
  player: PlayerDataManager,
  args: { count: number; activeCount: number; alterCount: number },
): Promise<void> {
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    hub.creatureCollected = args.count;
    hub.activeCreatureCollected = args.activeCount;
    hub.alterCollected = args.alterCount;
  });
  await player._trigger.emit("ArkhubCreatureCollection", [
    { activityId: ARKHUB_ACT_ID, count: args.count, collectionKey: "arkhubMissionCollection1" },
  ]);
  await player._trigger.emit("ArkhubCreatureCollection", [
    { activityId: ARKHUB_ACT_ID, count: args.activeCount, collectionKey: "arkhubMissionCollection2" },
  ]);
  await player._trigger.emit("ActivityArkhubCreatureCollect", [
    { activityId: ARKHUB_ACT_ID, count: args.count, collectionKey: "arkhubMissionCollection1" },
  ]);
  await player._trigger.emit("ActivityArkhubAlterCollect", [
    { activityId: ARKHUB_ACT_ID, count: args.count, alterCount: args.alterCount },
  ]);
}

/** 信息素诱引生物扫描（任务 15；Phase 2 ARKDEX 调用） */
export async function arkhubCreatureCaptured(
  player: PlayerDataManager,
): Promise<void> {
  await player._trigger.emit("ArkhubCreatureCaptured", [
    { activityId: ARKHUB_ACT_ID },
  ]);
}

/** 发起生物数据交换（任务 16；Phase 2 交换站调用） */
export async function arkhubCreatureExchange(
  player: PlayerDataManager,
): Promise<void> {
  await player._trigger.emit("ArkhubCreatureExchange", [
    { activityId: ARKHUB_ACT_ID },
  ]);
}

/** 发布画像（任务 20-21；Phase 3 像素持久化调用） */
export async function arkhubPixelPublished(
  player: PlayerDataManager,
  count: number,
): Promise<void> {
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    hub.pixelPublished = count;
  });
  await player._trigger.emit("ArkhubPublishPixelArt", [
    { activityId: ARKHUB_ACT_ID, count },
  ]);
}

/** 收集画像（任务 22-23/勋章 01；Phase 3 像素持久化调用） */
export async function arkhubPixelCollected(
  player: PlayerDataManager,
  count: number,
): Promise<void> {
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    hub.pixelCollected = count;
  });
  await player._trigger.emit("ArkhubCollectPixelArt", [
    { activityId: ARKHUB_ACT_ID, count },
  ]);
  await player._trigger.emit("ActivityArkhubPixelCollect", [
    { activityId: ARKHUB_ACT_ID, count },
  ]);
}

/* ================= 枢纽引导/剧情推进（GuideFlags 渐进，2026-08-19） =================
 *
 * 现状背景：本地网关原先把 GuideFlags 全部初始化为"完成态"（1/2），客户端因此不触发
 * 任何引导对话/剧情（§25.2c 记：GuideFlags 是进度计数——0=未开始/1=播放中/2=完成）。
 * 本节实现"剧情推进"：GuideFlags 持久化到 ARK_HUB（per-player），渐进模式下初始给
 * 未开始态（0），玩家完成引导对话（交互帧 actor）→ 服务端推进 flag → 出展指引任务
 * 1-3（ArkhubMissionCompleted）随之完成。
 *
 * 安全设计：默认仍回退完成态（零风险）；`config.arkhub.guideProgressive=true` 开启
 * 渐进引导（index.ts 注入 + unlockActivity 播种联动）。
 */

/** 枢纽 GuideFlags 全部键（对齐网关 defaultGuideFlags / 官服完成态快照） */
export const ARKHUB_GUIDE_KEYS = [
  "arkhub_login",
  "terminal_guide",
  "capture_catch_guide_01",
  "capture_catch_guide_02",
  "arkdex_battle_guide",
  "pixel_unlock",
  "pixel_unlock_system",
  "area_1_block",
  "area_2_block",
  "area_3_blcok",
  "area_2_guard",
  "area_3_guard",
  "arkdex_mmkabi1",
] as const;
export type ArkhubGuideKey = (typeof ARKHUB_GUIDE_KEYS)[number];

/** 完成态 GuideFlags（对齐网关 defaultGuideFlags/官服完成态快照：进度类=2、布尔类=1） */
export function arkhubCompletedGuideFlags(): Record<string, number> {
  return {
    arkdex_battle_guide: 2,
    area_2_guard: 1,
    area_3_guard: 1,
    terminal_guide: 1,
    area_3_blcok: 1,
    terminal_guide_arkdex: 1,
    arkhub_login: 1,
    arkdex_mmkabi1: 1,
    capture_catch_guide_02: 2,
    pixel_unlock: 1,
    pixel_unlock_system: 1,
    area_2_block: 1,
    area_1_block: 1,
    capture_catch_guide_01: 2,
  };
}

/**
 * 渐进引导初始态（config.arkhub.guideProgressive=true 时首次下发；持久化后走存档值）。
 * 关键引导 flag=0（未开始，客户端播放引导对话），非引导/防卡 flag 保持完成态：
 * - capture_catch_guide_01（夏妮引导）保持 2——对话 actor 未确认，任务 1 播种完成态可领
 * - area_*_block / area_*_guard / arkdex_mmkabi1 保持 1——防区域/场景卡死
 * - capture_catch_guide_02 / arkdex_battle_guide / arkhub_login / terminal_guide / pixel_* = 0
 */
export function arkhubProgressiveGuideFlags(): Record<string, number> {
  return {
    ...arkhubCompletedGuideFlags(),
    arkhub_login: 0,
    terminal_guide: 0,
    capture_catch_guide_02: 0,
    arkdex_battle_guide: 0,
    pixel_unlock: 0,
    pixel_unlock_system: 0,
  };
}

/**
 * 读玩家 GuideFlags（持久化优先，兼容无 guideFlags 字段的存量存档）。
 * @param progressive - 无持久化时的缺省：true=渐进初始态（未开始，触发引导对话）；
 *                      false=完成态（不触发任何引导，默认零风险）。
 */
export function arkhubResolveGuideFlags(
  player: PlayerDataManager,
  progressive = false,
): Record<string, number> {
  const gf = hubState(player)?.guideFlags;
  if (gf && typeof gf === "object") {
    // 持久化优先；未持久化的引导键按渐进/完成态基线兜底——
    // progressive=true 时用渐进初始态（防卡键外引导=0），避免残留完成态导致新引导对话不触发
    const base = progressive ? arkhubProgressiveGuideFlags() : arkhubCompletedGuideFlags();
    return { ...base, ...(gf as Record<string, number>) };
  }
  return progressive ? arkhubProgressiveGuideFlags() : arkhubCompletedGuideFlags();
}

/**
 * 引导 actor → 推进的 GuideFlags（交互帧 actorId 匹配；值取 max 防回退）。
 * 覆盖完整引导链（arkvent actorTriggerOperations 实锤）：
 * - 夏妮引导①（capture_catch_guide_01，任务 1）：shiane_01（INTERACT 起点/AVG 提交）、
 *   shiane_02b（领奖 ReceiveArkhubReward reward_guide_01）
 * - 捕抓引导②（capture_catch_guide_02，任务 2）：mmkabi_auto（ENTER 起点/StartArkdexCaptureGuideBattle）、
 *   mmkabi_01b（领奖 + 设施解锁：扫描仪/道具箱/数据库）
 * - 终端引导（terminal_guide）：terminal_auto（ENTER）、terminal_02a（INTERACT）
 * - 对决引导（arkdex_battle_guide，任务 3）：bryota_01c（AUTO）
 * - 像素解锁：pixel_unlock
 */
export const ARKHUB_GUIDE_ACTOR_FLAGS: Record<string, Partial<Record<string, number>>> = {
  arkhub_main_shiane_01: { capture_catch_guide_01: 2 },
  arkhub_main_shiane_02b: { capture_catch_guide_01: 2 },
  arkhub_capture1_mmkabi_auto: { capture_catch_guide_02: 2 },
  arkhub_capture1_mmkabi_01b: {
    capture_catch_guide_02: 2,
    pixel_unlock: 1,
    pixel_unlock_system: 1,
  },
  arkhub_main_terminal_auto: { terminal_guide: 2 },
  arkhub_main_terminal_02a: { terminal_guide: 2 },
  arkhub_main_bryota_01c: { arkdex_battle_guide: 2 },
  pixel_unlock: { pixel_unlock: 1 },
};

/**
 * 推进引导进度（网关交互帧 actor 匹配后调用）
 * 落 ARK_HUB.guideFlags 持久化 + 按推进的 flag 发射 ArkhubMissionCompleted
 * （出展指引任务 1-3 模板监听 args.flag === param[2]）。
 */
export async function arkhubAdvanceGuide(
  player: PlayerDataManager,
  actorId: string,
): Promise<void> {
  const flags = ARKHUB_GUIDE_ACTOR_FLAGS[actorId];
  if (!flags) {
    logger.debug("arkhub", `引导 actor 未映射: ${actorId}`);
    return;
  }
  let changed: string[] = [];
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.[ARKHUB_ACT_ID];
    if (!hub) return;
    hub.guideFlags = hub.guideFlags ?? {};
    for (const [key, value] of Object.entries(flags)) {
      const cur = (hub.guideFlags[key] as number) ?? 0;
      if (cur < (value as number)) {
        hub.guideFlags[key] = value;
        changed.push(key);
      }
    }
  });
  if (changed.length === 0) {
    logger.debug("arkhub", `引导 ${actorId} 无新推进（flag 已达成）`);
    return;
  }
  for (const key of changed) {
    await player._trigger.emit("ArkhubMissionCompleted", [
      { activityId: ARKHUB_ACT_ID, flag: key },
    ]);
  }
  logger.info("arkhub", `引导推进 ${actorId}: ${changed.join(",")}`);
}
