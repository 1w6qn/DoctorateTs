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
