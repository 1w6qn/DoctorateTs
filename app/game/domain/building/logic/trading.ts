/**
 * 基建分区逻辑：贸易站（订单生成/加速/交付/结算/策略/劳动力购买）
 *
 * 由 BuildingManager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { BuildingManager } from "../logic";
import { ItemBundle } from "@excel/excel";
import { now } from "@utils/time";
import { Draft } from "mutative";
import { PlayerDataModel } from "@game/domain/playerdata";
import { BuildingData_OrderType, BuildingData_RoomType } from "@game/domain/playerdata";
import { headcountMoodRelief, isDispersedAp, warmupHoursOf, MAX_AP } from "@game/domain/building/mood";
import { getManufactFormula, getWorkshopFormula, getBuildingConstant, getRoomPhase, getGoldRate, getManufactPhase, getDormPhase, getFurnitureInfo, getRoomMaxLevel, getManufactFormulaType, getRoomElectricity, getMeetingPhase, getHirePhase, getClueExpiredDays, getMessageLeaveBoardConst } from "@excel/building_excel";
import {
  CharBuffSource,
  roomSpeedBonus,
  controlGlobalBonus,
  charMoodCost,
  getActiveCharBuffs,
  parseVupValue,
  phaseRank,
} from "@game/domain/building/buff";
import {
  isFormulaUnlocked,
  isDiamondStrategyUnlocked,
  FormulaUnlockCtx,
} from "@game/domain/building/unlocks";
import {
  goldOrderDistribution,
  pickGoldCount,
  warmupSkillTier,
  WARMUP_ALPHA_HOURS,
  WARMUP_BETA_HOURS,
  WarmupActive,
} from "@game/domain/building/trade-orders";

  /**
   * 内部方法：生成一笔贸易站金币订单（结构对齐官服 O_GOLD：delivery 3003 → gain GOLD）
   * 1~4 张贸易凭证 × 汇率 = 金币收益；订单 instId 由调用方保证递增连续。
   *
   * 特殊技能适配（独占订单，数据源 gamedata_const cc.tra.* 术语）：
   * - trade_ord_pepe（佩佩）：固定获取「特别独占订单」——所需赤金交付数为 0、收益恒定
   * - trade_ord_closure（可露希尔）：固定获取「可露希尔特别订单」——赤金交付 2、收益恒定
   */
export function _genTradingOrder(mgr: BuildingManager, draft: Draft<PlayerDataModel>, room: any, instId: number) : void {
    const rate = getGoldRate();
    // 定位该房间槽位 → 进驻干员的 TRADING 技能
    const slotId = Object.entries(draft.building.rooms.TRADING).find(
      ([, r]) => r === room,
    )?.[0];
    const slot = slotId ? draft.building.roomSlots[slotId] : null;
    const chars = mgr._roomCharSources(draft, slot ?? null);
    const hasBuff = (re: RegExp) =>
      chars.some((c) =>
        getActiveCharBuffs(c, "TRADING").some((b) => re.test(b?.buffId ?? "")),
      );
    // 开采协力（O_DIAMOND，官方 Lv3 策略）：源石碎片×2 交付 → 合成玉×20（2026-08-25 对齐）
    if ((room.strategy as string) === "O_DIAMOND") {
      room.stock.push({
        instId,
        delivery: [{ id: "3141", type: "MATERIAL", count: 2 }],
        type: "O_DIAMOND",
        gain: { id: "4003", type: "DIAMOND_SHD", count: 20 },
        buff: [],
      });
      return;
    }
    // 佩佩「特别独占订单」：赤金交付 0、收益恒定（rate×2）
    if (hasBuff(/^trade_ord_pepe/)) {
      room.stock.push({
        instId,
        delivery: [],
        type: "O_GOLD",
        gain: { id: "4001", type: "GOLD", count: rate * 2 },
        buff: [],
        special: "pepe",
      });
      return;
    }
    // 可露希尔「可露希尔特别订单」：赤金交付 2、收益恒定（rate×3）
    if (hasBuff(/^trade_ord_closure/)) {
      room.stock.push({
        instId,
        delivery: [{ id: "3003", type: "MATERIAL", count: 2 }],
        type: "O_GOLD",
        gain: { id: "4001", type: "GOLD", count: rate * 3 },
        buff: [],
        special: "closure",
      });
      return;
    }
    // 官方站级概率表（Lv1 2金100%；Lv2 60/40；Lv3 30/50/20）+ 暖机概率改写
    // （trade_ord_wt&cost α/β，累积工时达阈后生效，离岗清零）——替代原均匀随机 1~4
    const warmup = mgr._tradeWarmupActive(draft, slot);
    let count = pickGoldCount(goldOrderDistribution(slot?.level ?? 1, warmup));
    // 违约订单（官方）：trade_ord_law 将交付数 <4 的订单视为违约；
    // trade_ord_against 违约订单赤金交付额外 +1/+2（取最高档）
    let special: string | undefined;
    if (hasBuff(/^trade_ord_law/) && count < 4) {
      special = "breach";
      count += hasBuff(/^trade_ord_against\[01/) ? 2 : 1;
    }
    // 龙舌兰投资订单（官方）：非违约且交付数 >3 时龙门币收益 +250/+500（取最高档）
    let gainBonus = 0;
    if (!special && count > 3 && hasBuff(/^trade_ord_long/)) {
      gainBonus = hasBuff(/^trade_ord_long\[01/) ? 500 : 250;
    }
    room.stock.push({
      instId,
      delivery: [{ id: "3003", type: "MATERIAL", count }],
      type: "O_GOLD",
      gain: { id: "4001", type: "GOLD", count: count * rate + gainBonus },
      buff: [],
      ...(special ? { special } : {}),
    });
}

  /**
   * 内部方法：贸易站暖机技能激活统计（裁缝/手工艺品类订单概率改写）。
   * 干员持有 trade_ord_wt&cost α（[00x]）/β（[01x]）且累积工时（暖机基座 warmupSec）
   * 达阈（3h/5h）计为激活；离岗/换工位清零由 _accrueWarmup 保证。
   */
export function _tradeWarmupActive(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    slot: { charInstIds?: number[] } | null | undefined,) : WarmupActive {
    const active: WarmupActive = { alpha: 0, beta: 0 };
    for (const instId of slot?.charInstIds ?? []) {
      if (instId <= 0) continue;
      const src = mgr._charSource(draft, instId);
      if (!src) continue;
      const hours = warmupHoursOf(
        (draft.building.chars[String(instId)] as any)?.warmupSec,
      );
      let tier: "alpha" | "beta" | null = null;
      for (const b of getActiveCharBuffs(src, "TRADING")) {
        const t = warmupSkillTier(b?.buffId ?? "");
        // 同一干员同时持 α/β 时按高档（β）计（α+β 按 β）
        if (t === "beta") {
          tier = "beta";
          break;
        }
        if (t === "alpha") tier = "alpha";
      }
      if (tier === "beta" && hours >= WARMUP_BETA_HOURS) active.beta += 1;
      else if (tier === "alpha" && hours >= WARMUP_ALPHA_HOURS) active.alpha += 1;
    }
    return active;
}

  /**
   * 内部方法：贸易站订单时间推进（deltaTime 驱动）
   *
   * 官方模型（PlayerBuildingTradingNext）：next={order, processPoint, speed, maxPoint}，
   * processPoint 随时间按有效速度累积，达到 maxPoint 即生成一笔新订单并回退阈值。
   * 有效速度 = 存档 next.speed（基础订单效率）× (1 + 进驻干员 trade_* buff + 控制中枢
   * control_tra_* 全局)；回写 room.buff={speed, limit}（官方线格式，客户端倒计时显示）。
   *
   * 时间模型仅在存档已有订单进度（next.maxPoint > 0，官方迁移/时间累积过）时激活；
   * 旧存档无 next 数据 → 不惰性初始化（避免污染存档语义），交 _refreshTradingOrders
   * 静态补单兜底。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
export function _accrueTrading(mgr: BuildingManager, draft: Draft<PlayerDataModel>, ts: number) : void {
    const controlBonus = mgr._controlGlobalFor(draft).TRADING ?? 0;
    for (const [slotId, room] of Object.entries(
      draft.building.rooms.TRADING ?? {},
    )) {
      if (!room || room.state !== 1) continue;
      // 回写官方线格式 buff：speed=订单效率加成、limit=库存上限（任何工作时间贸易站）
      const slot = draft.building.roomSlots[slotId];
      const chars = mgr._roomCharSources(draft, slot);
      const bonus =
        roomSpeedBonus(chars, "TRADING", [], mgr._specialCtx(draft)) +
        controlBonus;
      const roomBuff = (room.buff as any) ?? {};
      roomBuff.speed = bonus;
      roomBuff.limit = room.stockLimit ?? 0;
      room.buff = roomBuff;
      // 旧存档无订单进度 → 静态补单兜底（本方法不推进）
      const next = room.next;
      if (!next || (next.maxPoint ?? 0) <= 0) continue;
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      // 修复（2026-08-26 dc-fix，生产速度过快）：存档 next.speed 已是有效速度（如 1.78 =
      // 1+0.78，maxPoint = 官方基础秒数，如 12600 = 3:30:00）——原实现
      // `next.speed = next.speed × (1+bonus)` 回写 → 加成每次 sync 复利滚雪球，订单越来越快。
      // 官方语义：速度 = 1 + 当前加成（每次按进驻干员重算，换班即时生效）。
      const effSpeed = Math.max(0.01, 1 + bonus);
      next.speed = effSpeed;
      next.processPoint = (next.processPoint ?? 0) + elapsed * effSpeed;
      // 达到阈值 → 逐笔生成订单（修复：while 一次性结算全部达到的订单——
      // 原 if 只生成 1 笔，长时间离线累积多笔时进度滞留、订单节奏失真）
      const limit = Math.max(1, room.stockLimit ?? 2);
      while (
        next.processPoint >= next.maxPoint &&
        Array.isArray(room.stock) &&
        room.stock.length < limit
      ) {
        const orderId = (next.order ?? -1) + 1;
        mgr._genTradingOrder(draft, room, orderId);
        next.order = orderId;
        next.processPoint -= next.maxPoint;
      }
    }
}

  /**
   * 内部方法：初始化贸易站补单守卫（_lastOrderFillTs）
   *
   * 修复（2026-08-25）：deliveryOrder/deliveryBatchOrder/accelerateOrder 结算清空
   * 库存后调用——若守卫从未初始化，下一次 sync 的 _refreshTradingOrders 会把该房间
   * 当"首次补单"立即补满到 stockLimit（已交付/已结算订单回退，改动被撤回，可无限
   * 刷金币/凭证）。记录结算时刻后，sync 补单走节流（间隔 ≥ _TRADE_FILL_INTERVAL 才
   * 补 1 单）。首次守卫由 _refreshTradingOrders 在"库存满"或"首次补单"时初始化，
   * 此处仅兜底"订单被消费但从未触发过补单"的房间。
   *
   * @param room - 贸易站房间对象（draft 内可变对象）
   */
export function _touchOrderFillGuard(mgr: BuildingManager, room: any) : void {
    if (!room) return;
    if ((room as any)._lastOrderFillTs == null) {
      (room as any)._lastOrderFillTs = now();
    }
}

  /**
   * 贸易站订单补充（静态兜底——旧存档无 next 时间累积的订单生成）
   *
   * 修复：服务端无订单生成逻辑——stock 由账号生成器静态填充，交付完即枯竭。
   * 简单机制：工作时间（state=1）且 stock 不足 stockLimit 时按 3003（贸易凭证）
   * × 汇率生成金币订单（结构与官服样本一致：delivery 3003 → gain GOLD）。
   *
   * 再修复：原实现恒补到 2 单（忽略 room.stockLimit）——贸易站升级/策略调整后
   * 库存上限形同虚设；现按 stockLimit 补单（缺省 2，防御 0/负数）。
   *
   * 防反复领取修复（2026-08-23）：原实现每次 sync 都无条件把 stock 补满到
   * stockLimit → 玩家 deliveryBatchOrder 清空库存后，紧接着 sync 又立即补满，
   * 可无限反复领取订单刷金币/凭证。现引入补单节流：
   * - 首次（房间尚无 `_lastOrderFillTs`）：当作守卫初始化，一次性补满到 stockLimit；
   * - 此后每次补单需距上次补单至少经过 `_TRADE_FILL_INTERVAL` 秒，且每次只补 1 单
   *   （订单随时间逐笔生成，贴近官方节奏），空缺不会再被瞬间回满。
   *
   * 时间模型已激活（next.maxPoint > 0）的房间跳过——订单由 _accrueTrading
   * 随时间逐笔生成，静态补单会破坏"订单获取效率"节奏。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒，用于补单节流判定）
   */
export function _refreshTradingOrders(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    ts: number,) : void {
    for (const slotId of Object.keys(draft.building.rooms.TRADING)) {
      const room = draft.building.rooms.TRADING[slotId];
      if (!room || room.state !== 1) continue;
      // 时间模型激活（next.maxPoint>0）→ 订单由 _accrueTrading 生成
      if (room.next?.maxPoint > 0) continue;
      if (!Array.isArray(room.stock)) room.stock = [];
      const target = Math.max(1, room.stockLimit ?? 2);
      if (room.stock.length >= target) {
        // 关键修复：库存已满（初始预置）也初始化补单守卫——否则结算清空后
        // 下一次 sync 会把本房间当"首次补单"立即补满 → 订单回退未结算状态。
        if ((room as any)._lastOrderFillTs == null) (room as any)._lastOrderFillTs = ts;
        continue;
      }
      // 补单节流：首次（守卫初始化）补满；此后需间隔 ≥ _TRADE_FILL_INTERVAL 才补 1 单
      const lastFill = (room as any)._lastOrderFillTs ?? 0;
      const isFirstFill = lastFill <= 0;
      if (!isFirstFill && ts - lastFill < mgr._TRADE_FILL_INTERVAL) continue;
      const missing = target - room.stock.length;
      const toFill = isFirstFill ? missing : 1;
      // instId 从现有库存最大值续增（保证递增连续）
      let maxInstId = room.stock.reduce((m, s) => Math.max(m, s?.instId ?? 0), 0);
      for (let i = 0; i < toFill; i++) {
        maxInstId += 1;
        mgr._genTradingOrder(draft, room, maxInstId);
      }
      // 记录本次补单时刻，用于下一次节流判定
      (room as any)._lastOrderFillTs = ts;
    }
}

  /**
   * 内部方法：结算单条订单（真实订单结构——扣 delivery 物品、加 gain 物品）
   * 例：delivery=[{3003×3}]、gain={4001(金币)×1500} → 扣 3003×3、加金币 1500
   */
export function _settleOrderInternal(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    stockItem: any,) : void {
    mgr._applyBundles(draft, stockItem?.delivery ?? [], -1);
    const gain = stockItem?.gain;
    if (gain) {
      if (gain.type === "GOLD") {
        mgr._applyGoldDelta(draft, gain.count ?? 0);
      } else {
        mgr._applyBundles(draft, [gain], 1);
      }
    }
}

  /**
   * 加速订单（立即结算指定订单——按 instId 查找）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
export async function accelerateOrder(mgr: BuildingManager, args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await mgr._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        const idx = room.stock.findIndex((s: any) => s.instId === orderId);
        if (idx !== -1) {
          mgr._settleOrderInternal(draft, room.stock[idx]);
          // 修复：splice 产生 DELETE patch（客户端删 stock 属性而非替换 → UI 残留）；
          // 用 filter 生成 replace patch（modified）
          room.stock = room.stock.filter((x: any) => x !== room.stock[idx]);
          // 修复（2026-08-25）：加速结算订单同样初始化补单守卫（同 deliveryOrder，
          // 防 sync 把已结算订单当"首次补单"立即补满 → 改动被撤回）
          mgr._touchOrderFillGuard(room);
          // 修复：AccelerateOrder 任务事件从未 emit → 加速订单类任务永不推进
          await mgr._trigger.emit("AccelerateOrder", []);
        }
      }
    });
}

  /**
   * 加速方案（制造站——立即完成当前生产方案 1 个）
   *
   * 修复（2026-08-14）：
   * 1. 原实现委托 settleSale 查 TRADING 房间，而客户端传的是制造站 slotId
   *    （抓包 {"slotId":"slot_15","cost":145}）→ 空 delta；改为按制造站槽位
   *    立即产出当前方案 1 个（受剩余目标限制）；
   * 2. 移除源石碎片（diamondShard）扣费——请求体 cost 为客户端本地消耗的
   *    「加速无人机」数量（客户端存档无服务端无人机计数字段），且设计文档明确
   *    「加速不消耗道具（私服友好）」；原实现把无人机数当源石碎片扣 → 玩家
   *    源石碎片被无故消耗（与 accelerateOrder 免费行为不一致，疑似 bug）。
   *
   * @param args - 包含 slotId（制造站槽位）和 cost（客户端无人机数，服务端不消耗）的参数对象
   */
export async function accelerateSolution(mgr: BuildingManager, args: { slotId: string; cost?: number }) {
    const { slotId, cost } = args;
    await mgr._player.update(async (draft) => {
      const room = draft.building.rooms.MANUFACTURE[args.slotId];
      // 无可加速方案（房间不存在/未开工/无配方）——不 500
      if (!room || !room.formulaId || room.state !== 1) return;
      const formula = getManufactFormula(String(room.formulaId));
      if (!formula) return;
      // 官方无人机语义（2026-08-25 对齐）：请求带 cost（客户端消耗的无人机数）时，
      // 1 架 = 3 分钟制造时间 → 按有效产能推进等价进度（持有量为客户端本地状态，
      // 官服存档无无人机字段，服务端不校验余额）
      if (typeof cost === "number" && Number.isInteger(cost) && cost > 0) {
        mgr._accrueManufacture(draft, slotId, now());
        if ((room.remainSolutionCnt ?? 0) <= 0) return; // 计划耗尽停摆，无可加速
        // 官方速率（2026-08-26 dc-fix）：1 点/秒 × (1+加成)——与 _accrueManufacture 同单位，
        // 1 架无人机 = 3 分钟制造时间 = 180 × (1+加成) 进度点（_roomCapacity 已回写 buff.speed）
        mgr._roomCapacity(draft, slotId, formula);
        const speedBonus = ((room.buff as any)?.speed as number) ?? 0;
        const costPoint = formula.costPoint ?? 0;
        if (costPoint <= 0) return;
        room.processPoint = (room.processPoint ?? 0) + cost * 180 * (1 + speedBonus);
        let produced = Math.floor(room.processPoint / costPoint);
        if (produced > 0) {
          produced = Math.min(produced, room.remainSolutionCnt ?? 0);
          room.processPoint -= produced * costPoint;
          room.remainSolutionCnt = (room.remainSolutionCnt ?? 0) - produced;
          room.outputSolutionCnt = (room.outputSolutionCnt ?? 0) + produced;
        }
        room.lastUpdateTime = now();
        return;
      }
      // 兼容旧客户端（cost 缺省）：立即完成当前生产方案 1 个（私服既有行为）
      if ((room.remainSolutionCnt ?? 0) > 0) room.remainSolutionCnt -= 1;
      room.outputSolutionCnt = (room.outputSolutionCnt ?? 0) + 1;
      room.processPoint = 0;
      room.lastUpdateTime = now();
      room.completeWorkTime = now();
    });
}

  /**
   * 完成订单（贸易站交付——结算首条库存订单，扣 delivery 加 gain）
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
export async function deliveryOrder(mgr: BuildingManager, args: { slotId: string; orderId: string | number }) {
    const { slotId, orderId } = args;
    let delivered = 0;
    await mgr._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (tradingRoom && Array.isArray(tradingRoom.stock)) {
        // 修复：按客户端指定 orderId（instId）结算，缺省回退队首——与 deliveryBatchOrder 一致
        const idx =
          orderId != null
            ? tradingRoom.stock.findIndex(
                (s: any) => String(s.instId) === String(orderId),
              )
            : 0;
        if (idx !== -1 && tradingRoom.stock[idx]) {
          mgr._settleOrderInternal(draft, tradingRoom.stock[idx]);
          // 修复：splice → DELETE patch 客户端残留 → filter 替换
          tradingRoom.stock = tradingRoom.stock.filter(
            (x: any) => x !== tradingRoom.stock[idx],
          );
          // 修复（2026-08-25）：结算订单后初始化补单守卫——否则下一次 sync 的
          // _refreshTradingOrders 把该房间当"首次补单"立即补满到 stockLimit（已交付
          // 订单又回来，改动被撤回，可无限刷金币/凭证）。记录结算时刻，sync 补单走
          // 节流（间隔 ≥ _TRADE_FILL_INTERVAL 才补 1 单）。
          mgr._touchOrderFillGuard(tradingRoom);
          delivered = 1;
        }
      }
    });
    // 修复：DeliveryOrder 任务事件从未 emit → 交付订单类任务永不推进
    if (delivered > 0) {
      await mgr._trigger.emit("DeliveryOrder", [{ count: delivered }]);
    }
}

  /**
   * 批量完成订单（对 orderId 数组中的每个订单按 instId 结算）
   * 兼容字段变体（CS BuildingDeliveryBatchOrderRequest.slotList 为主）：
   * slotList / slotIdList / roomSlotIdList / 单值 slotId / roomSlotId——
   * 客户端改造版可能发不同字段名导致 200 但不交付（空循环）。
   * @param args - 包含 slotList（或变体）的参数对象
   */
export async function deliveryBatchOrder(mgr: BuildingManager, args: {
    slotList?: string[];
    slotIdList?: string[];
    roomSlotIdList?: string[];
    slotId?: string;
    roomSlotId?: string;
  }) : Promise<{
    [slotId: string]: ItemBundle[];
  }> {
    // 修复：官方字段为 slotList（CS BuildingDeliveryBatchOrderRequest { slotList }，
    // 结算每个贸易站的全部库存订单）；原实现读 slotId/orderId → 客户端请求解构不到
    // → 空 delta。响应 delivered: { slotId: [收益物品] } 对齐 CS/抓包。
    const slotList =
      args.slotList ??
      args.slotIdList ??
      args.roomSlotIdList ??
      (args.slotId ? [args.slotId] : args.roomSlotId ? [args.roomSlotId] : []);
    const delivered: { [slotId: string]: ItemBundle[] } = {};
    let totalDelivered = 0;
    await mgr._player.update(async (draft) => {
      for (const slotId of slotList) {
        const room = draft.building.rooms.TRADING[slotId];
        if (!room || !Array.isArray(room.stock) || room.stock.length === 0) {
          delivered[slotId] = [];
          continue;
        }
        const gains: ItemBundle[] = [];
        // 倒序移除，避免索引错位
        for (let i = room.stock.length - 1; i >= 0; i--) {
          const stock = room.stock[i];
          const gain = stock?.gain;
          if (gain) {
            gains.push({ id: gain.id, type: gain.type, count: gain.count });
          }
          mgr._settleOrderInternal(draft, stock);
          // 修复：splice 产生 DELETE patch（客户端 UI 残留旧订单）→ filter 替换
          room.stock = room.stock.filter((x: any) => x !== stock);
          totalDelivered += 1;
        }
        // 修复（2026-08-25）：批量交付后初始化补单守卫——否则交付清空库存后，紧接的
        // sync 的 _refreshTradingOrders 把该房间当"首次补单"立即补满到 stockLimit
        // （订单回退、交付被撤回，可无限刷金币/凭证）。记录交付时刻，sync 补单走节流。
        if (totalDelivered > 0) mgr._touchOrderFillGuard(room);
        delivered[slotId] = gains;
      }
    });
    // 修复：DeliveryOrder 任务事件从未 emit → 批量交付同样不推进任务
    if (totalDelivered > 0) {
      await mgr._trigger.emit("DeliveryOrder", [{ count: totalDelivered }]);
    }
    return delivered;
}

  /**
   * 删除订单（按 instId）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
export async function deleteOrder(mgr: BuildingManager, args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await mgr._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        room.stock = room.stock.filter((s: any) => s.instId !== orderId);
      }
    });
}

  /**
   * 贸易站结算
   * 结算全部库存订单：扣贸易凭证 3003，按 count×500 兑换金币
   *
   * 修复：CS BuildingSettleSaleRequest 字段为 roomSlotIdList（数组）——
   * 原实现读单值 slotId → 客户端请求解构不到 → 空 delta；现兼容两种形态。
   *
   * @param args - 包含 slotId（或 roomSlotIdList）的参数对象
   */
export async function settleSale(mgr: BuildingManager, args: { slotId?: string; roomSlotIdList?: string[] }) {
    const list = args.roomSlotIdList?.length
      ? args.roomSlotIdList
      : args.slotId
        ? [args.slotId]
        : [];
    return await mgr._player.update(async (draft) => {
      for (const slotId of list) {
        const room = draft.building.rooms.TRADING[slotId];
        if (room && Array.isArray(room.stock)) {
          for (const item of room.stock) {
            mgr._settleOrderInternal(draft, item);
          }
          room.stock = [];
          room.lastUpdateTime = now();
        }
      }
    });
}

  /**
   * 更换贸易方案
   *
   * 修复：CS BuildingChangeShopRequest 字段为 roomSlotId/stockIndex/
   * targetFormulaId/solutionCount——原实现读 slotId/solution（客户端不发）
   * → 空 delta；现兼容两种形态：targetFormulaId→strategy（订单类型）、
   * solutionCount→stockLimit（库存上限）。
   *
   * @param args - 包含 slotId（或 roomSlotId）+ strategy/stockLimit（或 CS 字段）的参数对象
   */
export async function changeSaleSolution(mgr: BuildingManager, args: {
    slotId?: string;
    roomSlotId?: string;
    targetFormulaId?: string;
    solutionCount?: number;
    solution?: { strategy: string; stockLimit: number };
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    const strategy = args.solution?.strategy ?? args.targetFormulaId;
    const stockLimit = args.solution?.stockLimit ?? args.solutionCount;
    if (!slotId) return;
    return await mgr._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room) {
        // 官方：开采协力（O_DIAMOND）需贸易站等级达 tradingStrategyUnlockLevel（3），
        // 未达标时忽略策略变更（库存上限正常生效）
        const strategyLocked =
          strategy === "O_DIAMOND" &&
          !isDiamondStrategyUnlocked(draft.building.roomSlots[slotId]?.level ?? 0);
        if (strategy && !strategyLocked) {
          room.strategy = strategy as BuildingData_OrderType;
        }
        if (stockLimit != null) room.stockLimit = stockLimit;
      }
    });
}

  /**
   * 更改贸易站策略
   * 参考实现：更新对应贸易站房间的 strategy 字段
   * @param args - 包含 slotId 和 strategy 的参数对象
   */
export async function changeStrategy(mgr: BuildingManager, args: { slotId: string; strategy: string }) {
    const { slotId, strategy } = args;
    return await mgr._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (tradingRoom) {
        tradingRoom.strategy = strategy as BuildingData_OrderType;
      }
    });
}

  /**
   * 购买劳动力
   * 消耗源石（1 源石/次），增加 labor.value（+10/次，上限 maxValue）
   * 注：apToLaborRatio=2 是 AP→劳动力 比例（apToLaborUnlockLevel=4 解锁），buyLabor 用源石走官方固定 10 点——YAGNI 未接入
   * @param args - 包含 buyCount 的参数对象
   */
export async function buyLabor(mgr: BuildingManager, args: { buyCount: number }) {
    const { buyCount } = args;
    // 修复：负数 buyCount 绕过余额守卫（androidDiamond -= 负数 → 免费源石）；非法入参直接拒绝
    if (
      typeof buyCount !== "number" ||
      !Number.isInteger(buyCount) ||
      buyCount <= 0
    ) {
      return;
    }
    return await mgr._player.update(async (draft) => {
      const labor = draft.building.status.labor;
      // 官方 AP 兑换路径（2026-08-25 对齐）：控制中枢等级 ≥ apToLaborUnlockLevel(4)
      // 后用理智兑换劳动力，比例 apToLaborRatio(2)：1 AP → 2 劳动力（buyCount = 劳动力数）
      const ctlSlot = Object.values(draft.building.roomSlots).find(
        (s) => s.roomId === "CONTROL",
      );
      const unlockLevel = getBuildingConstant<number>("apToLaborUnlockLevel") ?? 4;
      const ratio = getBuildingConstant<number>("apToLaborRatio") ?? 2;
      if ((ctlSlot?.level ?? 0) >= unlockLevel && ratio > 0) {
        const apCost = Math.ceil(buyCount / ratio);
        if (((draft.status as any).ap ?? 0) < apCost) return;
        (draft.status as any).ap -= apCost;
        labor.value = Math.min(labor.value + buyCount, labor.maxValue);
        return;
      }
      // 私服兼容路径（中枢未达 4 级）：1 源石 → 10 劳动力（既有行为，文档记录）
      const cost = 1;
      if (draft.status.androidDiamond < cost * buyCount) return;
      draft.status.androidDiamond -= cost * buyCount;
      labor.value = Math.min(labor.value + 10 * buyCount, labor.maxValue);
    });
}
