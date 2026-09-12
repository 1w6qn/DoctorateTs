/**
 * 基建分区逻辑：建造与升级（房间建造/升级/降级/专精/装修等级与成本核算）
 *
 * 由 BuildingManager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { BuildingManager } from "../logic";
import excel from "@excel/excel";
import { now } from "@utils/time";
import config from "@core/config/index";
import { Draft } from "mutative";
import { PlayerDataModel } from "../../../kernel/playerdata";
import { BuildingData_OrderType, BuildingData_RoomType } from "../../../kernel/playerdata";
import {
  PlayerBuildingManufacture,
  PlayerBuildingManufactureBuff,
} from "../../../kernel/playerdata";
import { getSpecCond, SPEC_ASSIST_BASE_BONUS } from "../mastery";
import { getManufactFormula, getWorkshopFormula, getBuildingConstant, getRoomPhase, getGoldRate, getManufactPhase, getDormPhase, getFurnitureInfo, getRoomMaxLevel, getManufactFormulaType, getRoomElectricity, getMeetingPhase, getHirePhase, getClueExpiredDays, getMessageLeaveBoardConst, getRoomUnlockCondId, canRoomLevelDown, getRoomBasicSpeedBuff } from "@excel/building_excel";
import {
  CharBuffSource,
  roomSpeedBonus,
  controlGlobalBonus,
  charMoodCost,
  getActiveCharBuffs,
  parseVupValue,
  phaseRank,
} from "../buff";
import {
  isFormulaUnlocked,
  isDiamondStrategyUnlocked,
  FormulaUnlockCtx,
} from "../unlocks";
import type { BuildingWithExt, TraineeWithMaxPoint, TrainingRoom } from "./ext-types";
import type { UpgradeSpecializationRequest } from "../models";

/** 制造配方（`getManufactFormula` 返回类型；building_excel 未导出该类型别名，故取 ReturnType） */
type ManufactFormula = NonNullable<ReturnType<typeof getManufactFormula>>;

  /** 制造站基础容量（房间等级 phase.outputCapacity；缺数据回退房间存储值） */
export function _manufactBaseCapacity(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    roomSlotId: string,
    room: PlayerBuildingManufacture | undefined,) : number {
    const slot = draft.building.roomSlots[roomSlotId];
    const phase = getManufactPhase(slot?.level ?? 1);
    return phase?.outputCapacity ?? room?.capacity ?? 0;
}

  /**
   * 制造站有效容量（基础容量 × (1 + 干员技能加成 + 控制中枢全局加成)）。
   * 官方线格式约定：room.capacity = 基础容量（相位 outputCapacity），buff.speed = 加成系数
   * ——服务端生产按有效容量随时间累积，并回写 buff.speed 供客户端计时显示一致。
   */
export function _roomCapacity(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    roomSlotId: string,
    formula: ManufactFormula | undefined,) : number {
    const slot = draft.building.roomSlots[roomSlotId];
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    const base = mgr._manufactBaseCapacity(draft, roomSlotId, room);
    const chars = mgr._roomCharSources(draft, slot);
    // targets 过滤：buff.targets 非空时仅对配方类型（F_GOLD/F_EXP/…）生效
    const targets = formula?.formulaType ? [formula.formulaType] : [];
    // 修复（2026-09-09，B2）：补「每名在岗干员 +1%」基础效率（manufactData.basicSpeedBuff）——
    // 原实现只叠加技能与中枢全局加成，该字段全仓未被读 → 产出与倒计时低 1~3%
    const stationed = (slot?.charInstIds ?? []).filter((i) => i > 0).length;
    const bonus =
      roomSpeedBonus(chars, "MANUFACTURE", targets, mgr._specialCtx(draft)) +
      (mgr._controlGlobalFor(draft).MANUFACTURE ?? 0) +
      getRoomBasicSpeedBuff("MANUFACTURE") * stationed;
    if (room) {
      room.capacity = base;
      const roomBuff = (room.buff ?? {}) as PlayerBuildingManufactureBuff;
      roomBuff.speed = bonus;
      room.buff = roomBuff;
    }
    return Math.max(1, Math.round(base * (1 + bonus)));
}

  /**
   * 建造房间（Excel 驱动——按 rooms[roomId].phases[1].buildCost 扣材料/劳动力）
   *
   * 修复：
   * 1. 建造前校验资源足额——原实现直接扣减，材料/金币不足时库存扣成负数；
   * 2. 建造后确保 rooms[roomId][slotId] 房间对象存在——原实现只改 slot，
   *    客户端按 roomId 查房间对象为空 → 房间"看不见"；
   * 3. 建造完成时间按 buildCost.time 推进（原实现恒 now()+1）。
   *
   * @param args - 包含 roomSlotId 和 roomId 的参数对象
   */
export async function buildRoom(mgr: BuildingManager, args: { roomSlotId: string; roomId: string }) {
    const { roomSlotId, roomId } = args;
    await mgr._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      // 建造 = 1 级相位 buildCost（材料/金币/劳动力）
      const phase = getRoomPhase(roomId, 1);
      if (!phase) return; // 房间类型未知——容错跳过
      // 修复（2026-09-09，B8）：建造前置校验（unlockCondId → roomUnlockConds，如制造站需发电站 Lv1）
      if (!mgr._roomUnlockSatisfied(draft, getRoomUnlockCondId(roomId, 1))) return;
      // 修复：资源足额校验——不足时拒绝建造（避免负库存/负金币）
      if (!mgr._canAfford(draft, phase.buildCost)) return;
      // 电力校验：新房间耗电（或换建时替换原房间耗电）后余额不得为负——
      // 官方行为：电力不足无法建造/升级，需先升级发电站
      const oldElec = slot.roomId ? getRoomElectricity(slot.roomId, slot.level ?? 1) : 0;
      const newElec = getRoomElectricity(roomId, 1);
      if (mgr._powerBalance(draft) - oldElec + newElec < 0) return;
      mgr._applyBuildCost(draft, phase.buildCost);
      slot.state = 1; // 建造中（completeUpgradeRoom 完成后置 2）
      slot.roomId = roomId as BuildingData_RoomType;
      slot.level = 1;
      // 曾达等级记录（配方解锁判定：官方以“曾达等级”解锁制造/加工配方）
      mgr._touchMaxLevel(draft, roomId, 1);
      const buildTime = phase.buildCost?.time ?? 0;
      slot.completeConstructTime = now() + Math.max(1, buildTime);
      // 修复：确保 rooms[roomId][slotId] 房间对象存在（客户端按类型查房间）
      const roomsByType = draft.building.rooms[roomId as keyof PlayerDataModel["building"]["rooms"]];
      if (roomsByType && !roomsByType[roomSlotId]) {
        (roomsByType as Record<string, { state?: number }>)[roomSlotId] = { state: 1 };
      }
    });
    // 修复：HasRoom 任务事件从未 emit → 拥有房间类任务永不推进
    const roomCount = Object.values(
      mgr._player._playerdata.building.roomSlots,
    ).filter((s) => s.roomId).length;
    await mgr._trigger.emit("HasRoom", [{ roomCount }]);
}

  /** 内部方法：建造/升级资源足额校验（items 含 GOLD 按 status.gold、MATERIAL 按 inventory；labor 按劳动力） */
export function _canAfford(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    buildCost?: {
      items?: { id: string; count: number; type: string }[];
      time?: number;
      labor?: number;
    },) : boolean {
    for (const item of buildCost?.items ?? []) {
      const have =
        item.type === "GOLD"
          ? draft.status.gold
          : draft.inventory[item.id] || 0;
      if (have < (item.count ?? 0)) return false;
    }
    if (buildCost?.labor) {
      if (draft.building.status.labor.value < buildCost.labor) return false;
    }
    return true;
}

  /**
   * 配方解锁判定上下文：曾达等级（服务端扩展字段）+ 当前房间数 + 关卡星数。
   * 官方以“曾达等级”解锁制造/加工配方（解锁后任意等级房间可用）；官服存档无该字段，
   * 服务端自建 building.maxLevelReached（降级不回退，旧存档惰性初始化）。
   * 修复（2026-08-26 dc-fix）：旧存档无 maxLevelReached 记录时曾达等级恒 0 →
   * 全部配方被判未解锁（制造站无法补货/换配方）；当前房间等级本身即“曾达”
   * （lv3 制造站必然曾达 3 级），取两者最大值。
   */
export function _unlockCtx(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : FormulaUnlockCtx {
    const roomCountByType: Record<string, number> = {};
    const currentMaxLevel: Record<string, number> = {};
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (!slot?.roomId || (slot.level ?? 0) < 1) continue;
      roomCountByType[slot.roomId] = (roomCountByType[slot.roomId] ?? 0) + 1;
      currentMaxLevel[slot.roomId] = Math.max(
        currentMaxLevel[slot.roomId] ?? 0,
        slot.level ?? 0,
      );
    }
    const stageState: Record<string, number> = {};
    for (const [stageId, st] of Object.entries(draft.dungeon?.stages ?? {})) {
      stageState[stageId] = st?.state ?? 0;
    }
    const building = draft.building as BuildingWithExt;
    const recorded: Record<string, number> = building.maxLevelReached ?? {};
    const maxLevelReached: Record<string, number> = {};
    for (const roomId of new Set([
      ...Object.keys(recorded),
      ...Object.keys(currentMaxLevel),
    ])) {
      maxLevelReached[roomId] = Math.max(
        recorded[roomId] ?? 0,
        currentMaxLevel[roomId] ?? 0,
      );
    }
    return { maxLevelReached, roomCountByType, stageState };
}

  /**
 * 房间解锁条件判定（`roomUnlockConds[condId].number[*] = { type, level, count }`）
 *
 * 官方：每个房间相位带 `unlockCondId`；条件要求「指定类型房间达到指定等级、且数量 ≥ count」，
 * `type === "FUNCTIONAL"` 表示「功能房间（不含电梯/走廊）达到指定等级的数量」。
 * 无配置/空条件视为满足（数据版本缺表时不阻塞）。
 * @param mgr - 基建管理器
 * @param draft - 可写草稿
 * @param condId - 条件 id（可为 undefined）
 * @returns 是否满足
 */
export function _roomUnlockSatisfied(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    condId: string | undefined,) : boolean {
    if (!condId) return true;
    const cond = excel.BuildingData?.roomUnlockConds?.[condId];
    const numbers = Object.values(cond?.number ?? {});
    if (!numbers.length) return true;
    const slots = Object.values(draft.building.roomSlots ?? {});
    const maxLevelByType: Record<string, number> = {};
    for (const slot of slots) {
      if (!slot?.roomId) continue;
      maxLevelByType[slot.roomId] = Math.max(maxLevelByType[slot.roomId] ?? 0, slot.level ?? 1);
    }
    for (const n of numbers) {
      const type = String(n?.type ?? "");
      const needLevel = Number(n?.level ?? 0);
      const needCount = Number(n?.count ?? 0);
      if (type === "FUNCTIONAL") {
        const count = slots.filter(
          (s) => s?.roomId && s.roomId !== "CORRIDOR" && s.roomId !== "ELEVATOR" &&
            (s.level ?? 1) >= needLevel,
        ).length;
        if (count < needCount) return false;
        continue;
      }
      if ((maxLevelByType[type] ?? 0) < needLevel) return false;
    }
    return true;
}

/** 记录房间类型曾达最高等级（建造/升级时取 max，降级不回退） */
export function _touchMaxLevel(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    roomId: string,
    level: number,) : void {
    const building = draft.building as BuildingWithExt;
    const reached = (building.maxLevelReached ??= {});
    if ((reached[roomId] ?? 0) < level) reached[roomId] = level;
}

  /** 材料/金币列表足额校验（专精材料等通用成本） */
export function _canAffordCosts(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    costs: { id: string; count: number; type: string }[],) : boolean {
    for (const c of costs ?? []) {
      if ((c.count ?? 0) <= 0) continue;
      const have =
        c.type === "GOLD" ? draft.status.gold : draft.inventory[c.id] || 0;
      if (have < c.count) return false;
    }
    return true;
}

  /** 扣减材料/金币列表（足额校验后调用） */
export function _applyCosts(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    costs: { id: string; count: number; type: string }[],) : void {
    for (const c of costs ?? []) {
      if ((c.count ?? 0) <= 0) continue;
      if (c.type === "GOLD") mgr._applyGoldDelta(draft, -c.count);
      else mgr._applyItemDelta(draft, c.id, -c.count);
    }
}

  /**
   * 内部方法：当前电力余额（发电站供给 − 全部房间消耗，按相位 electricity 求和）。
   * POWER 房间相位为正向（+60/+130/+270 发电），其余房间为负向（-10/-30/… 消耗）。
   * 模板存档为满配布局，余额恰为 0——新建筑/升级需先升级发电站（官方行为）。
   */
export function _powerBalance(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : number {
    let balance = 0;
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (!slot?.roomId) continue;
      balance += getRoomElectricity(slot.roomId, slot.level ?? 1);
    }
    return balance;
}

  /**
   * 升级房间等级（Excel 驱动——按目标等级相位 buildCost 扣资源）
   *
   * 修复：目标等级越界（超过 phases 上限）时按最高可用等级钳制——
   * 原实现相位不存在时静默跳过（客户端升级按钮无反馈）。
   *
   * @param args - 包含 roomSlotId 和 targetLevel 的参数对象
   */
export async function upgradeRoom(mgr: BuildingManager, args: { roomSlotId: string; targetLevel: number }) {
    const { roomSlotId, targetLevel } = args;
    return await mgr._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      const maxLevel = getRoomMaxLevel(slot.roomId);
      const target = Math.max(1, Math.min(targetLevel || 1, maxLevel || 1));
      if (target <= (slot.level ?? 1)) return; // 无升级空间
      const phase = getRoomPhase(slot.roomId, target);
      if (!phase) return; // 相位不存在——容错跳过
      // 修复（2026-09-09，B8）：升级前置校验——官方每级相位带 unlockCondId
      //（如制造站 Lv2/Lv3 需中枢 Lv3/Lv4、贸易站 Lv2 需中枢 Lv3），原实现只看材料/劳动力/电力，
      // 可绕过中枢等级门槛直接升满
      if (!mgr._roomUnlockSatisfied(draft, getRoomUnlockCondId(slot.roomId, target))) return;
      // 修复：升级前资源足额校验——不足时拒绝（避免负库存）
      if (!mgr._canAfford(draft, phase.buildCost)) return;
      // 电力校验：升级后耗电增量不得使余额为负（如发电站升级供给更多电力）
      const oldElec = getRoomElectricity(slot.roomId, slot.level ?? 1);
      const newElec = getRoomElectricity(slot.roomId, target);
      if (mgr._powerBalance(draft) - oldElec + newElec < 0) return;
      mgr._applyBuildCost(draft, phase.buildCost);
      slot.level = target;
      slot.state = 1; // 升级中（completeUpgradeRoom 完成后置 2，客户端进度一致）
      // 曾达等级记录（降级不回退）
      mgr._touchMaxLevel(draft, slot.roomId, target);
    });
}

  /**
   * 完成房间建造/升级
   *
   * 修复：原实现只刷新 event.building——buildRoom 置 state=1（建造中）后
   * 永远无法完成 → 客户端"建造中"房间卡死。现扫描全部槽位，将
   * state=1 且 completeConstructTime 已到的房间置为 state=2（已完成）。
   */
export async function completeUpgradeRoom(mgr: BuildingManager) {
    return await mgr._player.update(async (draft) => {
      const ts = now();
      for (const slot of Object.values(draft.building.roomSlots)) {
        if (slot.state === 1 && slot.completeConstructTime <= ts) {
          slot.state = 2;
        }
      }
      draft.event.building = mgr._nextDailyBoundary(now());
    });
}

  /**
   * 降级房间
   *
   * 修复：等级下界钳制（原实现可降到 0 → 客户端房间等级非法）。
   * 简化实现：不返还建造材料。
   *
   * @param args - 包含 roomSlotId 的参数对象
   */
export async function degradeRoom(mgr: BuildingManager, args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await mgr._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot?.roomId || (slot.level ?? 1) <= 1) return;
      // 修复（2026-09-09，B8）：① 不可降级房间（rooms[roomId].canLevelDown === false：
      // 控制中枢/加工站/办公室/训练室/会客室）原实现只判 level > 1，可把中枢降级；
      // ② 发电站降级减少供电，须保证电力余额不为负（否则其他房间全部失电）
      if (!canRoomLevelDown(slot.roomId)) return;
      const oldElec = getRoomElectricity(slot.roomId, slot.level ?? 1);
      const newElec = getRoomElectricity(slot.roomId, Math.max(1, (slot.level ?? 1) - 1));
      // 仅当降级会**减少供电**（发电站：electricity 为正值）时才要求电力余额不为负；
      // 耗电房间降级只会省电（newElec > oldElec），不应被已有的负余额卡住
      if (newElec < oldElec && mgr._powerBalance(draft) - oldElec + newElec < 0) return;
      slot.level -= 1;
      slot.state = 2;
    });
}

  /** 内部方法：应用建造/升级消耗（items 扣 inventory/金币、labor 扣劳动力） */
export function _applyBuildCost(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number },) : void {
    for (const item of buildCost?.items ?? []) {
      if (item.type === "GOLD") {
        mgr._applyGoldDelta(draft, -item.count);
      } else {
        mgr._applyItemDelta(draft, item.id, -item.count);
      }
    }
    if (buildCost?.labor) {
      draft.building.status.labor.value = Math.max(
        draft.building.status.labor.value - buildCost.labor,
        0,
      );
    }
}

  /**
   * 内部方法：库存物品数量增减——building 订单/制造/加工结算的统一直写收敛点。
   * 语义与原各处内联字面量完全一致：draft.inventory[itemId] = (draft.inventory[itemId] || 0) + delta，
   * 缺省键按 0 起算（?? 0）；delta 允许为负（扣料、部分结算回退），不做任何钳制。
   *
   * ⚠️ 已知缺口：本方法直接改写 draft.inventory，绕过 InventoryManager.gainItem 的
   * items:get 事件通道——制造/加工/订单产出不推进 TotalSimpleTokenCount、ActivityCoinGain
   * 等勋章任务事件。本次仅为结构收敛（不新增事件发射，行为保持不变）；迁移方案见
   * docs/重复实现审查-整合清单.md §一。
   */
export function _applyItemDelta(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    itemId: string,
    delta: number,) : void {
    draft.inventory[itemId] = (draft.inventory[itemId] || 0) + delta;
    // 修复（2026-09-09，B12）：**产出**（正增量）登记到待派发队列，由各入口在
    // update 完成后经 _flushGainEvents 补发 items:get 同口径的追踪事件
    // （TotalSimpleTokenCount / GotItemBeforeTime / ActivityCoinGain）——
    // 原实现完全绕过事件通道，制造/加工/订单产出不推进勋章与任务。
    // 扣料（负增量）不登记。
    if (delta > 0 && itemId) {
      mgr._pendingGainEvents.push({ id: itemId, count: delta });
    }
}

  /**
   * 内部方法：批量库存增减——bundle 形态 { id, count? }，count 缺省按 1
   * （与订单 delivery/gain 的 `?? 1` 缺省语义一致）；sign=+1 入账 / -1 扣料。
   *
   * ⚠️ 同 _applyItemDelta：绕过 items:get 是已知缺口（勋章/任务不推进），
   * 迁移方案见 docs/重复实现审查-整合清单.md §一。
   */
export function _applyBundles(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    bundles: { id?: string; count?: number }[] | null | undefined,
    sign: 1 | -1,) : void {
    for (const b of bundles ?? []) {
      // b.id 类型上可缺省（成本/订单数据形如 { id?, count? }）；原实现即直接以该键写
      // inventory——非空断言仅为通过类型检查，运行时行为与原字面量写法一致
      mgr._applyItemDelta(draft, b.id!, sign * (b.count ?? 1));
    }
}

  /**
   * 内部方法：金币数量增减——building 订单/制造/加工结算的统一金币直写收敛点。
   * 语义与原内联 `draft.status.gold -= x` / `+= x` 完全一致（等价于 gold += ±x，
   * 无下限钳制，允许负值）。
   *
   * ⚠️ 已知缺口：同样绕过 InventoryManager.gainItem 的 items:get 类型分发（GOLD
   * 分支），勋章/任务事件不推进；迁移方案见 docs/重复实现审查-整合清单.md §一。
   */
export function _applyGoldDelta(mgr: BuildingManager, draft: Draft<PlayerDataModel>, delta: number) : void {
    draft.status.gold += delta;
}

  /**
   * 专精升级（开始训练）
   * 记录训练目标到训练室 trainee（官方 CS 枚举：TRAINING=1/OUTOFDATE=2/WAITING=3/EMPTY=0），
   * 将目标技能置为专精中（state=1），完成时由 completeUpgradeSpecialization 提升等级。
   *
   * 当 config.developer.specializationTimeZero=true 时，跳过训练等待——立即完成升级
   * （specializeLevel 直接 +1、技能复位、trainee 复位 WAITING），并照常发出
   * UpgradeSpecialization 任务事件。
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
export async function upgradeSpecialization(mgr: BuildingManager, args: {
    charInstId: number;
    targetSkill: number;
    /** 客户端发送但服务端不读（CS UpdateSpecializationRequest 无该字段） */
    reduceTimeBd?: UpgradeSpecializationRequest["reduceTimeBd"];
  }) {
    const { charInstId, targetSkill } = args;
    // 专精时间强制为 0：门控与扣费照常执行，仅跳过训练等待直接结算
    const instant = Boolean(config.developer?.specializationTimeZero);
    let settledLevel = 0;
    await mgr._player.update(async (draft) => {
      const char = draft.troop.chars[String(charInstId)];
      if (!(char && char.skills && char.skills[targetSkill])) return;
      const skill = char.skills[targetSkill];
      // 修复（2026-09-09）：即时完成分支此前**完全跳过门控与扣费**（直接 specializeLevel += 1），
      // 而 data/config.json 默认值即 specializationTimeZero=true → 调用 /building/upgradeSpecialization
      // 可白嫖专精、无视精二/技能 7 级要求，且 specializeLevel 能无限增长超过专三。
      // 门控与扣费现为两分支共用，即时完成只影响「是否等待 lvlUpTime」。
      if (skill.unlock !== 1) return; // 技能未解锁
      const targetLevel = (skill.specializeLevel ?? 0) + 1;
      // 官方门控：精英2 + 技能 7 级 + 专精≤3（训练室等级上限/槽位占用在下方校验）
      if (phaseRank(char.evolvePhase) < 2) return;
      if ((char.mainSkillLvl ?? 0) < 7) return;
      if (targetLevel > 3) return;
      if (instant && skill.state === 1 && (skill.completeUpgradeTime ?? -1) > 0) {
        // 该档材料已在训练发起时扣除（配置由「等待」切到「即时」的存档）——直接结算，不重复扣费
        skill.specializeLevel = targetLevel;
        skill.state = 0;
        skill.completeUpgradeTime = -1;
        settledLevel = targetLevel;
        resetTraineeWaiting(mgr, draft, charInstId);
        return;
      }
      const preCond = getSpecCond(char.charId, targetSkill, targetLevel);
      if (!preCond) return; // 该档位无专精配置
      // 档位自带的精英化前置（levelUpCostCond[].unlockCond.phase）
      if (phaseRank(char.evolvePhase) < preCond.phaseNeed) return;
      // 训练室定位：优先该干员已在训练的房间，其次首个空训练槽（按槽位遍历以取房间等级）
      const roomEntries = Object.entries(draft.building.rooms.TRAINING);
      const entry =
        roomEntries.find(([, r]) => r.trainee?.charInstId === charInstId) ??
        roomEntries.find(
          ([, r]) => !r.trainee || r.trainee.state === 0 || r.trainee.charInstId === -1,
        ) ??
        roomEntries[0];
      if (!entry) return;
      const [trainSlotId, roomRaw] = entry;
      const room = roomRaw as TrainingRoom;
      // 同时只能执行一个训练计划：他人训练中 → 拒绝（官方）
      const curTrainee = room.trainee;
      if (
        curTrainee &&
        curTrainee.charInstId > 0 &&
        curTrainee.charInstId !== charInstId &&
        curTrainee.state === 1
      ) {
        return;
      }
      // 专精等级上限 = 训练室等级（官方）
      const trainLevel = draft.building.roomSlots[trainSlotId]?.level ?? 3;
      if (targetLevel > trainLevel) return;
      // 消耗训练材料（足额校验后扣——官方专精需材料，2026-08-25 对齐）
      const cond = preCond;
      if (!mgr._canAffordCosts(draft, cond.costs)) return;
      mgr._applyCosts(draft, cond.costs);
      if (instant) {
        // 立即完成：技能直接到目标档，训练室 trainee 复位 WAITING
        skill.specializeLevel = targetLevel;
        skill.state = 0;
        skill.completeUpgradeTime = -1;
        settledLevel = targetLevel;
        resetTraineeWaiting(mgr, draft, charInstId);
        return;
      }
      skill.state = 1; // 专精中
      skill.completeUpgradeTime = now() + cond.lvlUpTime;
      if (room.trainee?.charInstId !== charInstId) {
        room.trainee = {
          charInstId,
          state: 1,
          targetSkill,
          processPoint: 0,
          // speed 同旧注释：官方基础速度 1（教官/协助加成在 _accrueTraining 实时合成）
          speed: 1,
        };
      } else {
        room.trainee.targetSkill = targetSkill;
        room.trainee.state = 1; // TRAINING
        room.trainee.processPoint = 0;
      }
      // 官方训练时长阈值（专一 8h/专二 16h/专三 24h = lvlUpTime）——
      // _accrueTraining 推进 processPoint 至 maxPoint 后置待领取（state=2）
      room.trainee.maxPoint = cond.lvlUpTime;
      room.trainer = room.trainer ?? { charInstId: -1, state: 0 };
      room.trainer.state = 1; // TRAINING
      room.lastUpdateTime = now();
    });
    // 任务事件（即时完成分支同样发出）
    if (settledLevel > 0) {
      await mgr._trigger.emit("UpgradeSpecialization", [
        { targetLevel: settledLevel },
      ]);
      // 修复（2026-09-09，审计 §5.3）：CharSkillSpecCount（技能精熟奖章 I–IX）无同名事件
      // 派发 → 9 枚恒不可得；与 UpgradeSpecialization 同点派发（载荷同形）
      await mgr._trigger.emit("CharSkillSpecCount", [
        { targetLevel: settledLevel },
      ]);
    }
}

  /**
   * 复位训练室 trainee/trainer 为 WAITING
   *
   * 官方线格式 trainee 恒为对象（state=3 WAITING、targetSkill=-1）；置 null 会让客户端读
   * trainee.charInstId 崩溃 → 存档破坏，故只在对象上改字段。
   * @param mgr - 基建管理器（与同文件其它导出函数签名一致）
   * @param draft - 当前草稿
   * @param charInstId - 待复位的干员
   */
export function resetTraineeWaiting(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    charInstId: number,) : void {
    const rooms = Object.values(draft.building.rooms.TRAINING);
    const room =
      rooms.find((r) => r?.trainee?.charInstId === charInstId) ?? rooms[0];
    if (!room?.trainee) return;
    room.trainee.state = 3; // WAITING
    room.trainee.targetSkill = -1;
    if (room.trainer) room.trainer.state = 3; // WAITING
    room.lastUpdateTime = now();
}

  /**
   * 完成专精升级（领取）
   * 提升目标技能 specializeLevel 并复位状态；trainee 复位为 WAITING（保留对象——官方
   * 线格式 trainee 恒为对象，置 null 会让客户端读 trainee.charInstId 崩溃 → 存档破坏）
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
export async function completeUpgradeSpecialization(mgr: BuildingManager, args: {
    charInstId?: number;
    targetSkill?: number;
  }) {
    let settledLevel = 0;
    await mgr._player.update(async (draft) => {
      // 客户端请求体为空（抓包 body={}）——从训练室 trainee 读取待结算对象
      let charInstId = args.charInstId;
      let targetSkill = args.targetSkill;
      const rooms = Object.values(draft.building.rooms.TRAINING);
      const room =
        (charInstId != null
          ? rooms.find((r) => r.trainee?.charInstId === charInstId)
          : undefined) ??
        rooms.find(
          (r) => r.trainee && r.trainee.charInstId > 0 && r.trainee.targetSkill >= 0,
        );
      if (charInstId == null) charInstId = room?.trainee?.charInstId;
      if (targetSkill == null) targetSkill = room?.trainee?.targetSkill;
      if (charInstId == null || targetSkill == null || targetSkill < 0) return;
      // 时长门控（新模型）：带 maxPoint 的 trainee 仅训练完成（state=2 待领取）可结算；
      // 旧存档无 maxPoint → 保持原行为（避免存量流程断裂）
      const traineeRec: TraineeWithMaxPoint | undefined = room?.trainee;
      if (traineeRec && (traineeRec.maxPoint ?? 0) > 0 && traineeRec.state !== 2) {
        return;
      }
      const char = draft.troop.chars[String(charInstId)];
      let settled = false;
      // 修复（2026-09-09）：结算此前无上限校验，可把 specializeLevel 抬到 3 以上（超专三）
      if ((char?.skills?.[targetSkill]?.specializeLevel ?? 0) >= 3) return;
      if (char && char.skills && char.skills[targetSkill]) {
        char.skills[targetSkill].specializeLevel += 1;
        settledLevel = char.skills[targetSkill].specializeLevel;
        char.skills[targetSkill].state = 0;
        char.skills[targetSkill].completeUpgradeTime = -1;
        settled = true;
      }
      // 仅结算成功时复位 trainee——targetSkill 越界/干员 skills 为空时保留训练进度，
      // 避免"专精未发放但训练被清空"的存档破坏（训练成果丢失）
      if (settled && room?.trainee?.charInstId === charInstId) {
        // 官方线格式 trainee 恒为对象（LocalArknight 参考：完成后 state=WAITING、
        // targetSkill=-1，干员保留待下一次专精；置 null 会让客户端读 trainee.charInstId
        // 崩溃 → 存档破坏）
        room.trainee.state = 3; // WAITING
        room.trainee.targetSkill = -1;
        if (room.trainer) room.trainer.state = 3; // WAITING
        room.lastUpdateTime = now();
      }
    });
    // 修复：UpgradeSpecialization 任务事件从未 emit（建筑训练室路径）→ 专精任务永不推进；
    // char.ts 的"Duplicated"直改路径会发，本路径（真实训练室结算）补齐
    if (settledLevel > 0) {
      await mgr._trigger.emit("UpgradeSpecialization", [
        { targetLevel: settledLevel },
      ]);
      // 修复（2026-09-09，审计 §5.3）：训练室结算路径同样计数技能精熟奖章（CharSkillSpecCount）
      await mgr._trigger.emit("CharSkillSpecCount", [
        { targetLevel: settledLevel },
      ]);
    }
}

  /**
   * 升级自定义等级
   * 简化实现：参考 Python 实现返回 202，预留接口
   */
export async function upgradeDiyLevel(mgr: BuildingManager) {
    return await mgr._player.update(async (draft) => {
      draft.event.building = mgr._nextDailyBoundary(now());
    });
}
