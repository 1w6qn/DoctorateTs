/**
 * 基建分区逻辑：干员进驻与心情（分配/休整/清洁/亲密/加成计算）
 *
 * 由 BuildingManager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { BuildingManager } from "../logic";
import { Draft } from "mutative";
import { PlayerDataModel } from "../../../kernel/playerdata";
import { headcountMoodRelief, isDispersedAp, warmupHoursOf, MAX_AP } from "../mood";
import { splitDormBuffs, sumByGroupMax } from "../dorm-special";
import {
  CharBuffSource,
  roomSpeedBonus,
  controlGlobalBonus,
  charMoodCost,
  getActiveCharBuffs,
  parseVupValue,
  phaseRank,
} from "../buff";

  /**
   * 设置私人宿舍归属
   *
   * 修复：
   * 1. CS 字段名为 charInsId（大 S），客户端发送 charInsId——
   *    原实现读 charInstId → undefined 写入 owners:[null] 破坏存档；
   * 2. 双端同步——原实现只写 room.owners：旧 owner 的 chars[].privateRooms
   *    残留旧宿舍、新 owner 若已在其他私人宿舍则两个宿舍同时挂 owner →
   *    客户端"干员已在其他私人宿舍"校验不一致。现同步清理旧 owner、迁移新 owner。
   *
   * @param args - 包含 slotId 和 charInstId 的参数对象
   */
export async function setPrivateDormOwner(mgr: BuildingManager, args: {
    slotId: string;
    charInstId?: number;
    charInsId?: number;
  }) {
    const { slotId } = args;
    // 修复：CS 字段名为 charInsId（大 S），客户端发送 charInsId——
    // 原实现读 charInstId → undefined 写入 owners:[null] 破坏存档
    const charInstId = args.charInstId ?? args.charInsId;
    if (charInstId == null) return;
    return await mgr._player.update(async (draft) => {
      const room = draft.building.rooms.PRIVATE[slotId];
      if (!room) return; // 防御：非法 slotId
      // 清理旧 owner：从该宿舍 owner 位置移除，并同步其 chars[].privateRooms
      for (const oldId of room.owners ?? []) {
        if (oldId > 0 && oldId !== charInstId) {
          const oldChar = draft.building.chars[String(oldId)];
          if (oldChar) {
            oldChar.privateRooms = (oldChar.privateRooms ?? []).filter(
              (r) => r !== slotId,
            );
          }
        }
      }
      // 若新 owner 此前在别的私人宿舍 → 移除旧归属（一干员一私人宿舍）
      const newChar = draft.building.chars[String(charInstId)];
      if (newChar) {
        for (const otherSlotId of newChar.privateRooms ?? []) {
          if (otherSlotId === slotId) continue;
          const otherRoom = draft.building.rooms.PRIVATE[otherSlotId];
          if (otherRoom) {
            otherRoom.owners = (otherRoom.owners ?? []).filter(
              (id) => id !== charInstId,
            );
          }
        }
        newChar.privateRooms = [
          ...(newChar.privateRooms ?? []).filter((r) => r !== slotId),
          slotId,
        ];
      }
      room.owners = [charInstId];
    });
}

  /**
   * 设置基建助战干员
   * @param args - 包含 type（位置）和 charInstId 的参数对象
   */
export async function setBuildingAssist(mgr: BuildingManager, args: { type: number; charInstId: number }) {
    const { type, charInstId } = args;
    await mgr._player.update(async (draft) => {
      if (draft.building.assist.includes(charInstId)) {
        const index = draft.building.assist.indexOf(charInstId);
        draft.building.assist[index] = -1;
      }
      draft.building.assist[type] = charInstId;
    });
    // 修复：SetBuildingAssist 任务事件从未 emit → 设置基建助手类任务永不推进
    await mgr._trigger.emit("SetBuildingAssist", []);
}

  /** 查找干员所在房间槽位 ID */
export function _findRoomSlotIdByChar(mgr: BuildingManager, charInstId: number) : string | undefined {
    const slots = mgr._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      if (slots[slotId].charInstIds.includes(charInstId)) {
        return slotId;
      }
    }
    return undefined;
}

  /** 从所有房间槽位中移除指定干员（置为 -1） */
export function _clearCharFromRooms(mgr: BuildingManager, charInstIdList: number[]) : void {
    const slots = mgr._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      const ids = slots[slotId].charInstIds;
      for (let i = 0; i < ids.length; i++) {
        if (charInstIdList.includes(ids[i])) {
          ids[i] = -1;
        }
      }
    }
}

  /** 干员 buff 激活所需信息（charId/level/evolvePhase/ap），缺失返回 null */
export function _charSource(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    instId: number,) : CharBuffSource | null {
    const char = draft.troop?.chars?.[String(instId)];
    if (!char?.charId) return null;
    return {
      charId: char.charId,
      level: char.level ?? 0,
      evolvePhase: char.evolvePhase ?? 0,
      // 心情（raw AP）供涣散判定——缺失视为满心情（未建档干员）
      ap: (draft.building.chars as any)?.[String(instId)]?.ap,
    };
}

  /** 指定房间进驻干员的 buff 源列表（过滤无效干员） */
export function _roomCharSources(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    slot: { charInstIds?: number[] } | null | undefined,) : CharBuffSource[] {
    return (slot?.charInstIds ?? [])
      .filter((i) => i > 0)
      .map((i) => mgr._charSource(draft, i))
      .filter((c): c is CharBuffSource => c != null);
}

  /** 控制中枢进驻干员的全局 buff（按目标房间类型，乘法系数） */
export function _controlGlobalFor(mgr: BuildingManager, draft: Draft<PlayerDataModel>,) : Record<string, number> {
    const ctlSlot = Object.values(draft.building.roomSlots).find(
      (s) => s.roomId === "CONTROL",
    );
    return controlGlobalBonus(
      mgr._roomCharSources(draft, ctlSlot ?? null),
      mgr._specialCtx(draft),
    );
}

  /**
   * 特殊技能上下文：各房间进驻干员 charId（按房间类型分组）。
   * 供 fraction/token 条件技能判定（"每个进驻制造站的X干员"→ manufactureCharIds、
   * "≥N台作业平台进驻发电站"→ powerCharIds、"与X同驻控制中枢"→ controlCharIds）。
   */
export function _specialCtx(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : any {
    const byRoom: Record<string, string[]> = {};
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (!slot?.roomId) continue;
      const ids = (slot.charInstIds ?? [])
        .filter((i) => i > 0)
        .map((i) => mgr._charSource(draft, i)?.charId)
        .filter((c): c is string => c != null);
      (byRoom[slot.roomId] ??= []).push(...ids);
    }
    return {
      roomCharIds: byRoom.MANUFACTURE ?? [],
      manufactureCharIds: byRoom.MANUFACTURE ?? [],
      tradingCharIds: byRoom.TRADING ?? [],
      dormCharIds: byRoom.DORMITORY ?? [],
      powerCharIds: byRoom.POWER ?? [],
      controlCharIds: byRoom.CONTROL ?? [],
    };
}

  /**
   * 宿舍基础恢复（点/小时，官方公式 2026-08-25 对齐，宿舍页）：
   * (1.5 + 0.1×等级) + 氛围×0.0004（技能部分按作用域在 _recomputeCharScales 分发）。
   */
export function _dormBaseRecoveryPerHour(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    slotId: string,) : number {
    const slot = draft.building.roomSlots[slotId];
    const room = draft.building.rooms.DORMITORY?.[slotId];
    const level = slot?.level ?? 1;
    const comfort = (room as any)?.comfort ?? 0;
    return 1.5 + 0.1 * level + comfort * 0.0004;
}

  /** 输出类房间基础心情消耗（AP/秒，真实存档校准：制造/贸易 -55、会客/人力/发电 -65） */
export function _workBaseScale(mgr: BuildingManager, roomType: string) : number {
    switch (roomType) {
      case "MANUFACTURE":
      case "TRADING":
      case "WORKSHOP":
        return -55;
      case "MEETING":
      case "HIRE":
      case "POWER":
        return -65;
      default:
        return 0; // CONTROL/TRAINING/其他不消耗
    }
}

  /**
   * 重算所有干员心情档位（changeScale）：
   * - 未进驻 → 0；宿舍 → 该宿舍恢复量；输出房间 → 基础消耗 - 技能附加消耗（charMoodCost）
   * 换班/休息后立即生效，随后 _accrueCharAp 按新档位随时间累积。
   */
export function _recomputeCharScales(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : void {
    const roomTypeOf = new Map<number, string>();
    // 干员 → 所在房间在岗人数（官方头数心情减免：制造/贸易 2人-0.05、3人-0.1 点/时）
    const headcountOf = new Map<number, number>();
    for (const slot of Object.values(draft.building.roomSlots)) {
      const stationed = (slot?.charInstIds ?? []).filter((i) => i > 0);
      for (const instId of stationed) {
        roomTypeOf.set(instId, slot.roomId);
        headcountOf.set(instId, stationed.length);
      }
    }
    // 宿舍恢复按宿舍房间 × 成员分别计算（官方 2026-08-25 对齐，宿舍页）：
    // 基础 (1.5+0.1×级) + 氛围×0.0004 + 控制中枢 dorm 全局为全员共享；技能按作用域分发：
    // all 全员（同种取最高）/ self 仅自身 / single 心情最低成员（除施放者）/
    // shared（小酌怡情）总量均分给心情未满成员；单位：1 点/时 = 100 AP/秒
    const dormScale = new Map<number, number>();
    for (const [slotId, slot] of Object.entries(draft.building.roomSlots)) {
      if (slot.roomId !== "DORMITORY") continue;
      const basePerHour = mgr._dormBaseRecoveryPerHour(draft, slotId);
      const controlPerHour = mgr._controlGlobalFor(draft).DORMITORY ?? 0;
      const members = (slot.charInstIds ?? []).filter((i) => i > 0);
      const allEntries: { group: string; value: number }[] = [];
      const sharedEntries: { group: string; value: number }[] = [];
      const singleEntries: { group: string; value: number }[] = [];
      const selfOf = new Map<number, number>();
      const singleOwners = new Set<number>();
      for (const instId of members) {
        const src = mgr._charSource(draft, instId);
        if (!src) continue;
        // 宿舍为休息语境：涣散干员的宿舍技能仍生效（allowDispersed）
        const split = splitDormBuffs(
          getActiveCharBuffs(src, "DORMITORY", { allowDispersed: true }),
        );
        allEntries.push(...split.all);
        sharedEntries.push(...split.shared);
        if (split.single.length > 0) {
          singleEntries.push(...split.single);
          singleOwners.add(instId);
        }
        selfOf.set(instId, sumByGroupMax(split.self));
      }
      const allBonus = sumByGroupMax(allEntries);
      const singleBonus = sumByGroupMax(singleEntries);
      const sharedTotal = sumByGroupMax(sharedEntries);
      const apOf = (instId: number): number =>
        (draft.building.chars[String(instId)] as any)?.ap ?? MAX_AP;
      // 单体恢复目标：除施放者外心情最低成员（官方近似：锁定最低心情者）
      let singleTarget = -1;
      let lowestAp = Infinity;
      for (const instId of members) {
        if (singleOwners.has(instId)) continue;
        const ap = apOf(instId);
        if (ap < MAX_AP && ap < lowestAp) {
          lowestAp = ap;
          singleTarget = instId;
        }
      }
      const unfull = members.filter((i) => apOf(i) < MAX_AP);
      const sharedPer = unfull.length > 0 ? sharedTotal / unfull.length : 0;
      for (const instId of members) {
        let perHour =
          basePerHour + allBonus + controlPerHour + (selfOf.get(instId) ?? 0);
        if (instId === singleTarget) perHour += singleBonus;
        if (unfull.includes(instId)) perHour += sharedPer;
        dormScale.set(instId, Math.round(perHour * 100));
      }
    }
    for (const [instIdStr, ch] of Object.entries(draft.building.chars ?? {})) {
      const instId = Number(instIdStr);
      const roomType = roomTypeOf.get(instId);
      let scale: number;
      if (roomType === "DORMITORY") {
        scale = dormScale.get(instId) ?? 0;
      } else if (!roomType) {
        scale = 0;
      } else {
        scale = mgr._workBaseScale(roomType);
        const src = mgr._charSource(draft, instId);
        if (src) {
          scale -= charMoodCost(src, roomType);
          // 特殊技能适配（控制中枢心情类，数据源 buffId 前缀 + <@cc.kw> 关键词干员）：
          // - control_mp_cost_double（魔王）：与阿米娅同驻控制中枢时，自身和阿米娅心情恢复
          // - control_mp_cost_reset（若叶睦）：与丰川祥子同驻控制中枢时，消除自身心情消耗
          if (roomType === "CONTROL") {
            const active = getActiveCharBuffs(src, "CONTROL");
            const ctlChars = mgr._roomCharSources(draft, mgr._controlSlot(draft));
            if (ctlChars.some((c) => c.charId === "char_002_amiya")) {
              const dbl = active.find((b) => /^control_mp_cost_double/.test(b?.buffId ?? ""));
              if (dbl) {
                // 恢复档位：描述 vup（点/小时）× 100 → AP/秒
                const rec = parseVupValue(dbl?.description);
                if (rec != null) scale = rec * 100;
              }
            }
            if (ctlChars.some((c) => c.charId === "char_4182_oblvns")) {
              const reset = active.find((b) => /^control_mp_cost_reset/.test(b?.buffId ?? ""));
              if (reset) scale = 0; // 消除自身心情消耗
            }
          }
        }
        // 官方头数心情减免（制造/贸易）：2人 +0.05、3人 +0.1 点/时
        // （1 点/时 = 100 raw AP/秒，与 charMoodCost ×100 换算一致）
        if (roomType === "MANUFACTURE" || roomType === "TRADING") {
          scale += headcountMoodRelief(headcountOf.get(instId) ?? 1) * 100;
        }
      }
      if (ch.changeScale !== scale) {
        ch.changeScale = scale;
      }
    }
}

  /** 控制中枢槽位（特殊心情技能判定用） */
export function _controlSlot(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : { charInstIds?: number[] } | null {
    return (
      Object.values(draft.building.roomSlots).find((s) => s.roomId === "CONTROL") ?? null
    );
}

  /**
   * 分配干员到房间
   * 参考 Python AssignChar 实现：将干员从原房间移除并分配到目标房间
   * 对于训练室会特殊处理 trainer/trainee（修复：按房间类型定位训练室——
   * 原实现硬编码 slot_13，房间布局不同时训练室状态不同步）
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
export async function assignChar(mgr: BuildingManager, args: { roomSlotId: string; charInstIdList: number[] }) {
    const { roomSlotId, charInstIdList } = args;
    return await mgr._player.update(async (draft) => {
      // 训练锁（官方：训练开始后不可中止，训练位干员锁定至完成）：
      // 正在训练（trainee.state=1）的干员拒绝派往非训练室房间
      const targetRoomId = draft.building.roomSlots[roomSlotId]?.roomId;
      if (targetRoomId !== "TRAINING") {
        for (const tr of Object.values(draft.building.rooms.TRAINING ?? {})) {
          const t = (tr as any)?.trainee;
          if (
            t &&
            t.charInstId > 0 &&
            t.state === 1 &&
            charInstIdList.includes(t.charInstId)
          ) {
            return;
          }
        }
      }
      // 先将所有房间中已存在的相同干员移除（置为 -1）
      for (const slotKey in draft.building.roomSlots) {
        const slot = draft.building.roomSlots[slotKey];
        const ids = slot.charInstIds;
        for (let i = 0; i < ids.length; i++) {
          for (let n = 0; n < charInstIdList.length; n++) {
            if (charInstIdList[n] === ids[i]) {
              ids[i] = -1;
            }
          }
        }
      }
      // 将目标房间的干员列表替换为新列表
      draft.building.roomSlots[roomSlotId].charInstIds = charInstIdList;

      // 训练室特殊处理：按房间类型定位（不硬编码 slot_13）
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot?.roomId === "TRAINING" && charInstIdList.length >= 2) {
        const trainer = charInstIdList[0];
        const trainee = charInstIdList[1];
        const trainingRoom = draft.building.rooms.TRAINING[roomSlotId];
        if (trainingRoom) {
          trainingRoom.trainee = trainingRoom.trainee ?? {
            charInstId: -1, processPoint: 0, speed: 1, state: 0, targetSkill: -1,
          };
          trainingRoom.trainer = trainingRoom.trainer ?? { charInstId: -1, state: 0 };
          trainingRoom.trainee.charInstId = trainee;
          trainingRoom.trainee.targetSkill = -1;
          // speed 同 upgradeSpecialization：官方基础速度 1（空态/训练中 ≈1.x），
          // 非参考实现移植的 1000（否则 processPoint 秒涨 1000 → 训练进度异常）
          trainingRoom.trainee.speed = 1;
          trainingRoom.trainer.charInstId = trainer;
          trainingRoom.trainee.state = trainee === -1 ? 0 : 3;
          trainingRoom.trainer.state = trainer === -1 ? 0 : 3;
        }
      }
      // 换班后立即按新岗位重算心情档位（下次 sync 按新档位随时间累积）
      mgr._recomputeCharScales(draft);
    });
}

  /**
   * 批量更换工作干员
   * 将指定房间的干员列表替换为 charInstIdList，同时清空这些干员在其他房间的占用
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
  /**
   * 批量更换工作干员（客户端换班管理入口）
   *
   * 官方协议：CS BuildingBatchChangeWorkCharRequest 无字段（实测 body={}）——
   * 客户端实际换班走 assignChar（每房间一条，含清人 assignChar [-1]）。
   * 服务端兼容请求体字段名变体（roomSlotId/slotId、charInstIdList/charInstIds/list），
   * 携带数据时立即生效；空请求体按官方行为返回当前状态（不 500、不改分配）。
   * @param args - 请求体（roomSlotId/slotId + charInstIdList/charInstIds/list）
   */
  /**
   * 内部方法：从房间预设队列中选出「干员当前心情总和最高」的一组
   * （compare 心情 field = building.chars[].ap，值越大心情越充沛）。
   * 供 batchChangeWorkChar / useOnePresetQueue 自动换班为心情相对高的一组。
   * @param draft - Immer 草稿
   * @param slotId - 房间槽位 ID
   * @returns 目标预设干员组（不存在队列返回 null）
   */
export function _pickHighestApPreset(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    slotId: string,) : number[] | null {
    const queue = mgr._roomPresetQueue(draft, slotId);
    if (!queue || queue.length === 0) return null;
    // 心情总和最高的组；固定比较顺序保证平手时选中第一组（无心情数据按 0 计）
    let best: number[] | null = null;
    let bestAp = -1;
    for (const group of queue) {
      if (!Array.isArray(group)) continue;
      const ap = group.reduce<number>(
        (sum, id) =>
          id > 0 ? sum + (draft.building.chars[String(id)]?.ap ?? 0) : sum,
        0,
      );
      if (ap > bestAp) {
        bestAp = ap;
        best = group;
      }
    }
    return best;
}

export async function batchChangeWorkChar(mgr: BuildingManager, args: {
    roomSlotId?: string;
    slotId?: string;
    charInstIdList?: number[];
    charInstIds?: number[];
    list?: number[];
  }) {
    const roomSlotId = args.roomSlotId ?? args.slotId;
    const charInstIdList = args.charInstIdList ?? args.charInstIds ?? args.list;
    // 本次换班实际发生变化的干员数（对齐官服 buildingBatchChangeWorkChar pushMessage 的 num）
    let changedCount = 0;
    await mgr._player.update(async (draft) => {
      // 修复（2026-08-19）：官方 CS BuildingBatchChangeWorkCharRequest 无字段——
      // 客户端"换班"按钮发空体 {}。抓包实测空体不含 roomSlotId → 原实现
      // `if (!roomSlotId) return;` 直接短路返回空 delta → 客户端判定"换班无效"。
      // 修复（2026-08-23）：空体应视为"全局自动换班"——遍历所有设了预设队列的
      // 工作房间，逐个自动应用「中心情相对高（心情总和最高）」的一组；显式携带
      // roomSlotId/charInstIdList 时仍仅操作指定房间/排班（兼容旧行为）。
      const slots = roomSlotId
        ? [roomSlotId]
        : Object.keys(draft.building.roomSlots);
      let changed = false;
      for (const sid of slots) {
        const target = Array.isArray(charInstIdList)
          ? charInstIdList
          : mgr._pickHighestApPreset(draft, sid);
        // 空体全局模式：房间无预设队列则跳过（不影响其他房间）
        if (!target) continue;
        // 记录更换前排班，用于统计本次实际变化的干员数
        const before = draft.building.roomSlots[sid].charInstIds;
        // 清空这些干员在其他房间的占用
        for (const slotKey in draft.building.roomSlots) {
          if (slotKey === sid) continue;
          const ids = draft.building.roomSlots[slotKey].charInstIds;
          for (let i = 0; i < ids.length; i++) {
            if (target.includes(ids[i])) {
              ids[i] = -1;
            }
          }
        }
        const after: number[] = [...target];
        // 统计该房间槽位排班发生变化的干员数（新旧逐位比较，-1 与空视为等价）
        const len = Math.max(before.length, after.length);
        for (let i = 0; i < len; i++) {
          if ((before[i] ?? -1) !== (after[i] ?? -1)) changedCount++;
        }
        draft.building.roomSlots[sid].charInstIds = after;
        changed = true;
      }
      // 换班后立即按新岗位重算心情档位
      if (changed) mgr._recomputeCharScales(draft);
    });
    // 对齐官服：实际发生换班变更时下发 buildingBatchChangeWorkChar pushMessage（num=变化的干员数）
    if (changedCount > 0) {
      mgr._player.pushMessage("buildingBatchChangeWorkChar", { num: changedCount });
    }
}

  /**
   * 批量休息干员
   * 将指定干员从所有房间的工作位置移除（置为 -1），随后自动将
   * 「不在任何房间中且当前心情(ap)为 0」的干员安排入住宿舍空位（补宿舍回复）。
   * 官方 CS BuildingBatchChangeRestCharRequest 无字段（实际清人走 assignChar [-1]），
   * 服务端兼容 charInstIdList/charInstIds/list 字段名变体；空请求体不改分配。
   * @param args - 请求体（charInstIdList/charInstIds/list）
   */
export async function batchRestChar(mgr: BuildingManager, args: {
    charInstIdList?: number[];
    charInstIds?: number[];
    list?: number[];
  }) {
    const charInstIdList = args.charInstIdList ?? args.charInstIds ?? args.list;
    // 本次实际得到休息（移出岗位 + 入住宿舍）的干员数
    // 对齐官服 buildingBatchRestChar pushMessage 的 num
    let restedCount = 0;
    await mgr._player.update(async (draft) => {
      if (Array.isArray(charInstIdList)) {
        for (const slotKey in draft.building.roomSlots) {
          const ids = draft.building.roomSlots[slotKey].charInstIds;
          for (let i = 0; i < ids.length; i++) {
            if (charInstIdList.includes(ids[i])) {
              ids[i] = -1;
              restedCount++;
            }
          }
        }
      }
      // 自动把不在房间且心情告罄的干员安排进宿舍空位，并累计实际安置数
      restedCount += mgr._fillDormEmptySlots(draft);
      // 休息后立即恢复空闲心情档位（0）
      mgr._recomputeCharScales(draft);
    });
    // 对齐官服：实际发生休息变更时下发 buildingBatchRestChar pushMessage（num=休息的干员数）
    if (restedCount > 0) {
      mgr._player.pushMessage("buildingBatchRestChar", { num: restedCount });
    }
}

  /**
   * 内部方法：将「不在任何房间中且当前心情(ap)为 0」的干员安排入住宿舍空位。
   *
   * 宿舍空位判定（修复 2026-08-23）：
   * - 空床（charInstIds 中 ≤0 的槽位）；
   * - 以及「宿舍内心情已满（ap ≥ 上限 8640000）且所在宿舍未锁定（presetQueues[slotId].locked
   *   ≠ true）」的干员——这类干员已不需要继续驻宿回复，可腾出床位让给需要休息的干员。
   *   （锁定的宿舍视为不可变动，腾床不触及锁定房间。）
   * @returns 实际被安排入住宿舍的干员数
   */
export function _fillDormEmptySlots(mgr: BuildingManager, draft: Draft<PlayerDataModel>) : number {
    // 心情满值（与 _accrueCharAp 封顶一致）
    const MAX_AP = 8640000;
    // 收集已占用的干员（排除在任意房间工作中的）
    const occupied = new Set<number>();
    for (const slot of Object.values(draft.building.roomSlots)) {
      for (const id of slot?.charInstIds ?? []) {
        if (id && id > 0) occupied.add(id);
      }
    }
    // 需要入住的目标：不在任何房间 且 心情(ap) 为 0 的干员
    const candidates: number[] = [];
    for (const [instIdStr, ch] of Object.entries(draft.building.chars ?? {})) {
      const instId = Number(instIdStr);
      if (occupied.has(instId)) continue;
      if ((ch?.ap ?? 0) > 0) continue;
      candidates.push(instId);
    }
    if (candidates.length === 0) return 0;
    // 依次填补各宿舍槽位床位（先空床，后满心情未锁定干员的床位），先填床位数较多的宿舍
    const dormSlots = Object.entries(draft.building.roomSlots)
      .filter(([, slot]) => slot.roomId === "DORMITORY")
      .sort((a, b) => b[1].charInstIds.length - a[1].charInstIds.length);
    let c = 0;
    for (const [slotId, slot] of dormSlots) {
      const ids = slot.charInstIds;
      const meta = mgr._presetQueues(draft)[slotId] as
        | { locked?: boolean }
        | undefined;
      const locked = meta?.locked === true;
      for (let i = 0; i < ids.length && c < candidates.length; i++) {
        if (ids[i] <= 0) {
          // 空床：直接入住
          ids[i] = candidates[c++];
          continue;
        }
        // 满心情且未锁定宿舍的干员 → 视为可腾出床位（让位给需休息干员）
        if (locked) continue;
        const ch = draft.building.chars[String(ids[i])];
        if ((ch?.ap ?? 0) >= MAX_AP) {
          ids[i] = candidates[c++];
        }
      }
    }
    // 返回实际被安排入住宿舍的干员数（供 batchRestChar 统计 pushMessage 的 num）
    return c;
}

  /**
   * 清理房间槽位
   * 清空房间内全部干员（置为 -1）
   * @param args - 包含 roomSlotId 的参数对象
   */
export async function cleanRoomSlot(mgr: BuildingManager, args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await mgr._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        slot.charInstIds = slot.charInstIds.map(() => -1);
      }
    });
}

  /** 给单个干员增加信赖（同步更新 troop.chars 与 charGroup） */
export function _addFavor(mgr: BuildingManager, draft: Draft<PlayerDataModel>,
    charInstId: number,
    gain: number,) : void {
    const char = draft.troop.chars[String(charInstId)];
    if (!char) return;
    char.favorPoint += gain;
    if (draft.troop.charGroup[char.charId]) {
      draft.troop.charGroup[char.charId].favorPoint += gain;
    }
}

  /**
   * 获得信赖（单个干员）
   * @param args - 包含 charInstId 的参数对象
   */
export async function gainIntimacy(mgr: BuildingManager, args: { charInstId: number }) {
    const { charInstId } = args;
    let gained = 0;
    await mgr._player.update(async (draft) => {
      mgr._addFavor(draft, charInstId, mgr._intimacyGain);
      gained = mgr._intimacyGain;
    });
    // 修复：GainIntimacy 任务事件从未 emit → 基建信赖类任务永不推进
    if (gained > 0) {
      await mgr._trigger.emit("GainIntimacy", [{ count: gained }]);
    }
}

  /**
   * 获得全部信赖（所有在岗 + 助战干员）
   *
   * 修复：CS BuildingGainAllIntimacyResponse 含 normal/assist 计数——原实现
   * 只结算在岗干员且 assist 恒 0；现同步结算助战列表干员并返回真实计数。
   *
   * @param args - 请求体参数
   */
export async function gainAllIntimacy(mgr: BuildingManager, args: any) : Promise<{ normal: number; assist: number }> {
    // 修复：响应需含 normal/assist 计数（CS BuildingGainAllIntimacyResponse）
    let normal = 0;
    let assist = 0;
    let total = 0;
    await mgr._player.update(async (draft) => {
      const seen = new Set<number>();
      for (const slotKey in draft.building.roomSlots) {
        for (const instId of draft.building.roomSlots[slotKey].charInstIds) {
          if (instId > 0 && !seen.has(instId)) {
            seen.add(instId);
            mgr._addFavor(draft, instId, mgr._intimacyGain);
            normal++;
          }
        }
      }
      // 修复：助战干员同步结算（与 gainAssistIntimacy 同源，客户端一键领取时计数正确）
      for (const instId of draft.building.assist ?? []) {
        if (instId > 0 && !seen.has(instId)) {
          seen.add(instId);
          mgr._addFavor(draft, instId, mgr._intimacyGain);
          assist++;
        }
      }
      total = normal + assist;
    });
    // 修复：GainIntimacy 任务事件从未 emit → 一键信赖不推进任务
    if (total > 0) {
      await mgr._trigger.emit("GainIntimacy", [{ count: total }]);
    }
    return { normal, assist };
}

  /**
   * 获得助战信赖（assist 列表中的干员）
   * @param args - 请求体参数
   */
export async function gainAssistIntimacy(mgr: BuildingManager, args: any) {
    let gained = 0;
    await mgr._player.update(async (draft) => {
      for (const instId of draft.building.assist) {
        if (instId > 0) {
          mgr._addFavor(draft, instId, mgr._intimacyGain);
          gained += mgr._intimacyGain;
        }
      }
    });
    // 修复：GainIntimacy 任务事件从未 emit → 助战信赖不推进任务
    if (gained > 0) {
      await mgr._trigger.emit("GainIntimacy", [{ count: gained }]);
    }
}

  /**
   * 确认私人宿舍信赖
   * 参考实现：将指定干员的信赖点数提升到 25570
   * @param args - 包含 charInstId 的参数对象
   */
export async function confirmPrivateDormIntimacy(mgr: BuildingManager, args: { charInstId: number }) {
    const charInstId = String(args.charInstId);
    let charId = "";
    const charInfo = mgr._player._playerdata.troop.chars[charInstId];
    if (charInfo) {
      charId = charInfo.charId;
    }
    return await mgr._player.update(async (draft) => {
      if (charId && draft.troop.charGroup[charId]) {
        draft.troop.charGroup[charId].favorPoint = 25570;
      }
      if (charId && draft.troop.chars[charInstId]) {
        draft.troop.chars[charInstId].favorPoint = 25570;
      }
    });
}
