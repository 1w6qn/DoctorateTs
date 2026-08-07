import { PlayerCharacter } from "@game/model/character";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { WritableDraft } from "immer";
import { PlayerDataModel } from "@game/model/playerdata";
import { PlayerBuildingMeetingClue } from "@game/model/playerdata";
import { accountManager } from "./AccountManger";
import { getManufactFormula } from "@excel/building_excel";

/**
 * 基建管理器类
 *
 * 负责游戏基建系统的所有业务逻辑，包括房间管理、干员分配、订单生产、
 * 线索系统、预设队列以及其他基建相关功能。
 * 通过 Immer 进行状态管理，所有变更通过 PlayerDataManager.update 进行。
 */
export class BuildingManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  /**
   * 构造函数
   * @param player - 玩家数据管理器实例
   * @param _trigger - 事件触发器
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on(
      "building:char:init",
      async ([char]: [PlayerCharacter]) => {
        await this._player.update(async (draft) => {
          draft.building.chars[char.instId] = {
            charId: char.charId,
            lastApAddTime: now(),
            ap: 8640000,
            roomSlotId: "",
            index: -1,
            changeScale: 0,
            bubble: {
              normal: {
                add: -1,
                ts: 0,
              },
              assist: {
                add: -1,
                ts: 0,
              },
            },
            workTime: 0,
          };
        });
      },
    );
  }

  /** 获取会客室留言板信息 */
  get boardInfo(): string[] {
    return Object.keys(
      Object.values(this._player._playerdata.building.rooms.MEETING)[0].board,
    );
  }

  /** 获取信息共享时间戳 */
  get infoShare(): number {
    return Object.values(this._player._playerdata.building.rooms.MEETING)[0]
      .infoShare.ts;
  }

  /** 获取家具数量 */
  get furnCnt(): number {
    return Object.keys(this._player._playerdata.building.furniture).length;
  }

  /**
   * 同步基建数据
   * @returns 当前时间戳
   */
  async sync() {
    return await this._player.update(async (draft) => {
      draft.event.building = now() + 5000;
      return now();
    });
  }

  /**
   * 切换基建背景音乐
   * @param args - 包含 musicId 的参数对象
   */
  async changeBGM(args: { musicId: string }) {
    const { musicId } = args;
    return await this._player.update(async (draft) => {
      draft.building.music.selected = musicId;
    });
  }

  /**
   * 设置私人宿舍归属
   * @param args - 包含 slotId 和 charInstId 的参数对象
   */
  async setPrivateDormOwner(args: { slotId: string; charInstId: number }) {
    const { slotId, charInstId } = args;
    return await this._player.update(async (draft) => {
      draft.building.rooms.PRIVATE[slotId].owners = [charInstId];
    });
  }

  /**
   * 设置基建助战干员
   * @param args - 包含 type（位置）和 charInstId 的参数对象
   */
  async setBuildingAssist(args: { type: number; charInstId: number }) {
    const { type, charInstId } = args;
    return await this._player.update(async (draft) => {
      if (draft.building.assist.includes(charInstId)) {
        const index = draft.building.assist.indexOf(charInstId);
        draft.building.assist[index] = -1;
      }
      draft.building.assist[type] = charInstId;
    });
  }

  // ==================== 内部工具方法 ====================

  /** 查找干员所在房间槽位 ID */
  _findRoomSlotIdByChar(charInstId: number): string | undefined {
    const slots = this._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      if (slots[slotId].charInstIds.includes(charInstId)) {
        return slotId;
      }
    }
    return undefined;
  }

  /** 从所有房间槽位中移除指定干员（置为 -1） */
  _clearCharFromRooms(charInstIdList: number[]): void {
    const slots = this._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      const ids = slots[slotId].charInstIds;
      for (let i = 0; i < ids.length; i++) {
        if (charInstIdList.includes(ids[i])) {
          ids[i] = -1;
        }
      }
    }
  }

  /** 生成线索 ID（递增且不与现有库存冲突） */
  _nextClueId(): string {
    const meeting = Object.values(this._player._playerdata.building.rooms.MEETING)[0];
    const used = new Set<string>();
    for (const c of [
      ...(meeting?.ownStock ?? []),
      ...(meeting?.receiveStock ?? []),
    ]) {
      used.add(c.id);
    }
    let i = 1;
    while (used.has(`clue_${String(i).padStart(3, "0")}`)) i++;
    return `clue_${String(i).padStart(3, "0")}`;
  }

  // ==================== 房间管理 ====================

  /**
   * 建造房间
   * 简化实现：根据 roomSlotId 和 roomId 更新房间的建造状态
   * @param args - 包含 roomSlotId 和 roomId 的参数对象
   */
  async buildRoom(args: { roomSlotId: string; roomId: string }) {
    const { roomSlotId, roomId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        slot.state = 1;
        slot.roomId = roomId;
        slot.completeConstructTime = now() + 1;
      }
    });
  }

  /**
   * 升级房间等级
   * 对应 Python 参考实现的 changRoomLevel
   * @param args - 包含 roomSlotId 和 targetLevel 的参数对象
   */
  async upgradeRoom(args: { roomSlotId: string; targetLevel: number }) {
    const { roomSlotId, targetLevel } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        slot.level = targetLevel;
      }
    });
  }

  /**
   * 完成房间升级
   * 简化实现：将房间状态置为已完成，参考 Python 实现返回 202
   */
  async completeUpgradeRoom() {
    return await this._player.update(async (draft) => {
      draft.event.building = now() + 5000;
    });
  }

  /**
   * 降级房间
   * 简化实现：降低房间等级
   * @param args - 包含 roomSlotId 的参数对象
   */
  async degradeRoom(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot && slot.level > 1) {
        slot.level -= 1;
      }
    });
  }

  /**
   * 专精升级
   * 将目标技能置为专精中（state=1），完成时由 completeUpgradeSpecialization 提升等级
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
  async upgradeSpecialization(args: {
    charInstId: number;
    targetSkill: number;
    reduceTimeBd?: any;
  }) {
    const { charInstId, targetSkill } = args;
    return await this._player.update(async (draft) => {
      const char = draft.troop.chars[String(charInstId)];
      if (char && char.skills && char.skills[targetSkill]) {
        char.skills[targetSkill].state = 1; // 专精中
      }
    });
  }

  /**
   * 完成专精升级
   * 提升目标技能 specializeLevel 并复位状态
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
  async completeUpgradeSpecialization(args: {
    charInstId: number;
    targetSkill: number;
  }) {
    const { charInstId, targetSkill } = args;
    return await this._player.update(async (draft) => {
      const char = draft.troop.chars[String(charInstId)];
      if (char && char.skills && char.skills[targetSkill]) {
        char.skills[targetSkill].specializeLevel += 1;
        char.skills[targetSkill].state = 0;
        char.skills[targetSkill].completeUpgradeTime = -1;
      }
    });
  }

  /**
   * 升级自定义等级
   * 简化实现：参考 Python 实现返回 202，预留接口
   */
  async upgradeDiyLevel() {
    return await this._player.update(async (draft) => {
      draft.event.building = now() + 5000;
    });
  }

  // ==================== 干员分配 ====================

  /**
   * 分配干员到房间
   * 参考 Python AssignChar 实现：将干员从原房间移除并分配到目标房间
   * 对于训练室（slot_13）会特殊处理 trainer/trainee
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
  async assignChar(args: { roomSlotId: string; charInstIdList: number[] }) {
    const { roomSlotId, charInstIdList } = args;
    return await this._player.update(async (draft) => {
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

      // 训练室特殊处理
      if (roomSlotId === "slot_13" && charInstIdList.length >= 2) {
        const trainer = charInstIdList[0];
        const trainee = charInstIdList[1];
        const trainingRoom = draft.building.rooms.TRAINING[roomSlotId];
        if (trainingRoom) {
          trainingRoom.trainee.charInstId = trainee;
          trainingRoom.trainee.targetSkill = -1;
          trainingRoom.trainee.speed = 1000;
          trainingRoom.trainer.charInstId = trainer;
          trainingRoom.trainee.state = trainee === -1 ? 0 : 3;
          trainingRoom.trainer.state = trainer === -1 ? 0 : 3;
        }
      }
    });
  }

  /**
   * 批量更换工作干员
   * 将指定房间的干员列表替换为 charInstIdList，同时清空这些干员在其他房间的占用
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
  async batchChangeWorkChar(args: {
    roomSlotId: string;
    charInstIdList: number[];
  }) {
    const { roomSlotId, charInstIdList } = args;
    return await this._player.update(async (draft) => {
      // 清空这些干员在其他房间的占用
      for (const slotKey in draft.building.roomSlots) {
        if (slotKey === roomSlotId) continue;
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (charInstIdList.includes(ids[i])) {
            ids[i] = -1;
          }
        }
      }
      draft.building.roomSlots[roomSlotId].charInstIds = charInstIdList;
    });
  }

  /**
   * 批量休息干员
   * 将指定干员从所有房间的工作位置移除（置为 -1）
   * @param args - 包含 charInstIdList 的参数对象
   */
  async batchRestChar(args: { charInstIdList: number[] }) {
    const { charInstIdList } = args;
    return await this._player.update(async (draft) => {
      for (const slotKey in draft.building.roomSlots) {
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (charInstIdList.includes(ids[i])) {
            ids[i] = -1;
          }
        }
      }
    });
  }

  /**
   * 清理房间槽位
   * 清空房间内全部干员（置为 -1）
   * @param args - 包含 roomSlotId 的参数对象
   */
  async cleanRoomSlot(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        slot.charInstIds = slot.charInstIds.map(() => -1);
      }
    });
  }

  /** 单次信赖增加量（私服简化常量） */
  private _intimacyGain = 12;

  /** 给单个干员增加信赖（同步更新 troop.chars 与 charGroup） */
  private _addFavor(
    draft: WritableDraft<PlayerDataModel>,
    charInstId: number,
    gain: number,
  ): void {
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
  async gainIntimacy(args: { charInstId: number }) {
    const { charInstId } = args;
    return await this._player.update(async (draft) => {
      this._addFavor(draft, charInstId, this._intimacyGain);
    });
  }

  /**
   * 获得全部信赖（所有在岗干员）
   * @param args - 请求体参数
   */
  async gainAllIntimacy(args: any) {
    return await this._player.update(async (draft) => {
      const seen = new Set<number>();
      for (const slotKey in draft.building.roomSlots) {
        for (const instId of draft.building.roomSlots[slotKey].charInstIds) {
          if (instId > 0 && !seen.has(instId)) {
            seen.add(instId);
            this._addFavor(draft, instId, this._intimacyGain);
          }
        }
      }
    });
  }

  /**
   * 获得助战信赖（assist 列表中的干员）
   * @param args - 请求体参数
   */
  async gainAssistIntimacy(args: any) {
    return await this._player.update(async (draft) => {
      for (const instId of draft.building.assist) {
        if (instId > 0) {
          this._addFavor(draft, instId, this._intimacyGain);
        }
      }
    });
  }

  /**
   * 确认私人宿舍信赖
   * 参考实现：将指定干员的信赖点数提升到 25570
   * @param args - 包含 charInstId 的参数对象
   */
  async confirmPrivateDormIntimacy(args: { charInstId: number }) {
    const charInstId = String(args.charInstId);
    let charId = "";
    const charInfo = this._player._playerdata.troop.chars[charInstId];
    if (charInfo) {
      charId = charInfo.charId;
    }
    return await this._player.update(async (draft) => {
      if (charId && draft.troop.charGroup[charId]) {
        draft.troop.charGroup[charId].favorPoint = 25570;
      }
      if (charId && draft.troop.chars[charInstId]) {
        draft.troop.chars[charInstId].favorPoint = 25570;
      }
    });
  }

  // ==================== 订单/生产 ====================

  /** 内部方法：结算单条订单（扣凭证 3003、加金币 count×500） */
  private _settleOrderInternal(
    draft: WritableDraft<PlayerDataModel>,
    stockItem: any,
  ): void {
    const goldNum = stockItem?.count || 0;
    draft.inventory["3003"] = (draft.inventory["3003"] || 0) - goldNum;
    draft.status.gold += goldNum * 500;
  }

  /**
   * 加速订单（立即结算指定订单）
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
  async accelerateOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        const idx = room.stock.findIndex((s: any) => s.orderId === orderId);
        if (idx !== -1) {
          this._settleOrderInternal(draft, room.stock[idx]);
          room.stock.splice(idx, 1);
        }
      }
    });
  }

  /**
   * 加速方案（立即结算全部库存订单）
   * @param args - 包含 slotId 的参数对象
   */
  async accelerateSolution(args: { slotId: string }) {
    return this.settleSale(args);
  }

  /**
   * 完成订单（贸易站交付）
   * 参考实现：扣除订单库存物品，增加金币
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
  async deliveryOrder(args: { slotId: string; orderId: string }) {
    const { slotId } = args;
    return await this._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (
        tradingRoom &&
        Array.isArray(tradingRoom.stock) &&
        tradingRoom.stock.length > 0
      ) {
        const stockItem = tradingRoom.stock[0] as any;
        const goldNum = stockItem?.count || 0;
        // 扣除贸易凭证（3003）并增加金币
        draft.inventory["3003"] =
          (draft.inventory["3003"] || 0) - goldNum;
        draft.status.gold += goldNum * 500;
        // 清空订单库存
        tradingRoom.stock = [];
      }
    });
  }

  /**
   * 批量完成订单
   * 对 orderId 数组中的每个订单执行交付逻辑，扣除贸易凭证并增加金币
   * @param args - 包含 slotId 和 orderId 列表的参数对象
   */
  async deliveryBatchOrder(args: { slotId: string; orderId: string[] }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (
        tradingRoom &&
        Array.isArray(tradingRoom.stock) &&
        tradingRoom.stock.length > 0
      ) {
        for (const oid of orderId) {
          const stockIdx = tradingRoom.stock.findIndex(
            (s: any) => s.orderId === oid,
          );
          if (stockIdx === -1) continue;
          const stockItem = tradingRoom.stock[stockIdx] as any;
          const goldNum = stockItem?.count || 0;
          draft.inventory["3003"] =
            (draft.inventory["3003"] || 0) - goldNum;
          draft.status.gold += goldNum * 500;
          tradingRoom.stock.splice(stockIdx, 1);
        }
      }
    });
  }

  /**
   * 删除订单
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
  async deleteOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        room.stock = room.stock.filter((s: any) => s.orderId !== orderId);
      }
    });
  }

  /**
   * 制造站结算
   * 参考实现：根据配方将产出物品加入背包，并消耗对应材料，重置制造站状态
   * @param args - 包含 roomSlotId 的参数对象
   */
  async settleManufacture(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      this._settleManufactureInternal(draft, roomSlotId);
      // 重置制造站状态
      const room = draft.building.rooms.MANUFACTURE[roomSlotId];
      room.state = 0;
      room.formulaId = "";
      room.lastUpdateTime = now();
      room.completeWorkTime = -1;
      room.remainSolutionCnt = 0;
      room.outputSolutionCnt = 0;
    });
  }

  /**
   * 内部方法：执行制造站结算的材料/产出更新（Excel 驱动——查 manufactFormulas）
   * 产出：itemId × count × outputSolutionCnt；消耗：costs（MATERIAL 扣 inventory / GOLD 扣 status.gold）
   * @param draft - Immer 可写草稿
   * @param roomSlotId - 房间槽位 ID
   */
  private _settleManufactureInternal(
    draft: WritableDraft<PlayerDataModel>,
    roomSlotId: string,
  ) {
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    if (!room) return;
    const outputSolutionCnt = room.outputSolutionCnt;
    const formulaIdStr = String(room.formulaId ?? "");
    if (outputSolutionCnt === 0 || !formulaIdStr) return;
    const formula = getManufactFormula(formulaIdStr);
    if (!formula) return; // 配方不存在（数据版本错位）——容错跳过

    // 产出：itemId × count × 已产出方案数
    const gainCount = (formula.count ?? 1) * outputSolutionCnt;
    draft.inventory[formula.itemId] =
      (draft.inventory[formula.itemId] || 0) + gainCount;

    // 消耗：costs（MATERIAL 扣 inventory / GOLD 扣 status.gold）
    for (const cost of formula.costs ?? []) {
      if (cost.type === "GOLD") {
        draft.status.gold -= cost.count * outputSolutionCnt;
      } else {
        draft.inventory[cost.id] =
          (draft.inventory[cost.id] || 0) - cost.count * outputSolutionCnt;
      }
    }
  }

  /**
   * 贸易站结算
   * 结算全部库存订单：扣贸易凭证 3003，按 count×500 兑换金币
   * @param args - 包含 slotId 的参数对象
   */
  async settleSale(args: { slotId: string }) {
    const { slotId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        for (const item of room.stock) {
          this._settleOrderInternal(draft, item);
        }
        room.stock = [];
      }
    });
  }

  /**
   * 更换制造方案
   * 参考实现：先结算当前产出，再切换到新配方
   * @param args - 包含 roomSlotId、targetFormulaId、solutionCount 的参数对象
   */
  async changeManufactureSolution(args: {
    roomSlotId: string;
    targetFormulaId: string;
    solutionCount: number;
  }) {
    const { roomSlotId, targetFormulaId, solutionCount } = args;
    return await this._player.update(async (draft) => {
      // 先结算当前已产出的方案
      this._settleManufactureInternal(draft, roomSlotId);
      // 切换到新配方
      const room = draft.building.rooms.MANUFACTURE[roomSlotId];
      room.state = 1;
      room.formulaId = targetFormulaId;
      room.lastUpdateTime = now();
      room.completeWorkTime = -1;
      room.remainSolutionCnt = 0;
      room.outputSolutionCnt = solutionCount;
    });
  }

  /**
   * 更换贸易方案
   * @param args - 包含 slotId 和 solution（strategy/stockLimit）的参数对象
   */
  async changeSaleSolution(args: {
    slotId: string;
    solution: { strategy: string; stockLimit: number };
  }) {
    const { slotId, solution } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room) {
        if (solution.strategy) room.strategy = solution.strategy;
        if (solution.stockLimit != null) room.stockLimit = solution.stockLimit;
      }
    });
  }

  /**
   * 更换自定义方案
   * 参考实现：根据 roomSlotId 找到对应房间类型，更新其 diySolution 字段
   * @param args - 包含 roomSlotId 和 solution 的参数对象
   */
  async changeDiySolution(args: { roomSlotId: string; solution: any }) {
    const { roomSlotId, solution } = args;
    return await this._player.update(async (draft) => {
      // 会客室（slot_36）单独处理
      if (roomSlotId === "slot_36") {
        (draft.building.rooms.MEETING[roomSlotId] as any).diySolution = solution;
        return;
      }
      // 其他房间：通过 roomSlots 找到房间类型
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        const roomType = slot.roomId as keyof PlayerDataModel["building"]["rooms"];
        const room = draft.building.rooms[roomType];
        if (room && room[roomSlotId]) {
          (room[roomSlotId] as any).diySolution = solution;
        }
      }
    });
  }

  /**
   * 加工站合成
   * 参考实现：消耗配方材料，产出目标物品，扣除龙门币
   * @param args - 包含 roomSlotId、times 的参数对象
   * @returns 合成结果对象（包含 type/id/count）
   */
  async workshopSynthesis(args: { roomSlotId: string; times: number }) {
    const { roomSlotId, times } = args;
    let resultItem: { type: string; id: string; count: number } | null = null;
    await this._player.update(async (draft) => {
      const workshopRoom = draft.building.rooms.MANUFACTURE[roomSlotId] as any;
      // 注：Python 实现从 MANUFACTURE 房间获取 formulaId，此处保留该逻辑
      const workshopFormula = workshopRoom?.formulaId;
      if (workshopFormula && typeof workshopFormula === "object") {
        const costs = workshopFormula.costs || [];
        for (const cost of costs) {
          const itemId = cost.id;
          const itemCount = cost.count;
          draft.inventory[itemId] =
            (draft.inventory[itemId] || 0) - itemCount * times;
        }
        // 增加产出物品
        if (workshopFormula.itemId) {
          draft.inventory[workshopFormula.itemId] =
            (draft.inventory[workshopFormula.itemId] || 0) + times;
        }
        if (workshopFormula.goldCost) {
          draft.status.gold -= workshopFormula.goldCost * times;
        }
        resultItem = {
          type: "MATERIAL",
          id: workshopFormula.itemId,
          count: times,
        };
      }
    });
    return resultItem;
  }

  /**
   * 加工站分解
   * 分解家具为木材（30012），私服简化固定产出
   * @param args - 包含 furnitureId 和 count 的参数对象
   */
  async workshopDecomposition(args: { furnitureId: string; count: number }) {
    const { furnitureId, count } = args;
    return await this._player.update(async (draft) => {
      const furn = draft.building.furniture[furnitureId];
      if (!furn || furn.count < count) return;
      furn.count -= count;
      draft.inventory["30012"] = (draft.inventory["30012"] || 0) + count * 2;
    });
  }

  // ==================== 线索系统 ====================

  /** 获取首个会客室房间 */
  private _meetingRoom() {
    const rooms = this._player._playerdata.building.rooms.MEETING;
    return Object.values(rooms)[0];
  }

  /**
   * 获取每日线索
   * 每日一条免费线索（dailyReward 已领则不重复发放）
   * @param args - 请求体参数
   */
  async getDailyClue(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.dailyReward) return;
      const status = draft.status;
      const clue: PlayerBuildingMeetingClue = {
        id: this._nextClueId(),
        type: `clue_${1 + Math.floor(Math.random() * 7)}`,
        number: 1 + Math.floor(Math.random() * 3),
        uid: String(status.uid),
        name: status.nickName,
        nickNum: String(status.nickNumber),
        chars: [],
        inUse: 0,
      };
      room.ownStock.push(clue);
      room.dailyReward = clue;
    });
  }

  /**
   * 发送线索（ownStock → receiveStock，私服简化在同一玩家库存间流转）
   * @param args - 包含 id 和 friendId 的参数对象
   */
  async sendClue(args: { id: string; friendId: string }) {
    const { id, friendId } = args;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const idx = room.ownStock.findIndex((c) => c.id === id);
      if (idx === -1) return;
      const clue = room.ownStock.splice(idx, 1)[0];
      clue.uid = String(friendId);
      room.receiveStock.push(clue);
    });
  }

  /**
   * 自动发送线索（发送第一条可发线索）
   * @param args - 请求体参数
   */
  async sendClueAuto(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.ownStock.length === 0) return;
      const clue = room.ownStock.shift()!;
      room.receiveStock.push(clue);
    });
  }

  /**
   * 接收线索到库存（receiveStock → ownStock）
   * @param args - 包含 id 的参数对象
   */
  async receiveClueToStock(args: { id: string }) {
    const { id } = args;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const idx = room.receiveStock.findIndex((c) => c.id === id);
      if (idx === -1) return;
      const clue = room.receiveStock.splice(idx, 1)[0];
      room.ownStock.push(clue);
    });
  }

  /**
   * 放置线索到留言板
   * @param args - 包含 id 的参数对象
   */
  async putClueToTheBoard(args: { id: string }) {
    const { id } = args;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const idx = room.ownStock.findIndex((c) => c.id === id);
      if (idx === -1) return;
      const clue = room.ownStock.splice(idx, 1)[0];
      room.board[id] = id;
    });
  }

  /**
   * 自动放置线索到留言板（放置全部可放线索）
   * @param args - 请求体参数
   */
  async putClueToTheBoardAuto(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      for (const clue of room.ownStock) {
        room.board[clue.id] = clue.id;
      }
      room.ownStock = [];
    });
  }

  /**
   * 删除自己持有的线索
   * @param args - 包含 id 的参数对象
   */
  async deleteOwnClue(args: { id: string }) {
    const { id } = args;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      room.ownStock = room.ownStock.filter((c) => c.id !== id);
    });
  }

  /**
   * 删除接收到的线索
   * @param args - 包含 id 的参数对象
   */
  async deleteReceiveClue(args: { id: string }) {
    const { id } = args;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      room.receiveStock = room.receiveStock.filter((c) => c.id !== id);
    });
  }

  /**
   * 获取线索盒（ownStock + receiveStock）
   * @returns 包含 box 字段的对象
   */
  async getClueBox() {
    const room = this._meetingRoom();
    return {
      box: [...(room?.ownStock ?? []), ...(room?.receiveStock ?? [])],
    };
  }

  /**
   * 获取线索好友列表（基于好友关系数据）
   * @returns 包含 result 字段的对象
   */
  async getClueFriendList() {
    const uid = String(this._player._playerdata.status.uid);
    const social = await accountManager.getSocial(uid);
    const result = await Promise.all(
      social.friends.map(async (f) => {
        const info = await accountManager.getPlayerFriendInfo(f.uid);
        return {
          uid: f.uid,
          nickName: info.nickName,
          nickNumber: info.nickNumber,
          level: info.level,
        };
      }),
    );
    return { result };
  }

  /**
   * 获取会议室奖励（信用点）
   * @returns 包含 rewards 的对象
   */
  async getMeetingroomReward() {
    const room = this._meetingRoom();
    const rewards: any[] = [];
    if (room?.socialReward?.daily) {
      rewards.push({ type: "credit", count: room.socialReward.daily });
    }
    return { rewards };
  }

  // ==================== 预设队列 ====================

  /** 惰性获取预设队列容器（旧存档无该字段时初始化） */
  private _presetQueues(draft: WritableDraft<PlayerDataModel>): any {
    const building = draft.building as any;
    if (!building.presetQueues) building.presetQueues = {};
    return building.presetQueues;
  }

  /**
   * 添加预设队列
   * @param args - 包含 roomSlotId、presetName、charInstIdList 的参数对象
   */
  async addPresetQueue(args: {
    roomSlotId: string;
    presetName: string;
    charInstIdList: number[];
  }) {
    const { roomSlotId, presetName, charInstIdList } = args;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      queues[roomSlotId] = {
        name: presetName ?? "",
        charInstIdList,
        createTs: now(),
      };
    });
  }

  /**
   * 删除预设队列
   * @param args - 包含 roomSlotId 的参数对象
   */
  async deletePresetQueue(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      delete queues[roomSlotId];
    });
  }

  /**
   * 编辑预设队列
   * @param args - 包含 roomSlotId、presetName、charInstIdList 的参数对象
   */
  async editPresetQueue(args: {
    roomSlotId: string;
    presetName?: string;
    charInstIdList?: number[];
  }) {
    const { roomSlotId, presetName, charInstIdList } = args;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      const queue = queues[roomSlotId];
      if (!queue) return;
      if (presetName != null) queue.name = presetName;
      if (charInstIdList != null) queue.charInstIdList = charInstIdList;
    });
  }

  /**
   * 使用预设队列（应用干员到房间，清空其他房间占用）
   * @param args - 包含 roomSlotId 的参数对象
   */
  async usePresetQueue(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      const queue = queues[roomSlotId];
      if (!queue) return;
      for (const slotKey in draft.building.roomSlots) {
        if (slotKey === roomSlotId) continue;
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (queue.charInstIdList.includes(ids[i])) ids[i] = -1;
        }
      }
      draft.building.roomSlots[roomSlotId].charInstIds = [...queue.charInstIdList];
    });
  }

  /**
   * 使用单个预设队列（单房间版，同 usePresetQueue）
   * @param args - 包含 roomSlotId 的参数对象
   */
  async useOnePresetQueue(args: { roomSlotId: string }) {
    return this.usePresetQueue(args);
  }

  /**
   * 修改预设名称
   * @param args - 包含 roomSlotId 和 presetName 的参数对象
   */
  async changePresetName(args: { roomSlotId: string; presetName: string }) {
    const { roomSlotId, presetName } = args;
    return this.editPresetQueue({ roomSlotId, presetName });
  }

  /**
   * 保存自定义预设方案（diyPresetSolutions）
   * @param args - 包含 presetName 和 solution 的参数对象
   */
  async saveDiyPresetSolution(args: { presetName: string; solution: any }) {
    const { presetName, solution } = args;
    return await this._player.update(async (draft) => {
      (draft.building as any).diyPresetSolutions[presetName] = solution;
    });
  }

  /**
   * 编辑锁定队列（记录锁定状态）
   * @param args - 包含 roomSlotId 和 locked 的参数对象
   */
  async editLockQueue(args: { roomSlotId: string; locked: boolean }) {
    const { roomSlotId, locked } = args;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      const queue = queues[roomSlotId];
      if (queue) queue.locked = locked;
    });
  }

  // ==================== 其他功能 ====================

  /**
   * 更改贸易站策略
   * 参考实现：更新对应贸易站房间的 strategy 字段
   * @param args - 包含 slotId 和 strategy 的参数对象
   */
  async changeStrategy(args: { slotId: string; strategy: string }) {
    const { slotId, strategy } = args;
    return await this._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (tradingRoom) {
        tradingRoom.strategy = strategy;
      }
    });
  }

  /**
   * 购买劳动力
   * 消耗源石（1 源石/次），增加 labor.value（+10/次，上限 maxValue）
   * @param args - 包含 buyCount 的参数对象
   */
  async buyLabor(args: { buyCount: number }) {
    const { buyCount } = args;
    return await this._player.update(async (draft) => {
      const labor = draft.building.status.labor;
      const cost = 1;
      if (draft.status.androidDiamond < cost * buyCount) return;
      draft.status.androidDiamond -= cost * buyCount;
      labor.value = Math.min(labor.value + 10 * buyCount, labor.maxValue);
    });
  }

  /**
   * 确认留言板奖励
   * 发放信用点（socialReward.daily + search），标记已领取
   * @param args - 请求体参数
   */
  async confirmMessageBoardReward(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.received) return;
      const reward = room.socialReward.daily + room.socialReward.search;
      draft.inventory["3003"] = (draft.inventory["3003"] || 0) + reward;
      room.received = 1;
    });
  }

  /**
   * 获取协助报告
   * 参考实现：返回近 4 天的制造/贸易/信赖报告数据
   * @returns 包含 reports 数组的对象
   */
  async getAssistReport() {
    const ts = now();
    return {
      reports: [
        { ts, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 86400, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 172800, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 345600, manufacture: {}, trading: {}, favor: [] },
      ],
    };
  }

  /**
   * 获取信息共享访客数
   * 参考实现：返回 0 个访客
   * @returns 包含 num 字段的对象
   */
  async getInfoShareVisitorsNum() {
    return { num: 0 };
  }

  /**
   * 获取最近访客
   * 参考实现：返回空访客列表
   * @returns 包含 visitors 字段的对象
   */
  async getRecentVisitors() {
    return { visitors: [] };
  }

  /**
   * 获取他人留言板内容
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async getOthersMessageBoardContent(args: any) {
    return args;
  }

  /**
   * 获取缩略图 URL
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async getThumbnailUrl(args: any) {
    return args;
  }

  /**
   * 发送表情
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async sendEmoji(args: any) {
    return args;
  }

  /**
   * 开始信息共享
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async startInfoShare(args: any) {
    return args;
  }

  /**
   * 访问基建
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async visitBuilding(args: any) {
    return args;
  }
}
