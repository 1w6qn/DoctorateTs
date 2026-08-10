import { PlayerCharacter } from "@game/model/character";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { WritableDraft } from "immer";
import { PlayerDataModel } from "@game/model/playerdata";
import { PlayerBuildingMeetingClue } from "@game/model/playerdata";
import { BuildingData_OrderType, BuildingData_RoomType } from "@game/model/playerdata";
import { accountManager } from "./AccountManger";
import { getManufactFormula, getWorkshopFormula, getBuildingConstant, getRoomPhase, getGoldRate } from "@excel/building_excel";

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
              private: {
                add: -1,
                ts: 0,
              },
            },
            workTime: 0,
            privateRooms: [],
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
   * 按 laborRecoverTime（秒/点）自动恢复劳动力（sync 等入口调用）
   * 例：laborRecoverTime=360 → 6 分钟恢复 1 点，封顶 maxValue
   */
  private _recoverLabor(draft: WritableDraft<PlayerDataModel>): void {
    const labor = draft.building.status.labor;
    const rate = getBuildingConstant<number>("laborRecoverTime") ?? 360;
    const ts = now();
    const elapsed = ts - (labor.lastUpdateTime || ts);
    if (elapsed <= 0 || rate <= 0) return;
    const gain = Math.floor(elapsed / rate);
    if (gain > 0) {
      labor.value = Math.min(labor.value + gain, labor.maxValue);
      labor.lastUpdateTime = ts;
    }
  }

  /**
   * 同步基建数据
   * @returns 当前时间戳
   */
  async sync() {
    return await this._player.update(async (draft) => {
      this._recoverLabor(draft);
      // 修复：制造站生产随时间累积（进度/产出不再与时间脱钩）
      for (const roomSlotId of Object.keys(draft.building.rooms.MANUFACTURE)) {
        this._accrueManufacture(draft, roomSlotId);
      }
      // 修复：贸易站订单补充（原实现无生成逻辑，交付完即永久为空）
      this._refreshTradingOrders(draft);
      // 训练室进度推进（trainee.processPoint 随时间累积，客户端进度显示一致；
      // 完成仍由客户端计时驱动 completeUpgradeSpecialization）
      this._accrueTraining(draft);
      draft.event.building = now() + 5000;
      return now();
    });
  }

  /**
   * 内部方法：训练室进度推进
   * trainee.processPoint += 流逝时间 × trainee.speed（与官方模型一致）
   * @param draft - Immer 可写草稿
   */
  private _accrueTraining(draft: WritableDraft<PlayerDataModel>): void {
    const trainingRoom = draft.building.rooms.TRAINING;
    for (const roomSlotId of Object.keys(trainingRoom)) {
      const room = trainingRoom[roomSlotId];
      const trainee = room?.trainee;
      if (!trainee || trainee.charInstId <= 0 || trainee.state !== 3) continue;
      const ts = now();
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      trainee.processPoint =
        (trainee.processPoint ?? 0) + elapsed * (trainee.speed ?? 1);
    }
  }

  /**
   * 内部方法：贸易站订单补充
   *
   * 修复：服务端无订单生成逻辑——stock 由账号生成器静态填充，交付完即枯竭。
   * 简单机制：工作时间（state=1）且 stock 不足 2 单时按 3003（贸易凭证）× 汇率
   * 生成金币订单（结构与官服样本一致：delivery 3003 → gain GOLD）。
   *
   * @param draft - Immer 可写草稿
   */
  private _refreshTradingOrders(
    draft: WritableDraft<PlayerDataModel>,
  ): void {
    const rate = getGoldRate();
    for (const slotId of Object.keys(draft.building.rooms.TRADING)) {
      const room = draft.building.rooms.TRADING[slotId];
      if (!room || room.state !== 1) continue;
      if (!Array.isArray(room.stock)) room.stock = [];
      const target = 2;
      if (room.stock.length >= target) continue;
      let maxInstId = room.stock.reduce((m, s) => Math.max(m, s?.instId ?? 0), 0);
      const missing = target - room.stock.length;
      for (let i = 0; i < missing; i++) {
        // 1~4 张贸易凭证 → count×rate 金币（参考官服 O_GOLD 订单结构）
        const count = 1 + Math.floor(Math.random() * 4);
        maxInstId += 1;
        room.stock.push({
          instId: maxInstId,
          delivery: [{ id: "3003", type: "MATERIAL", count }],
          type: "O_GOLD",
          gain: { id: "4001", type: "GOLD", count: count * rate },
          buff: [],
        });
      }
    }
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
  async setPrivateDormOwner(args: {
    slotId: string;
    charInstId?: number;
    charInsId?: number;
  }) {
    const { slotId } = args;
    // 修复：CS 字段名为 charInsId（大 S），客户端发送 charInsId——
    // 原实现读 charInstId → undefined 写入 owners:[null] 破坏存档
    const charInstId = args.charInstId ?? args.charInsId;
    if (charInstId == null) return;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.PRIVATE[slotId];
      if (!room) return; // 防御：非法 slotId
      room.owners = [charInstId];
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

  // ==================== 房间管理 ====================

  /**
   * 建造房间（Excel 驱动——按 rooms[roomId].phases[1].buildCost 扣材料/劳动力）
   * @param args - 包含 roomSlotId 和 roomId 的参数对象
   */
  async buildRoom(args: { roomSlotId: string; roomId: string }) {
    const { roomSlotId, roomId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      // 建造 = 1 级相位 buildCost（材料/金币/劳动力）
      const phase = getRoomPhase(roomId, 1);
      if (!phase) return; // 房间类型未知——容错跳过
      this._applyBuildCost(draft, phase.buildCost);
      slot.state = 1;
      slot.roomId = roomId as BuildingData_RoomType;
      slot.completeConstructTime = now() + 1;
    });
  }

  /**
   * 升级房间等级（Excel 驱动——按目标等级相位 buildCost 扣资源）
   * @param args - 包含 roomSlotId 和 targetLevel 的参数对象
   */
  async upgradeRoom(args: { roomSlotId: string; targetLevel: number }) {
    const { roomSlotId, targetLevel } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      const phase = getRoomPhase(slot.roomId, targetLevel);
      if (!phase) return; // 相位不存在——容错跳过
      this._applyBuildCost(draft, phase.buildCost);
      slot.level = targetLevel;
    });
  }

  /** 内部方法：应用建造/升级消耗（items 扣 inventory/金币、labor 扣劳动力） */
  private _applyBuildCost(
    draft: WritableDraft<PlayerDataModel>,
    buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number },
  ): void {
    for (const item of buildCost?.items ?? []) {
      if (item.type === "GOLD") {
        draft.status.gold -= item.count;
      } else {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) - item.count;
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

  /**
   * 单次信赖增加量（Excel 驱动：basicFavorPerDay 每日信赖量 ÷ 60 ≈ 每小时量）
   * 例：basicFavorPerDay=720 → 12/次（官服按小时累积信赖，私服简化每次操作发放）
   */
  private get _intimacyGain(): number {
    const perDay = getBuildingConstant<number>("basicFavorPerDay") ?? 720;
    return Math.max(Math.round(perDay / 60), 1);
  }

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
  async gainAllIntimacy(args: any): Promise<{ normal: number; assist: number }> {
    // 修复：响应需含 normal/assist 计数（CS BuildingGainAllIntimacyResponse）
    let normal = 0;
    await this._player.update(async (draft) => {
      const seen = new Set<number>();
      for (const slotKey in draft.building.roomSlots) {
        for (const instId of draft.building.roomSlots[slotKey].charInstIds) {
          if (instId > 0 && !seen.has(instId)) {
            seen.add(instId);
            this._addFavor(draft, instId, this._intimacyGain);
            normal++;
          }
        }
      }
    });
    return { normal, assist: 0 };
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

  /**
   * 内部方法：结算单条订单（真实订单结构——扣 delivery 物品、加 gain 物品）
   * 例：delivery=[{3003×3}]、gain={4001(金币)×1500} → 扣 3003×3、加金币 1500
   */
  private _settleOrderInternal(
    draft: WritableDraft<PlayerDataModel>,
    stockItem: any,
  ): void {
    for (const d of stockItem?.delivery ?? []) {
      draft.inventory[d.id] = (draft.inventory[d.id] || 0) - (d.count ?? 1);
    }
    const gain = stockItem?.gain;
    if (gain) {
      if (gain.type === "GOLD") {
        draft.status.gold += gain.count ?? 0;
      } else {
        draft.inventory[gain.id] =
          (draft.inventory[gain.id] || 0) + (gain.count ?? 1);
      }
    }
  }

  /**
   * 加速订单（立即结算指定订单——按 instId 查找）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
  async accelerateOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        const idx = room.stock.findIndex((s: any) => s.instId === orderId);
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
   * 完成订单（贸易站交付——结算首条库存订单，扣 delivery 加 gain）
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
  async deliveryOrder(args: { slotId: string; orderId: string }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
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
          this._settleOrderInternal(draft, tradingRoom.stock[idx]);
          tradingRoom.stock.splice(idx, 1);
        }
      }
    });
  }

  /**
   * 批量完成订单（对 orderId 数组中的每个订单按 instId 结算）
   * @param args - 包含 slotId 和 orderId 列表的参数对象
   */
  async deliveryBatchOrder(args: { slotList?: string[] }): Promise<{
    [slotId: string]: ItemBundle[];
  }> {
    // 修复：官方字段为 slotList（CS BuildingDeliveryBatchOrderRequest { slotList }，
    // 结算每个贸易站的全部库存订单）；原实现读 slotId/orderId → 客户端请求解构不到
    // → 空 delta。响应 delivered: { slotId: [收益物品] } 对齐 CS/抓包。
    const delivered: { [slotId: string]: ItemBundle[] } = {};
    await this._player.update(async (draft) => {
      for (const slotId of args.slotList ?? []) {
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
          this._settleOrderInternal(draft, stock);
          room.stock.splice(i, 1);
        }
        delivered[slotId] = gains;
      }
    });
    return delivered;
  }

  /**
   * 删除订单（按 instId）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
  async deleteOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        room.stock = room.stock.filter((s: any) => s.instId !== orderId);
      }
    });
  }

  /**
   * 内部方法：推进制造站生产（随时间累积 processPoint → 产出方案）
   *
   * 修复：基建生产不随时间累积、生产速度 buff 无效的问题。
   * 官方模型：房间 capacity（生产力/秒）× 流逝时间 → processPoint，
   * 每满 formula.costPoint 产出 1 方案（remainSolutionCnt 递减、outputSolutionCnt 递增）。
   * 用房间自维护的 lastUpdateTime 计算流逝（生成器的 saveTime/tailTime 为相对值，不可用）。
   *
   * @param draft - Immer 可写草稿
   * @param roomSlotId - 制造站房间槽位 ID
   */
  private _accrueManufacture(
    draft: WritableDraft<PlayerDataModel>,
    roomSlotId: string,
  ): void {
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    if (!room || room.state !== 1) return;
    const formula = getManufactFormula(room.formulaId);
    if (!formula) return;
    const costPoint = formula.costPoint ?? 0;
    const capacity = room.capacity ?? 0;
    if (costPoint <= 0 || capacity <= 0) return;
    const ts = now();
    const elapsed = ts - (room.lastUpdateTime || ts);
    if (elapsed <= 0) return;
    room.lastUpdateTime = ts;
    room.processPoint = (room.processPoint ?? 0) + elapsed * capacity;
    let produced = Math.floor(room.processPoint / costPoint);
    if (produced <= 0) return;
    room.processPoint -= produced * costPoint;
    // 未设目标时（remainSolutionCnt 无效）按公式无限产出；否则受剩余目标限制
    if ((room.remainSolutionCnt ?? 0) > 0) {
      produced = Math.min(produced, room.remainSolutionCnt);
      room.remainSolutionCnt -= produced;
    }
    room.outputSolutionCnt = (room.outputSolutionCnt ?? 0) + produced;
  }

  /**
   * 制造站结算
   * 参考实现：根据配方将产出物品加入背包，并消耗对应材料，重置制造站状态
   * @param args - 包含 roomSlotId 的参数对象
   */
  async settleManufacture(args: { roomSlotIdList?: string[]; supplement?: number }) {
    // 修复：官方字段为 roomSlotIdList（数组），原实现读取单值 roomSlotId →
    // 客户端请求解构不到 → 空 delta → 客户端"无法更新制造站状态"
    const list = args.roomSlotIdList ?? [];
    await this._player.update(async (draft) => {
      for (const roomSlotId of list) {
        // 先推进时间累积的产出再结算
        this._accrueManufacture(draft, roomSlotId);
        this._settleManufactureInternal(draft, roomSlotId);
        // 重置制造站状态（防御：非法 roomSlotId 直接跳过不 500）
        const room = draft.building.rooms.MANUFACTURE[roomSlotId];
        if (!room) continue;
        room.state = 0;
        room.formulaId = "";
        room.lastUpdateTime = now();
        room.completeWorkTime = -1;
        room.remainSolutionCnt = 0;
        room.outputSolutionCnt = 0;
        room.processPoint = 0;
      }
    });
    // 返回结算的房间数（CS BuildingSettleManufactResponse.supplement）
    return list.length;
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
    // 修复：余额校验——材料/金币不足时按比例只结算可承担部分，避免负库存/负金币
    let affordable = outputSolutionCnt;
    for (const cost of formula.costs ?? []) {
      const per = cost.count ?? 0;
      if (per <= 0) continue;
      const need = per * outputSolutionCnt;
      const have =
        cost.type === "GOLD"
          ? draft.status.gold
          : draft.inventory[cost.id] || 0;
      if (need > 0 && have < need) {
        affordable = Math.min(affordable, Math.floor(have / per));
      }
    }
    if (affordable <= 0) {
      // 材料不足：回退产出，仅保留已加的物品（下轮 settle 再补扣）
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) - gainCount;
      return;
    }
    const settleCount = Math.min(outputSolutionCnt, affordable);
    if (settleCount !== outputSolutionCnt) {
      // 部分结算：产出与消耗都按可承担数
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) -
        (gainCount - (formula.count ?? 1) * settleCount);
      room.outputSolutionCnt = outputSolutionCnt - settleCount;
      room.remainSolutionCnt = (room.remainSolutionCnt ?? 0) + (outputSolutionCnt - settleCount);
    }
    for (const cost of formula.costs ?? []) {
      if (cost.type === "GOLD") {
        draft.status.gold -= cost.count * settleCount;
      } else {
        draft.inventory[cost.id] =
          (draft.inventory[cost.id] || 0) - cost.count * settleCount;
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
      // 先推进并结算当前已产出的方案
      this._accrueManufacture(draft, roomSlotId);
      this._settleManufactureInternal(draft, roomSlotId);
      // 切换到新配方（修复：产出随时间累积而非立即满产——
      // remainSolutionCnt 为目标批次数，outputSolutionCnt 从 0 开始由 _accrueManufacture 推进）
      const room = draft.building.rooms.MANUFACTURE[roomSlotId];
      if (!room) return;
      room.state = 1;
      room.formulaId = targetFormulaId;
      room.lastUpdateTime = now();
      room.completeWorkTime = -1;
      room.remainSolutionCnt = Math.max(0, solutionCount ?? 0);
      room.outputSolutionCnt = 0;
      room.processPoint = 0;
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
        if (solution.strategy) room.strategy = solution.strategy as BuildingData_OrderType;
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
   * 加工站合成（Excel 驱动——查 workshopFormulas）
   * 消耗 costs（MATERIAL 扣 inventory / GOLD 扣金币）+ goldCost，产出 itemId×count×times，
   * extraOutcomeRate 概率触发 extraOutcomeGroup 加权副产物。
   * @param args - 包含 roomSlotId、times、formulaId（客户端传，缺失时回退房间 formulaId）的参数对象
   * @returns 合成结果对象（包含 type/id/count）
   */
  async workshopSynthesis(args: {
    roomSlotId: string;
    times: number;
    formulaId?: string;
  }) {
    const { roomSlotId, times, formulaId } = args;
    let resultItem: { type: string; id: string; count: number } | null = null;
    await this._player.update(async (draft) => {
      const roomFormulaId =
        formulaId ?? (draft.building.rooms.MANUFACTURE as any)[roomSlotId]?.formulaId;
      const formula = getWorkshopFormula(roomFormulaId);
      if (!formula) return; // 配方不存在（数据版本错位/制造配方 ID）——容错跳过

      // 修复：余额校验——材料/金币不足时按可承担次数合成，避免负库存/负金币
      const totalGoldCost = (formula.goldCost ?? 0) * times;
      let affordable = times;
      for (const cost of formula.costs ?? []) {
        const per = cost.count ?? 0;
        if (per <= 0) continue;
        const have =
          cost.type === "GOLD"
            ? draft.status.gold
            : draft.inventory[cost.id] || 0;
        if (have < per * times) {
          affordable = Math.min(affordable, Math.floor(have / per));
        }
      }
      if (totalGoldCost > 0 && draft.status.gold < totalGoldCost) {
        affordable = Math.min(affordable, Math.floor(draft.status.gold / (formula.goldCost ?? 1)));
      }
      if (affordable <= 0) return;
      const times2 = affordable;
      // 消耗：costs（MATERIAL 扣 inventory / GOLD 扣金币）
      for (const cost of formula.costs ?? []) {
        if (cost.type === "GOLD") {
          draft.status.gold -= cost.count * times2;
        } else {
          draft.inventory[cost.id] =
            (draft.inventory[cost.id] || 0) - cost.count * times2;
        }
      }
      // 消耗：goldCost（合成手续费）
      if (formula.goldCost) {
        draft.status.gold -= formula.goldCost * times2;
      }
      // 产出
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) + (formula.count ?? 1) * times2;
      // 副产物（extraOutcomeRate 概率 + extraOutcomeGroup 加权随机）
      if (
        formula.extraOutcomeRate &&
        formula.extraOutcomeGroup?.length &&
        Math.random() < formula.extraOutcomeRate
      ) {
        const pool = formula.extraOutcomeGroup as {
          weight?: number;
          itemId: string;
          itemCount: number;
        }[];
        const total = pool.reduce((s, g) => s + (g.weight ?? 1), 0);
        let roll = Math.random() * total;
        for (const g of pool) {
          roll -= g.weight ?? 1;
          if (roll <= 0) {
            draft.inventory[g.itemId] =
              (draft.inventory[g.itemId] || 0) + (g.itemCount ?? 1) * times2;
            break;
          }
        }
      }
      resultItem = {
        type: "MATERIAL",
        id: formula.itemId,
        count: times2,
      };
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

  /** 线索阵营（真实存档 type 取值，与 MEETING buff.weight keys 一致） */
  private static _CLUE_FACTIONS = [
    "RHINE",
    "PENGUIN",
    "BLACKSTEEL",
    "URSUS",
    "GLASGOW",
    "KJERAG",
    "RHODES",
  ];

  /**
   * 获取每日线索
   * 每日一条免费线索（dailyReward 已领则不重复发放）
   * 真实格式：type=阵营、id={uid}#{随机}#{时间戳}
   * @param args - 请求体参数
   */
  async getDailyClue(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.dailyReward) return;
      const status = draft.status;
      const clue: PlayerBuildingMeetingClue = {
        id: `${status.uid}#${Math.floor(Math.random() * 9000 + 1000)}#${now()}`,
        type: BuildingManager._CLUE_FACTIONS[
          Math.floor(Math.random() * BuildingManager._CLUE_FACTIONS.length)
        ],
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
