/**
 * SCRAP 模块（rogue_6 废品/载具）
 *
 * 客户端状态形状（types-playerdata）：scrap = {
 *   activeVehicle: { instId, isWalk },   // 当前移动方式（0=步行 / 载具 instId）
 *   inventory: { [instId]: { instId, id, value, useCnt, ts } },
 *   limit,                               // 库存上限
 * }
 * 简化实现：开局持有 1 个随机 MOVE 型废品（载具）；changeVehicle 切换当前载具。
 */
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";

export interface ScrapItem {
  instId: string;
  id: string;
  value: number;
  useCnt: number;
  ts: number;
}

export class RoguelikeScrapManager {
  activeVehicle: { instId: string; isWalk: boolean };
  inventory: { [key: string]: ScrapItem };
  limit: number;
  _index: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.activeVehicle = { instId: "", isWalk: true };
    this.inventory = {};
    this.limit = 10; // 零件箱容量 10（官方初始值）
    this._index = 0;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:scrap:gain", this.gain.bind(this));
  }

  init(): void {
    this.activeVehicle = { instId: "", isWalk: true };
    this.inventory = {};
    this.limit = 10; // 零件箱容量 10（官方初始值）
    this._index = 0;
  }

  continue(): void {
    const s = this._player.current.module?.scrap as any;
    this.activeVehicle = s?.activeVehicle || { instId: "", isWalk: true };
    this.inventory = s?.inventory || {};
    this.limit = s?.limit ?? 10;
    this._index = Object.keys(this.inventory).length;
  }

  /** 获得废品（战斗/事件奖励） */
  gain([id]: [string]): void {
    const theme = this._player.current.game!.theme;
    const type = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.scrap?.scrapItemToType?.[id];
    if (!type) return;
    if (Object.keys(this.inventory).length >= this.limit) return;
    this.inventory[`s_${this._index}`] = {
      instId: `s_${this._index}`,
      id,
      value: 1,
      useCnt: 0,
      ts: now(),
    };
    this._index += 1;
    // MOVE 型废品自动装备为载具（首个）
    if (type === "MOVE" && this.activeVehicle.isWalk) {
      this.activeVehicle = {
        instId: `s_${this._index - 1}`,
        isWalk: false,
      };
    }
  }

  /** 切换当前载具（scrap/changeVehicle） */
  changeVehicle(instId: string): void {
    const item = this.inventory[instId];
    if (instId === "") {
      this.activeVehicle = { instId: "", isWalk: true };
      return;
    }
    if (!item) return;
    this.activeVehicle = { instId, isWalk: false };
  }

  toJSON(): {
    activeVehicle: { instId: string; isWalk: boolean };
    inventory: { [key: string]: ScrapItem };
    limit: number;
  } {
    return {
      activeVehicle: this.activeVehicle,
      inventory: this.inventory,
      limit: this.limit,
    };
  }
}
