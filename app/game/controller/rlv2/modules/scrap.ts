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
  activeVehicle: { instId?: string; isWalk: boolean };
  inventory: { [key: string]: ScrapItem };
  limit: number;
  _index: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    // 官服 createGame scrap：activeVehicle 仅 { isWalk: true }（步行无 instId）、
    // 开局 2 个初始废品（s_1/s_2 = G_01，value 2）、零件箱容量 8（抓包确认）
    this.activeVehicle = { isWalk: true };
    this.inventory = {};
    this.limit = 8;
    this._index = 0;
    this.seedInitial();
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:scrap:gain", this.gain.bind(this));
  }

  init(): void {
    this.activeVehicle = { isWalk: true };
    this.inventory = {};
    this.limit = 8;
    this._index = 0;
    this.seedInitial();
  }

  /** 官服开局废品：s_1/s_2 = rogue_6_scrap_G_01（value 2）——初始零件箱自带 2 件 */
  private seedInitial(): void {
    const theme = this._player.current.game?.theme || "";
    if (theme !== "rogue_6") return;
    const tpl = { id: "rogue_6_scrap_G_01", value: 2, useCnt: 0, ts: now() };
    this.inventory["s_1"] = { instId: "s_1", ...tpl };
    this.inventory["s_2"] = { instId: "s_2", ...tpl };
    this._index = 3; // 下个废品 s_3（不覆盖 s_1/s_2）
  }

  continue(): void {
    const s = this._player.current.module?.scrap as any;
    this.activeVehicle = s?.activeVehicle || { isWalk: true };
    this.inventory = s?.inventory || {};
    this.limit = s?.limit ?? 8;
    this._index = Object.keys(this.inventory).length;
  }

  /** 获得废品（战斗/事件奖励） */
  gain([id]: [string]): void {
    const theme = this._player.current.game!.theme;
    const scrapMod = (excel.RoguelikeTopicTable.modules[theme] as any) || {};
    const type =
      (scrapMod.scrap ?? scrapMod.sCRAP)?.scrapItemToType?.[id];
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
      this.activeVehicle = { isWalk: true };
      return;
    }
    if (!item) return;
    this.activeVehicle = { instId, isWalk: false };
  }

  toJSON(): {
    activeVehicle: { instId?: string; isWalk: boolean };
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
