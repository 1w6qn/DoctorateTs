/**
 * WRATH / SKY 模块（rogue_5 怒气/天空）
 *
 * 客户端状态形状（types-playerdata）：
 *   wrath = { wraths: string[], newWrath: number }
 *   sky = { zones: { [key]: SkyZoneInfo } }
 *
 * 简化实现：怒气收集列表；天空区域（rogue_5 特殊地图）初始为空（随玩法推进填充）。
 */
import { RoguelikeV2Manager } from "../logic";
import excel from "@excel/excel";
import type { PlayerRoguelikeV2_CurrentData_Module_SkyZoneInfo } from "@excel/types-playerdata";
import { TypedEventEmitter } from "../../../kernel/events/runtime";

export class RoguelikeWrathManager {
  wraths: string[];
  newWrath: number;
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.wraths = [];
    this.newWrath = -1;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:wrath:gain", this.gain.bind(this));
  }

  init(): void {
    this.wraths = [];
    this.newWrath = -1;
  }

  continue(): void {
    const w = this._player.current.module?.wrath;
    this.wraths = w?.wraths ?? [];
    this.newWrath = w?.newWrath ?? -1;
  }

  /** 收集怒气（rlv2:wrath:gain 事件） */
  gain([id]: [string]): void {
    if (!this.wraths.includes(id)) {
      this.wraths.push(id);
      this.newWrath = this.wraths.length - 1;
    }
  }

  toJSON(): { wraths: string[]; newWrath: number } {
    return { wraths: this.wraths, newWrath: this.newWrath };
  }
}

/** SKY 模块（rogue_5 天空——特殊区域地图） */
export class RoguelikeSkyManager {
  /**
   * 天空区域地图（内部模型 Module.Sky.zones 为 `{[key: string]: any}`，生成模型为
   * `{[key: number]: SkyZoneInfo}`）——简化实现不写入任何区域，此处按生成条目形状声明
   */
  zones: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_SkyZoneInfo };
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.zones = {};
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  init(): void {
    this.zones = {};
  }

  continue(): void {
    this.zones = this._player.current.module?.sky?.zones || {};
  }

  toJSON(): { zones: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_SkyZoneInfo } } {
    return { zones: this.zones };
  }
}
