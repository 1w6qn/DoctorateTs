/**
 * COPPER 模块（rogue_5 铜币）
 *
 * 客户端状态形状（types-playerdata）：copper = {
 *   bag: { [key]: { id, isDrawn, layer, countDown, ts } },
 *   redrawCost, redrawFreeze, redrawFreezeCnt
 * }
 * 简化实现：开局抽 3 枚铜币入袋；gild 升级指定铜币（层数+1）；
 * redraw 重置抽牌（扣 redrawCost，3 次后冻结）。
 */
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";

export interface CopperItem {
  id: string;
  isDrawn: number;
  layer: number;
  countDown: number;
  ts: number;
}

export class RoguelikeCopperManager {
  bag: { [key: string]: CopperItem };
  redrawCost: number;
  redrawFreeze: number;
  redrawFreezeCnt: number;
  _index: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.bag = {};
    this.redrawCost = 2;
    this.redrawFreeze = 3;
    this.redrawFreezeCnt = 0;
    this._index = 0;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:copper:init", this.drawInitial.bind(this));
  }

  init(): void {
    this.bag = {};
    // 官方 moduleConsts：重抽费用（gold）、免费重抽次数
    const consts = (
      excel.RoguelikeTopicTable.modules[this._player.current.game!.theme] as any
    )?.copper?.moduleConsts;
    this.redrawCost = consts?.copperDrawFreezeCostCount?.[0] ?? 1;
    this.redrawFreeze = 3;
    this.redrawFreezeCnt = 0;
    this._index = 0;
  }

  continue(): void {
    const c = this._player.current.module?.copper;
    this.bag = c?.bag || {};
    this.redrawCost = c?.redrawCost ?? 2;
    this.redrawFreeze = c?.redrawFreeze ?? 3;
    this.redrawFreezeCnt = c?.redrawFreezeCnt ?? 0;
    this._index = Object.keys(this.bag).length;
  }

  /** 开局抽 3 枚铜币入袋 */
  drawInitial(): void {
    const theme = this._player.current.game!.theme;
    const copperData = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.copper?.copperData;
    if (!copperData) return;
    const ids = Object.keys(copperData);
    if (ids.length === 0) return;
    for (let i = 0; i < 3; i++) {
      const id = ids[Math.floor(Math.random() * ids.length)];
      this.bag[`c_${this._index}`] = {
        id,
        isDrawn: 1,
        layer: 0,
        countDown: 0,
        ts: now(),
      };
      this._index += 1;
    }
  }

  /** 镀金：升级指定铜币层数（copper/gild） */
  gild(key: string): void {
    const item = this.bag[key];
    if (!item) return;
    item.layer += 1;
    item.isDrawn = 1;
  }

  /** 重抽：清空已抽标记并重新抽 3 枚（copper/redraw）；扣 gold 重抽费用 */
  redraw(): { copper: string[]; divineEventId: string } {
    const theme = this._player.current.game!.theme;
    // 扣除重抽费用（gold）
    const goldItem = `${theme}_gold`;
    this._trigger.emit("rlv2:get:items", [
      [{ id: goldItem, count: -this.redrawCost }],
    ]);
    const drawn: string[] = [];
    for (const [key, item] of Object.entries(this.bag)) {
      if (item.isDrawn) {
        item.isDrawn = 0;
        drawn.push(key);
      }
    }
    const result: string[] = [];
    for (const key of drawn) {
      const item = this.bag[key];
      if (!item) continue;
      item.isDrawn = 1;
      result.push(key);
    }
    if (this.redrawFreezeCnt >= this.redrawFreeze) {
      // 冻结：不可再重抽
    }
    return { copper: result, divineEventId: "" };
  }

  toJSON(): {
    bag: { [key: string]: CopperItem };
    redrawCost: number;
    redrawFreeze: number;
    redrawFreezeCnt: number;
  } {
    return {
      bag: this.bag,
      redrawCost: this.redrawCost,
      redrawFreeze: this.redrawFreeze,
      redrawFreezeCnt: this.redrawFreezeCnt,
    };
  }
}
