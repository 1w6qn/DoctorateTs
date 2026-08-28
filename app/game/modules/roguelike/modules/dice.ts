/**
 * DICE 模块（rogue_2 骰子）
 *
 * 客户端状态形状（types-playerdata）：dice = { id, count }
 * id 为当前骰子类型（rogue_2_dice_1 等，随藏品升级），count 为持有数量。
 */
import { RoguelikeV2Manager } from "../logic";
import excel from "@excel/excel";
import { TypedEventEmitter } from "../../../kernel/events/runtime";

export class RoguelikeDiceManager {
  id: string;
  count: number;
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.id = "";
    this.count = 1;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  init(): void {
    this.id = "";
    this.count = 1;
  }

  continue(): void {
    const d = this._player.current.module?.dice;
    this.id = d?.id || "";
    this.count = d?.count || 1;
  }

  /** 骰子面数（随骰子类型/藏品升级） */
  get faceCount(): number {
    const theme = this._player.current.game!.theme;
    const diceData = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.dice?.dice;
    return diceData?.[this.id]?.diceFaceCount ?? 6;
  }

  toJSON(): { id: string; count: number } {
    return { id: this.id, count: this.count };
  }
}

/**
 * SANCHECK 模块（rogue_2 灯火/理智）
 *
 * 客户端状态形状（types-playerdata）：san = { sanity }
 * 简化实现：开局 100，战斗/事件消耗由 buff 驱动。
 */
export class RoguelikeSanManager {
  sanity: number;
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.sanity = 100;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  init(): void {
    this.sanity = 100;
  }

  continue(): void {
    this.sanity = this._player.current.module?.san?.sanity ?? 100;
  }

  toJSON(): { sanity: number } {
    return { sanity: this.sanity };
  }
}
