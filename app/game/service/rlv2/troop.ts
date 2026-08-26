import { PlayerRoguelikeV2 } from "../../domain/rlv2";
import { RoguelikeV2Manager } from "./logic";
import { omitKeys } from "@utils/object";
import { TypedEventEmitter } from "@game/service/events";

export class RoguelikeTroopManager
  implements PlayerRoguelikeV2.CurrentData.Troop
{
  _index: number;
  chars: { [key: string]: PlayerRoguelikeV2.CurrentData.Char };
  expedition: string[];
  expeditionDetails: { [key: string]: number };
  expeditionReturn: PlayerRoguelikeV2.CurrentData.ExpeditionReturn | null;
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._index = 0;
    this._player = player;
    this.chars = {};
    this.expedition = [];
    this.expeditionDetails = {};
    this.expeditionReturn = null;
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:char:get", this.getChar.bind(this));
  }

  get hasExpeditionReturn() {
    return this.expeditionReturn != null;
  }

  /** 重登"继续探索"：从存档 current.troop 恢复编队/先行一步状态 */
  continue() {
    const t = this._player.current.troop;
    if (!t) return;
    this.chars = t.chars || {};
    this.expedition = t.expedition || [];
    this.expeditionDetails = t.expeditionDetails || {};
    this.expeditionReturn = t.expeditionReturn ?? null;
  }

  init() {
    this.chars = {};
    this.expedition = [];
    this.expeditionDetails = {};
    this.expeditionReturn = null;
  }

  create() {
    this.chars = {};
    this.expedition = [];
    this.expeditionDetails = {};
    this.expeditionReturn = null;
  }

  getChar([char]: [PlayerRoguelikeV2.CurrentData.RecruitChar]) {
    const c = omitKeys(char, [
      "isUpgrade",
      "isCure",
      "population",
      "troopInstId",
    ]) as unknown as PlayerRoguelikeV2.CurrentData.Char;
    // 官服 troop.chars key/instId = 入队序号字符串（'1','2',...）——
    // recruit done() 已按 1 基递增分配 troopInstId；原实现 +1 错位且数字类型不符
    c.instId = String(char.troopInstId);
    this.chars[c.instId] = c;
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Troop {
    return {
      chars: this.chars,
      expedition: this.expedition,
      expeditionDetails: this.expeditionDetails,
      expeditionReturn: this.expeditionReturn,
      hasExpeditionReturn: this.hasExpeditionReturn,
    };
  }
}
