import { PlayerRoguelikeV2 } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { omit } from "lodash";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeTroopManager
  implements PlayerRoguelikeV2.CurrentData.Troop
{
  _index: number;
  chars: { [key: string]: PlayerRoguelikeV2.CurrentData.Char };
  expedition: string[];
  expeditionDetails: { [key: string]: number };
  expeditionReturn: PlayerRoguelikeV2.CurrentData.ExpeditionReturn | null;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._index = 0;
    this._player = player;
    this.chars = {};
    this.expedition = [];
    this.expeditionDetails = {};
    this.expeditionReturn = null;
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:char:get", this.getChar.bind(this));
  }

  get hasExpeditionReturn() {
    return this.expeditionReturn != null;
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

  getChar(char: PlayerRoguelikeV2.CurrentData.RecruitChar) {
    console.log("[RLV2] getChar", char);
    const c = omit(char, [
      "isUpgrade",
      "isCure",
      "population",
      "troopInstId",
    ]) as PlayerRoguelikeV2.CurrentData.Char;
    c.instId = char.troopInstId + 1;
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
