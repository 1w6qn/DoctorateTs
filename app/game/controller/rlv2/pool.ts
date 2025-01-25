import excel from "@excel/excel";
import { RoguelikeItemBundle } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { randomChoice } from "@utils/random";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikePoolManager {
  _pools: { [id: string]: string[] };

  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._pools = {};
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:relic:recycle", this.recycle.bind(this));
    this._trigger.on("rlv2:relic:put", this.put.bind(this));
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
  }

  recycle([id]: [string]) {
    console.log(id);
  }

  put([id]: [string]) {
    console.log(id);
  }

  init() {
    this._pools = {};
  }

  async create() {
    const theme = this._player.current.game!.theme;
    this._pools["pool_sacrifice_n"] = [];
    this._pools["pool_sacrifice_r"] = [];
    const fragment = excel.RoguelikeTopicTable.modules[theme].fragment;
    if (fragment) {
      this._pools["pool_fragment_3"] = [];
      this._pools["pool_fragment_4"] = [];
      this._pools["pool_fragment_5"] = [];
      Object.values(fragment.fragmentData).forEach((data) => {
        if (data.type == "INSPIRATION") {
          this._pools["pool_fragment_3"].push(data.id);
        } else if (data.type == "WISH") {
          this._pools["pool_fragment_4"].push(data.id);
        } else if (data.type == "IDEA") {
          this._pools["pool_fragment_5"].push(data.id);
        }
      });
    }
    Object.values(excel.RoguelikeTopicTable.details[theme].items)
      .filter((data) => data.canSacrifice)
      .forEach((data) => {
        if (data.value == 8) {
          this._pools["pool_sacrifice_n"].push(data.id);
        } else if (data.value == 12) {
          this._pools["pool_sacrifice_r"].push(data.id);
        }
      });
  }

  get(id: string, putback = false): RoguelikeItemBundle {
    const res = this._pools[id] ? randomChoice(this._pools[id]) : "";
    if (!putback) {
      this._pools[id].splice(this._pools[id].indexOf(res), 1);
    }
    return { id: res, count: 1 };
  }
}
