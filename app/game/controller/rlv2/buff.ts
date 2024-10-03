import { Blackboard } from "@excel/character_table";
import excel from "@excel/excel";
import { RoguelikeBuff, RoguelikeItemBundle } from "../../model/rlv2";
import EventEmitter from "events";
import { RoguelikeV2Controller } from "../rlv2";
import { RoguelikePlayerStatusManager } from "./status";

export class RoguelikeBuffManager {
  _player: RoguelikeV2Controller;
  _trigger: EventEmitter;
  _buffs!: RoguelikeBuff[];
  _status: RoguelikePlayerStatusManager;

  constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
    this._player = player;
    this._status = this._player._status;
    this._buffs = [];
    this._trigger = _trigger;
    this._trigger.on("rlv2:buff:apply", this.applyBuffs.bind(this));
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  async init() {
    this._buffs = [];
  }

  async continue() {
    const theme = this._player.current.game!.theme;
    Object.values(this._player.inventory!.relic).reduce((acc, relic) => {
      const buffs =
        excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs;
      this._buffs.push(...buffs);
      return [...acc, ...buffs];
    }, [] as RoguelikeBuff[]);
  }

  async create() {
    const theme = this._player.current.game!.theme;
    const modeGrade = this._player.current.game!.modeGrade;
    Object.keys(this._player.outer[theme].buff.unlocked).forEach((id) => {
      const buffs = excel.RoguelikeConsts[theme].outbuff[id];
      this.applyBuffs(...buffs);
    });
    this.applyBuffs(...excel.RoguelikeConsts[theme].modebuff[modeGrade]);
  }

  applyBuffs(...args: RoguelikeBuff[]) {
    args.forEach((arg) => {
      if (arg.key == "immediate_reward") {
        this.immediate_reward(arg.blackboard);
      } else if (arg.key == "item_cover_set") {
        this.item_cover_set(arg.blackboard);
      } else if (arg.key == "change_fragment_type_weight") {
        this._trigger.emit("rlv2:fragment:change_type_weight", arg.blackboard);
      }
    });
    this._buffs.push(...args);
  }

  filterBuffs(key: string): RoguelikeBuff[] {
    return this._buffs.filter((buff) => buff.key == key);
  }

  generateBuff(key: string, id: string, value: number): RoguelikeBuff {
    let blackboard: Blackboard = [];
    const funcs: { [key: string]: (id: string, value: number) => Blackboard } =
      {
        immediate_reward: (id: string, value: number) => {
          return [
            { key: "id", value: 0.0, valueStr: id },
            { key: "count", value: value, valueStr: null },
          ];
        },
      };
    if (funcs[key]) {
      blackboard = funcs[key](id, value);
    }
    return { key: key, blackboard: blackboard };
  }

  immediate_reward(blackboard: Blackboard) {
    const item: RoguelikeItemBundle = {
      id: blackboard[0].valueStr!,
      count: blackboard[1].value!,
      sub: 0,
    };
    this._trigger.emit("rlv2:get:items", [item]);
  }

  item_cover_set(blackboard: Blackboard) {
    const item: RoguelikeItemBundle = {
      id: blackboard[0].valueStr!,
      count: blackboard[1].value!,
      sub: 0,
    };
    const theme = this._player.current.game!.theme;
    const type =
      item.type || excel.RoguelikeTopicTable.details[theme].items[item.id].type;
    switch (type) {
      case "HP":
        this._status.property.hp.current = item.count;
        break;
    }
  }
}
