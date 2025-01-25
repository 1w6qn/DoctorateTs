import excel from "@excel/excel";
import { randomChoice } from "@utils/random";
import { PlayerRoguelikeV2, RoguelikeBuff } from "@game/model/rlv2";
import { RoguelikeV2Controller } from "../../rlv2";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeDisasterManager {
  _curDisaster: string | null;
  _disperseStep: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._curDisaster = null;
    this._disperseStep = 0;
    this._trigger = _trigger;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:disaster:generate", () => {
      this.generate.bind(this);
    });
    this._trigger.on("rlv2:disaster:abstract", this.abstract.bind(this));
    this._trigger.on("rlv2:move", () => {
      if (this._curDisaster) {
        this._disperseStep -= 1;
      } else if (Math.random() < 0.3) {
        this._trigger.emit("rlv2:disaster:generate", []);
      }
      if (this._disperseStep <= 0) {
        this._curDisaster = null;
      }
    });
  }

  init() {
    this._curDisaster = null;
    this._disperseStep = 0;
  }

  continue() {
    this._curDisaster = this._player.current.module!.disaster!.curDisaster;
    this._disperseStep = this._player.current.module!.disaster!.disperseStep;
  }

  generate([steps = 5]: [number]) {
    const theme = this._player.current.game!.theme;
    let level = 1;
    this._player._buff.filterBuffs("disaster_level_up").forEach((b) => {
      level += b.blackboard[0].value!;
    });
    const disasters = Object.values(
      excel.RoguelikeTopicTable.modules[theme].disaster!.disasterData,
    ).filter((d) => d.level == level);
    this._curDisaster = randomChoice(Object.keys(disasters));
    this._disperseStep = steps;
  }

  abstract() {
    this._disperseStep = 0;
    this._curDisaster = null;
  }

  getBuff(): RoguelikeBuff[] {
    let buff: RoguelikeBuff[] = [];
    if (this._curDisaster) {
      buff = [];
    }
    return buff;
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Module.Disaster {
    return {
      curDisaster: this._curDisaster,
      disperseStep: this._disperseStep,
    };
  }
}
