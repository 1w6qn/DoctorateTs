import excel from "@excel/excel";
import { randomChoice } from "@utils/random";
import { RoguelikeBuff } from "@game/model/rlv2";
import { RoguelikeV2Controller } from "../../rlv2";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeDisasterManager {
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:disaster:generate", () => {
      this.generate.bind(this);
    });
    this._trigger.on("rlv2:disaster:abstract", this.abstract.bind(this));
    this._trigger.on("rlv2:move", async () => {
      await this._player.update(async (draft) => {
        const disaster = draft.current.module!.disaster!;
        if (disaster.curDisaster) {
          disaster.disperseStep -= 1;
        } else if (Math.random() < 0.3) {
          await this._trigger.emit("rlv2:disaster:generate", []);
        }
        if (disaster.disperseStep <= 0) {
          disaster.curDisaster = null;
        }
      });
    });
  }

  async init() {
    await this._player.update(async (draft) => {
      draft.current.module!.disaster = {
        curDisaster: null,
        disperseStep: 0,
      };
    });
  }

  async generate([steps = 5]: [number]) {
    const theme = this._player.current.game!.theme;
    let level = 1;
    this._player._buff.filterBuffs("disaster_level_up").forEach((b) => {
      level += b.blackboard[0].value!;
    });
    const disasters = Object.values(
      excel.RoguelikeTopicTable.modules[theme].disaster!.disasterData,
    ).filter((d) => d.level == level);
    await this._player.update(async (draft) => {
      const disaster = draft.current.module!.disaster!;
      disaster.curDisaster = randomChoice(Object.keys(disasters));
      disaster.disperseStep = steps;
    });
  }

  async abstract() {
    await this._player.update(async (draft) => {
      const disaster = draft.current.module!.disaster!;
      disaster.curDisaster = null;
      disaster.disperseStep = 0;
    });
  }

  async getBuff(): Promise<RoguelikeBuff[]> {
    const buff: RoguelikeBuff[] = [];
    return buff;
  }

  /** 线格式：{ curDisasterId, disperseStep }（types-playerdata；内部字段为 curDisaster） */
  toJSON(): { curDisasterId: string | null; disperseStep: number } {
    return {
      curDisasterId: this._player.current.module?.disaster?.curDisaster ?? null,
      disperseStep:
        this._player.current.module?.disaster?.disperseStep ?? 0,
    };
  }
}
