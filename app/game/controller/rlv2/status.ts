import { EventEmitter } from "events";
import { PlayerRoguelikeV2 } from "../../model/rlv2";

import { RoguelikeV2Controller } from "../rlv2";
import excel from "@excel/excel";
import { RoguelikeEventManager, RoguelikePendingEvent } from "./events";

export class RoguelikePlayerStatusManager
  implements PlayerRoguelikeV2.CurrentData.PlayerStatus
{
  state!: string;
  property!: PlayerRoguelikeV2.CurrentData.PlayerStatus.Properties;
  cursor!: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition;
  trace!: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition[];
  status!: PlayerRoguelikeV2.CurrentData.PlayerStatus.Status;
  toEnding!: string;
  chgEnding!: boolean;
  _player: RoguelikeV2Controller;
  _trigger: EventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
    this._player = player;
    this.init();
    this._pending = new RoguelikeEventManager(this._player, _trigger);
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
  }

  _pending: RoguelikeEventManager;

  get pending(): RoguelikePendingEvent[] {
    return this._pending._pending;
  }

  init() {
    const _status = {
      state: "NONE",
      property: {
        exp: 0,
        level: 1,
        maxLevel: 0,
        hp: { current: 0, max: 0 },
        gold: 0,
        shield: 0,
        capacity: 0,
        population: { cost: 0, max: 0 },
        conPerfectBattle: 0,
        hpShowState: "NORMAL",
      },
      cursor: { zone: 0, position: null },
      trace: [],
      pending: [],
      status: { bankPut: 0 },
      toEnding: "",
      chgEnding: false,
    };
    this.state = _status.state;
    this.property = _status.property;
    this.cursor = _status.cursor;
    this.trace = _status.trace;
    this.chgEnding = _status.chgEnding;
    this.toEnding = _status.toEnding;
    this.status = _status.status;
  }

  async create() {
    await excel.initPromise;
    const game = this._player.current.game!;
    const theme = game.theme;
    const init = excel.RoguelikeTopicTable.details[theme].init.find(
      (i) =>
        i.modeGrade == game.modeGrade &&
        i.predefinedId == game.predefined &&
        i.modeId == game.mode,
    )!;
    this.state = "INIT";
    this.property.hp.current = init.initialHp;
    this.property.hp.max = init.initialHp;
    this.property.gold = init.initialGold;
    this.property.capacity = init.initialSquadCapacity;
    this.property.population.max = init.initialPopulation;
    this.property.population.cost = 0;
    this.property.conPerfectBattle = 0;
    this.property.shield = init.initialShield;
    this.property.maxLevel = 10;
    this.toEnding = `ro${game.theme.slice(-1)}_ending_1`;
  }

  bankPut() {
    const theme = this._player.current.game!.theme;
    const succeed = Math.random() <= 0.5;
    if (succeed && this._player.outer[theme].bank.current <= 999) {
      this.status.bankPut += 1;
      this._player.outer[theme].bank.current += 1;
      this._trigger.emit("rlv2:bankPut", succeed);
    }
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.PlayerStatus {
    return {
      state: this.state,
      property: this.property,
      cursor: this.cursor,
      trace: this.trace,
      pending: this.pending,
      status: this.status,
      toEnding: this.toEnding,
      chgEnding: this.chgEnding,
    };
  }
}
