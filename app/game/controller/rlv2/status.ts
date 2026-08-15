import { PlayerRoguelikeV2 } from "../../model/rlv2";

import { RoguelikeV2Controller } from "../rlv2";
import excel from "@excel/excel";
import { RoguelikeEventManager, RoguelikePendingEvent } from "./events";
import { TypedEventEmitter } from "@game/model/events";

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
  /** 本局结果（"success"=通关到最终层终点 / "giveup"=放弃，供 gameSettle 判定成功） */
  runResult!: string;
  innerMission?: PlayerRoguelikeV2.CurrentData.PlayerStatus.InnerMission[];
  nodeMission?: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodeMission;
  zoneReward?: { [key: string]: PlayerRoguelikeV2.CurrentData.PlayerStatus.ZoneRewardItem };
  traderReturn?: { [key: string]: PlayerRoguelikeV2.CurrentData.PlayerStatus.ZoneRewardItem };
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
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
      runResult: "",
    };
    this.state = _status.state;
    this.property = _status.property;
    this.cursor = _status.cursor;
    this.trace = _status.trace;
    this.chgEnding = _status.chgEnding;
    this.toEnding = _status.toEnding;
    this.runResult = _status.runResult;
    this.status = _status.status;
    this.innerMission = undefined;
    this.nodeMission = undefined;
    this.zoneReward = undefined;
    this.traderReturn = undefined;
  }

  async create() {
    const game = this._player.current.game!;
    const theme = game.theme;
    const init = excel.RoguelikeTopicTable.details[theme].init.find(
      (i) =>
        (i.modeGrade ?? 0) == (game.modeGrade ?? 0) &&
        i.predefinedId == game.predefined &&
        i.modeId == game.mode,
    )!;
    this.state = "INIT";
    // 新对局重置游标/轨迹（上一局 finishEvent 推进过 zone；不重置会导致下一局 init 阶段判定失效）
    this.cursor = { zone: 0, position: null };
    this.trace = [];
    // FBO 对默认值 0 的 int 字段编码为缺省 → undefined，按 0 处理
    this.property.hp.current = init.initialHp ?? 0;
    this.property.hp.max = init.initialHp ?? 0;
    this.property.gold = init.initialGold ?? 0;
    this.property.capacity = init.initialSquadCapacity ?? 0;
    this.property.population.max = init.initialPopulation ?? 0;
    this.property.population.cost = 0;
    this.property.conPerfectBattle = 0;
    this.property.shield = init.initialShield ?? 0;
    this.property.maxLevel = 10;
    this.toEnding = `ro${game.theme.slice(-1)}_ending_1`;
  }

  async bankPut() {
    const theme = this._player.current.game!.theme;
    const succeed = Math.random() <= 0.5;
    if (succeed && this._player.outer[theme].bank.current <= 999) {
      this.status.bankPut += 1;
      // outer 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
      await this._player.update(async (draft) => {
        draft.outer[theme].bank.current += 1;
      });
      await this._trigger.emit("rlv2:bankPut", [succeed]);
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
