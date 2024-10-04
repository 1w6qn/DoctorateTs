import excel from "@excel/excel";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class DungeonManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("stage:update", this.update.bind(this));
  }

  async update() {
    await this.initStages();
  }
  async initStages() {
    for (const stageId in excel.StageTable.stages) {
      if (!(stageId in this._player._playerdata.dungeon.stages)) {
        this._player._playerdata.dungeon.stages[stageId] = {
          completeTimes: 1,
          hasBattleReplay: 0,
          noCostCnt: 0,
          practiceTimes: 0,
          stageId: stageId,
          startTimes: 1,
          state: 3,
        };
      }
    }
  }
}
