import EventEmitter from "events";
import excel from "@excel/excel";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";

export class DungeonManager {
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("stage:update", this.update.bind(this));
    //this.initStages();
  }

  update() {}
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
