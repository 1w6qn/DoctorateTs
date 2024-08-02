import EventEmitter from "events";
import { PlayerDungeon, PlayerHiddenStage, PlayerSpecialStage, PlayerStage } from "../model/playerdata";
import excel from "../../excel/excel";


export class DungeonManager implements PlayerDungeon {
  stages: { [key: string]: PlayerStage; };
  cowLevel: { [key: string]: PlayerSpecialStage; };
  hideStages: { [key: string]: PlayerHiddenStage; };
  mainlineBannedStages: string[];
  _trigger: EventEmitter;
  constructor(dungeon: PlayerDungeon, _trigger: EventEmitter) {
    this.stages = dungeon.stages;
    this.cowLevel = dungeon.cowLevel;
    this.hideStages = dungeon.hideStages;
    this.mainlineBannedStages = dungeon.mainlineBannedStages;
    this._trigger = _trigger;
    //this.initStages();
  }
  async initStages() {
    await excel.initPromise
    
    for (let stageId in excel.StageTable.stages) {
      if (!(stageId in this.stages)) {
        this.stages[stageId] = {
          completeTimes: 1,
          hasBattleReplay: 0,
          noCostCnt: 0,
          practiceTimes: 0,
          stageId: stageId,
          startTimes: 1,
          state: 3,
        }
      }
    }
  }

  toJSON(): PlayerDungeon {
    return {
      stages: this.stages,
      cowLevel: this.cowLevel,
      hideStages: this.hideStages,
      mainlineBannedStages: this.mainlineBannedStages
    }
  }

}