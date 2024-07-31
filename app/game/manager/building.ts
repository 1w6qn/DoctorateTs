import EventEmitter from "events";
import { PlayerDataBuilding } from "../model/playerdata";
import excel from "@excel/excel";


export class BuildingManager {
  _trigger: EventEmitter;
  constructor(building: PlayerDataBuilding, _trigger: EventEmitter) {
    
    this._trigger = _trigger;
    //this.initStages();
  }
  toJSON() {
    return {

    }
  }

}