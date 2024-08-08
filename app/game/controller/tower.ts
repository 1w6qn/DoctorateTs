import { PlayerDataTower } from "@game/model/playerdata";
import EventEmitter from "events";

export class TowerController {
    _trigger:EventEmitter;
    _tower:PlayerDataTower;
    constructor(trigger:EventEmitter, tower:PlayerDataTower) {
        
        this._tower = tower;
        this._trigger = trigger;
    }
}