import { PlayerTower } from "@game/model/playerdata";
import EventEmitter from "events";

export class TowerController {
  _trigger: EventEmitter;
  _tower: PlayerTower;

  constructor(trigger: EventEmitter, tower: PlayerTower) {
    this._tower = tower;
    this._trigger = trigger;
  }
}
