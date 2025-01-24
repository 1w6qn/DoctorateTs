import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class DexNavManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  get teamV2Info(): { [key: string]: number } {
    return Object.entries(this._player._playerdata.dexNav.teamV2).reduce(
      (acc, [k, v]) => ({ ...acc, [k]: Object.keys(v).length }),
      {},
    );
  }
}
