import EventEmitter from "events";

import { max } from "lodash";
import { PlayerDataManager } from "./PlayerDataManager";

export class DexNavManager {
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("char:get", this.charGetDexNavPrefix.bind(this));
  }

  get teamV2Info(): { [key: string]: number } {
    return Object.entries(this._player._playerdata.dexNav.teamV2).reduce(
      (acc, [k, v]) => ({ ...acc, [k]: Object.keys(v).length }),
      {},
    );
  }

  async charGetDexNavPrefix(
    charId: string,
    args: { from: string } = { from: "NORMAL" },
  ) {
    const { from } = args;
    await this._player.update(async (draft) => {
      const { character } = draft.dexNav;
      if (!(charId in character)) {
        character[charId] = {
          charInstId: max(Object.values(character).map((k) => k.count))! + 1,
          count: 1,
        };
        return;
      }
      if (from === "CLASSIC") {
        character[charId].classicCount = 1 + (character[charId].count ?? 0);
      } else {
        character[charId].count += 1;
      }
    });
  }
}
