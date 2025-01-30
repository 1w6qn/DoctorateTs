import { PlayerCharacter } from "@game/model/character";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class BuildingManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on(
      "building:char:init",
      async ([char]: [PlayerCharacter]) => {
        await this._player.update(async (draft) => {
          draft.building.chars[char.instId] = {
            charId: char.charId,
            lastApAddTime: now(),
            ap: 8640000,
            roomSlotId: "",
            index: -1,
            changeScale: 0,
            bubble: {
              normal: {
                add: -1,
                ts: 0,
              },
              assist: {
                add: -1,
                ts: 0,
              },
            },
            workTime: 0,
          };
        });
      },
    );
  }

  get boardInfo(): string[] {
    return Object.keys(
      Object.values(this._player._playerdata.building.rooms.MEETING)[0].board,
    );
  }

  get infoShare(): number {
    return Object.values(this._player._playerdata.building.rooms.MEETING)[0]
      .infoShare.ts;
  }

  get furnCnt(): number {
    return Object.keys(this._player._playerdata.building.furniture).length;
  }

  async sync() {
    return await this._player.update(async (draft) => {
      draft.event.building = now() + 5000;
      return now();
    });
  }
}
