import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class HomeManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on(
      "background:condition:update",
      this.updateBackgroundCondition.bind(this),
    );
    this._trigger.on("background:unlock", this.unlockBackground.bind(this));
    this._trigger.on("background:get", async (id: string) => {
      await this._player.update(async (draft) => {
        draft.background.bgs[id] = {
          unlock: now(),
        };
      });
    });
    this._trigger.on(
      "homeTheme:condition:update",
      this.updateHomeThemeCondition.bind(this),
    );
    this._trigger.on("homeTheme:unlock", this.unlockHomeTheme.bind(this));
    this._trigger.on("homeTheme:get", async (id: string) => {
      await this._player.update(async (draft) => {
        draft.homeTheme.themes[id] = {
          unlock: now(),
        };
      });
    });
  }

  async setBackground(args: { bgID: string }) {
    await this._player.update(async (draft) => {
      draft.background.selected = args.bgID;
    });
  }

  async updateBackgroundCondition(
    bgID: string,
    conditionId: string,
    target: number,
  ) {
    await this._player.update(async (draft) => {
      if (draft.background.bgs[bgID]!.conditions!) {
        const cond = draft.background.bgs[bgID]!.conditions![conditionId];
        cond.v = target;
        if (cond.t == cond.v) {
          this._trigger.emit("background:unlock", { bgID });
        }
      }
    });
  }

  async unlockBackground(args: { bgID: string }) {
    const { bgID } = args;
    await this._player.update(async (draft) => {
      draft.background.bgs[bgID].unlock = now();
    });
  }

  async setHomeTheme(args: { themeId: string }) {
    const { themeId } = args;
    await this._player.update(async (draft) => {
      draft.homeTheme.selected = themeId;
    });
  }

  async updateHomeThemeCondition(args: {
    themeId: string;
    conditionId: string;
    target: number;
  }) {
    const { themeId, conditionId, target } = args;
    await this._player.update(async (draft) => {
      if (draft.homeTheme.themes[themeId]!.conditions!) {
        const cond = draft.homeTheme!.themes[themeId]!.conditions![conditionId];
        cond.v = target;
        if (cond.t == cond.v) {
          this._trigger.emit("homeTheme:unlock", { themeId });
        }
      }
    });
  }

  async unlockHomeTheme(args: { themeId: string }) {
    const { themeId } = args;
    await this._player.update(async (draft) => {
      draft.homeTheme.themes[themeId].unlock = now();
    });
  }

  async setLowPower(args: { newValue: number }) {
    const { newValue } = args;
    await this._player.update(async (draft) => {
      draft.setting.perf.lowPower = newValue;
    });
  }

  async npcAudioChangeLan(args: { id: string; voiceLan: string }) {
    const { id, voiceLan } = args;
    await this._player.update(async (draft) => {
      draft.npcAudio[id].npcShowAudioInfoFlag = voiceLan;
    });
  }
}
