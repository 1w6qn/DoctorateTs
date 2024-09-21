import EventEmitter from "events";
import {
  PlayerAvatar,
  PlayerDataModel,
  PlayerHomeBackground,
  PlayerHomeTheme,
  PlayerSetting,
} from "../model/playerdata";
import { now } from "@utils/time";

export class HomeManager {
  background: PlayerHomeBackground;
  homeTheme: PlayerHomeTheme;
  avatar: PlayerAvatar;
  setting: PlayerSetting;
  npcAudio: { [key: string]: { npcShowAudioInfoFlag: string } };
  _trigger: EventEmitter;

  constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
    this.background = playerdata.background;
    this.homeTheme = playerdata.homeTheme;
    this.setting = playerdata.setting;
    this.npcAudio = playerdata.npcAudio;
    this.avatar = playerdata.avatar;
    this._trigger = _trigger;
    this._trigger.on(
      "background:condition:update",
      this.updateBackgroundCondition.bind(this),
    );
    this._trigger.on("background:unlock", this.unlockBackground.bind(this));
    this._trigger.on("background:get", (id: string) => {
      this.background.bgs[id] = {
        unlock: now(),
      };
    });
    this._trigger.on(
      "homeTheme:condition:update",
      this.updateHomeThemeCondition.bind(this),
    );
    this._trigger.on("homeTheme:unlock", this.unlockHomeTheme.bind(this));
    this._trigger.on("homeTheme:get", (id: string) => {
      this.homeTheme.themes[id] = {
        unlock: now(),
      };
    });
  }

  setBackground(bgID: string) {
    this.background.selected = bgID;
  }

  updateBackgroundCondition(bgID: string, conditionId: string, target: number) {
    if (this.background.bgs[bgID]!.conditions!) {
      const cond = this.background.bgs[bgID]!.conditions![conditionId];
      cond.v = target;
      if (cond.t == cond.v) {
        this._trigger.emit("background:unlock", bgID);
      }
    }
  }

  unlockBackground(args: { bgID: string }) {
    this.background.bgs[args.bgID].unlock = now();
  }

  setHomeTheme(args: { themeId: string }) {
    this.homeTheme.selected = args.themeId;
  }

  updateHomeThemeCondition(args: {
    themeId: string;
    conditionId: string;
    target: number;
  }) {
    const { themeId, conditionId, target } = args;
    if (this.homeTheme.themes[themeId]!.conditions!) {
      const cond = this.homeTheme!.themes[themeId]!.conditions![conditionId];
      cond.v = target;
      if (cond.t == cond.v) {
        this._trigger.emit("homeTheme:unlock", themeId);
      }
    }
  }

  unlockHomeTheme(args: { themeId: string }) {
    this.homeTheme.themes[args.themeId].unlock = now();
  }

  setLowPower(args: { newValue: number }) {
    this.setting.perf.lowPower = args.newValue;
  }

  npcAudioChangeLan(args: { id: string; voiceLan: string }) {
    this.npcAudio[args.id].npcShowAudioInfoFlag = args.voiceLan;
  }

  toJSON() {
    return {
      background: this.background,
      homeTheme: this.homeTheme,
      setting: this.setting,
      npcAudio: this.npcAudio,
      avatar: this.avatar,
    };
  }
}
