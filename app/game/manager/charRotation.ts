import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { PlayerCharRotationSlot } from "@game/model/playerdata";
import { original } from "immer";
import { maxBy, toNumber } from "lodash";

export class CharRotationManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  async setCurrent(args: { instId: string }) {
    const { instId } = args;
    await this._player.update(async (draft) => {
      draft.charRotation.current = instId;
      console.log("draft", original(draft.charRotation));
      const preset = draft.charRotation.preset[instId];
      draft.background.selected = preset.background;
      draft.homeTheme.selected = preset.homeTheme;
      draft.status.secretarySkinId = preset.profile;
      draft.status.secretary = draft.troop.chars[preset.profileInst].charId;
    });
  }

  async createPreset() {
    let instId;
    await this._player.update(async (draft) => {
      instId = maxBy(Object.keys(draft.charRotation.preset))!;
      draft.charRotation.preset[instId] = {
        name: "未命名界面配置",
        background: "bg_rhodes_day",
        homeTheme: "tm_rhodes_day",
        profile: "char_002_amiya#1",
        profileInst: 1,
        slots: [
          {
            charId: "char_002_amiya",
            skinId: "char_002_amiya#1",
          },
        ],
      };
    });
    return instId;
  }

  async updatePreset(args: CharRotationUpdatePresetRequest) {
    const { instId, data } = args;
    await this._player.update(async (draft) => {
      if (data?.name) {
        draft.charRotation.preset[instId].name = data.name;
      }
      if (data?.background) {
        draft.charRotation.preset[instId].background = data.background;
        draft.background.selected = data.background;
      }
      if (data?.homeTheme) {
        draft.charRotation.preset[instId].homeTheme = data.homeTheme;
        draft.homeTheme.selected = data.homeTheme;
      }
      if (data?.secretarySkinId) {
        draft.charRotation.preset[instId].profile = data.secretarySkinId;
        draft.status.secretarySkinId = data.secretarySkinId;
      }
      if (data?.secretaryCharInstId) {
        draft.charRotation.preset[instId].profileInst = toNumber(
          data.secretaryCharInstId,
        );
        draft.status.secretary =
          draft.troop.chars[data.secretaryCharInstId].charId;
      }
      if (data?.slots) {
        draft.charRotation.preset[instId].slots = data.slots;
      }
    });
  }

  async deletePreset(args: { instId: string }) {
    const { instId } = args;
    await this._player.update(async (draft) => {
      delete draft.charRotation.preset[instId];
    });
  }
}

export interface CharRotationUpdatePresetRequest {
  instId: string;
  flag: number;
  data: {
    name?: string;
    background?: string;
    homeTheme?: string;
    secretarySkinId?: string;
    secretaryCharInstId?: string;
    slots?: PlayerCharRotationSlot[];
  };
}
