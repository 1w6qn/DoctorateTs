import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { PlayerCharRotationSlot } from "@game/model/playerdata";
import { maxBy, toNumber } from "lodash";

export class CharRotationManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  async setCurrent(args: { instId: string }) {
    await this._player.update(async (draft) => {
      draft.charRotation.current = args.instId;
      const preset = draft.charRotation.presets[args.instId];
      draft.background.selected = preset.background;
      draft.homeTheme.selected = preset.homeTheme;
      draft.status.secretarySkinId = preset.profile;
      draft.status.secretary = preset.profileInst.toString();
    });
  }

  async createPreset() {
    let instId;
    await this._player.update(async (draft) => {
      instId = maxBy(Object.keys(draft.charRotation.presets))!;
      draft.charRotation.presets[instId] = {
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
    await this._player.update(async (draft) => {
      if (args.data?.name) {
        draft.charRotation.presets[args.instId].name = args.data.name;
      }
      if (args.data?.background) {
        draft.charRotation.presets[args.instId].background =
          args.data.background;
        draft.background.selected = args.data.background;
      }
      if (args.data?.homeTheme) {
        draft.charRotation.presets[args.instId].homeTheme = args.data.homeTheme;
        draft.homeTheme.selected = args.data.homeTheme;
      }
      if (args.data?.secretarySkinId) {
        draft.charRotation.presets[args.instId].profile =
          args.data.secretarySkinId;
        draft.status.secretarySkinId = args.data.secretarySkinId;
      }
      if (args.data?.secretaryCharInstId) {
        draft.charRotation.presets[args.instId].profileInst = toNumber(
          args.data.secretaryCharInstId,
        );
        draft.status.secretary = args.data.secretaryCharInstId;
      }
      if (args.data?.slots) {
        draft.charRotation.presets[args.instId].slots = args.data.slots;
      }
    });
  }

  async deletePreset(args: { instId: string }) {
    const { instId } = args;
    await this._player.update(async (draft) => {
      delete draft.charRotation.presets[instId];
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
