import { PlayerStatus } from "../model/playerdata";
import excel from "@excel/excel";
import { checkNew, now } from "@utils/time";
import moment from "moment";
import { AvatarInfo } from "@game/model/character";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class StatusManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("status:refresh:time", this.refreshTime.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this));
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
  }

  get uid(): string {
    return this.status.uid;
  }

  get status(): PlayerStatus {
    return this._player._playerdata.status;
  }

  async refreshTime() {
    const ts = now();
    const { lastRefreshTs } = this.status;
    if (checkNew(lastRefreshTs, ts, "day")) {
      await this._trigger.emit("refresh:daily", [lastRefreshTs]);
    }
    if (moment().date() == 1 && checkNew(lastRefreshTs, ts, "month")) {
      await this._trigger.emit("refresh:monthly", []);
    }
    if (moment().day() == 1 && checkNew(lastRefreshTs, ts, "week")) {
      await this._trigger.emit("refresh:weekly", []);
    }
    await this._player.update(async (draft) => {
      draft.status.lastRefreshTs = ts;
      draft.status.lastOnlineTs = ts;
    });
  }

  async dailyRefresh() {}

  async weeklyRefresh() {}

  async monthlyRefresh() {}

  async changeSecretary(args: { charInstId: number; skinId: string }) {
    await this._player.update(async (draft) => {
      const { charInstId, skinId } = args;
      const charId = draft.troop.chars[charInstId].charId;
      draft.status.secretary = charId;
      draft.status.secretarySkinId = skinId;
    });
  }

  async finishStory(args: { storyId: string }) {
    await this._player.update(async (draft) => {
      const { storyId } = args;
      draft.status.flags[storyId] = 1;
    });
  }

  async changeAvatar(args: { avatar: AvatarInfo }) {
    await this._player.update(async (draft) => {
      const { avatar } = args;
      draft.status.avatar = avatar;
    });
  }

  async changeResume(args: { resume: string }) {
    await this._player.update(async (draft) => {
      const { resume } = args;
      draft.status.resume = resume;
    });
  }

  async bindNickName(args: { nickname: string }) {
    await this._player.update(async (draft) => {
      const { nickname } = args;
      draft.status.nickName = nickname;
    });
  }

  async buyAp() {
    await this._trigger.emit("items:use", [
      [{ id: "", type: "DIAMOND", count: 1 }],
    ]);
    await this._trigger.emit("items:get", [
      [{ id: "", type: "AP_GAMEPLAY", count: 135 }],
    ]);
  }

  async exchangeDiamondShard(args: { count: number }) {
    const { count } = args;
    await this._trigger.emit("items:get", [
      [
        {
          id: "",
          type: "DIAMOND_SHD",
          count: count * excel.GameDataConst.diamondToShdRate,
        },
      ],
    ]);
    await this._trigger.emit("items:use", [
      [{ id: "", type: "DIAMOND", count: count }],
    ]);
  }

  async receiveTeamCollectionReward(args: { rewardId: string }) {
    const { rewardId } = args;
    await this._player.update(async (draft) => {
      draft.collectionReward.team[rewardId] = 1;
    });
    await this._trigger.emit("items:get", [
      [excel.HandbookInfoTable.teamMissionList[rewardId].item],
    ]);
  }
}
