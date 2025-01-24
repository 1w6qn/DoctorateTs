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
      this._trigger.emit("refresh:daily", lastRefreshTs);
    }
    if (moment().date() == 1 && checkNew(lastRefreshTs, ts, "month")) {
      this._trigger.emit("refresh:monthly");
    }
    if (moment().day() == 1 && checkNew(lastRefreshTs, ts, "week")) {
      this._trigger.emit("refresh:weekly");
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
    const { charInstId, skinId } = args;
    const charId = this._player.troop.getCharacterByInstId(charInstId).charId;
    await this._player.update(async (draft) => {
      draft.status.secretary = charId;
      draft.status.secretarySkinId = skinId;
    });
  }

  async finishStory(args: { storyId: string }) {
    const { storyId } = args;
    await this._player.update(async (draft) => {
      draft.status.flags[storyId] = 1;
    });
  }

  async changeAvatar(args: { avatar: AvatarInfo }) {
    const { avatar } = args;
    await this._player.update(async (draft) => {
      draft.status.avatar = avatar;
    });
  }

  async changeResume(args: { resume: string }) {
    const { resume } = args;
    await this._player.update(async (draft) => {
      draft.status.resume = resume;
    });
  }

  async bindNickName(args: { nickname: string }) {
    const { nickname } = args;
    await this._player.update(async (draft) => {
      draft.status.nickName = nickname;
    });
  }

  async buyAp() {
    this._trigger.emit("items:use", [{ id: "", type: "DIAMOND", count: 1 }]);
    this._trigger.emit("items:get", [
      { id: "", type: "AP_GAMEPLAY", count: 135 },
    ]);
  }

  async exchangeDiamondShard(args: { count: number }) {
    const { count } = args;
    this._trigger.emit("items:get", [
      {
        id: "",
        type: "DIAMOND_SHD",
        count: count * excel.GameDataConst.diamondToShdRate,
      },
    ]);
    await new Promise((resolve) => setTimeout(resolve, 10));
    this._trigger.emit("items:use", [
      { id: "", type: "DIAMOND", count: count },
    ]);
  }

  async receiveTeamCollectionReward(args: { rewardId: string }) {
    const { rewardId } = args;
    await this._player.update(async (draft) => {
      draft.collectionReward.team[rewardId] = 1;
    });
    this._trigger.emit("items:get", [
      excel.HandbookInfoTable.teamMissionList[rewardId].item,
    ]);
  }
}
