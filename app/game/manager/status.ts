import excel from "@excel/excel";
import { checkNew, now } from "@utils/time";
import moment from "moment";
import { AvatarInfo } from "@game/model/character";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { WritableDraft } from "immer";
import { PlayerDataModel } from "@game/model/playerdata";

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
    return this._player._playerdata.status.uid;
  }
  async refreshTime() {
    // 先读取跨天判断所需的时间戳，再触发刷新事件
    // 注意：不能在 Immer recipe 内 emit（嵌套 update 会被外层 finishDraft 覆盖丢失）
    const ts = now();
    const lastRefreshTs = this._player._playerdata.status.lastRefreshTs;
    if (checkNew(lastRefreshTs, ts, "day")) {
      console.log("[EventManager] Daily refresh");
      await this._trigger.emit("refresh:daily", [lastRefreshTs]);
    }
    if (moment().day() == 1 && checkNew(lastRefreshTs, ts, "week")) {
      console.log("[EventManager] Daily refresh");
      await this._trigger.emit("refresh:weekly", []);
    }
    if (moment().date() == 1 && checkNew(lastRefreshTs, ts, "month")) {
      console.log("[EventManager] Daily refresh");
      await this._trigger.emit("refresh:monthly", []);
    }
    await this._player.update(async (draft) => {
      draft.status.lastRefreshTs = ts;
      draft.status.lastOnlineTs = ts;
    });
  }

  /**
   * 每日刷新：恢复体力并重置每日购买次数
   */
  async dailyRefresh() {
    await this._player.update(async (draft) => {
      this._refreshAp(draft);
      draft.status.buyApRemainTimes = 10;
    });
  }

  /**
   * 每周刷新（委托 dailyRefresh：跨周必然跨日，执行体力恢复与购买次数重置）
   */
  async weeklyRefresh() {
    return this.dailyRefresh();
  }

  /**
   * 每月刷新（委托 dailyRefresh：跨月必然跨日，执行体力恢复与购买次数重置）
   */
  async monthlyRefresh() {
    return this.dailyRefresh();
  }

  /**
   * 内部方法：按时间恢复体力
   * 每 6 分钟恢复 1 点（与 inventory AP_GAMEPLAY 逻辑一致），上限 maxAp
   * @param draft - Immer 可写草稿
   */
  private _refreshAp(draft: WritableDraft<PlayerDataModel>) {
    const addAp = Math.floor((now() - draft.status.lastApAddTime) / 360);
    if (draft.status.ap < draft.status.maxAp) {
      draft.status.ap = Math.min(
        draft.status.ap + Math.max(addAp, 0),
        draft.status.maxAp,
      );
    }
    draft.status.lastApAddTime = now();
  }

  async changeSecretary(args: { charInstId: number; skinId: string }) {
    const { charInstId, skinId } = args;
    await this._player.update(async (draft) => {
      const charId = draft.troop.chars[charInstId].charId;
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
      [{ id: "", type: "DIAMOND", count }],
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
