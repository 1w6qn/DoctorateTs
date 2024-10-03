import EventEmitter from "events";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { checkBetween, now } from "@utils/time";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";

export class CheckInManager {
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
  }

  get isSUb(): boolean {
    const { monthlySubscriptionStartTime, monthlySubscriptionEndTime } =
      this._player._playerdata.status;
    return checkBetween(
      now(),
      monthlySubscriptionStartTime,
      monthlySubscriptionEndTime,
    );
  }

  async dailyRefresh() {
    await this._player.update(async (draft) => {
      draft.checkIn.canCheckIn = 1;
      draft.checkIn.checkInRewardIndex += 1;
    });
  }

  async monthlyRefresh() {
    const ts = now();
    await this._player.update(async (draft) => {
      draft.checkIn.checkInGroupId = Object.values(
        excel.CheckinTable.groups,
      ).find((t) => checkBetween(ts, t.signStartTime, t.signEndTime))!.groupId;
      draft.checkIn.checkInHistory = [];
      draft.checkIn.checkInRewardIndex = -1;
    });
  }

  async checkIn(): Promise<{
    signInRewards: ItemBundle[];
    subscriptionRewards: ItemBundle[];
  }> {
    const signInRewards: ItemBundle[] = [];
    const subscriptionRewards: ItemBundle[] = [];
    await this._player.update(async (draft) => {
      if (!draft.checkIn.canCheckIn) {
        return;
      }
      draft.checkIn.canCheckIn = 0;
      if (draft.checkIn.checkInRewardIndex < 0) {
        draft.checkIn.checkInRewardIndex = 0;
      }
      const item =
        excel.CheckinTable.groups[draft.checkIn.checkInGroupId].items[
          draft.checkIn.checkInRewardIndex
        ];
      signInRewards.push({
        id: item.itemId,
        count: item.count,
        type: item.itemType,
      });
      if (this.isSUb) {
        const currentMonthlySubId = excel.CheckinTable.currentMonthlySubId;
        subscriptionRewards.push(
          ...excel.CheckinTable.monthlySubItem[currentMonthlySubId][1].items,
        );
      }
      draft.checkIn.checkInHistory.push(0);
    });
    this._trigger.emit("gainItems", subscriptionRewards.concat(signInRewards));
    return { signInRewards, subscriptionRewards };
  }
}
