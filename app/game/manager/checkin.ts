import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { checkBetween, now } from "@utils/time";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class CheckInManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
  }

  async dailyRefresh() {
    await this._player.update(async (draft) => {
      draft.checkIn.canCheckIn = 1;
      draft.checkIn.checkInRewardIndex += 1;
    });
  }

  async monthlyRefresh() {
    await this._player.update(async (draft) => {
      draft.checkIn.checkInGroupId = Object.values(
        excel.CheckinTable.groups,
      ).find((t) =>
        checkBetween(now(), t.signStartTime, t.signEndTime),
      )!.groupId;
      draft.checkIn.checkInHistory = [];
      draft.checkIn.checkInRewardIndex = -1;
    });
  }

  async checkIn(): Promise<{
    signInRewards: ItemBundle[];
    subscriptionRewards: ItemBundle[];
  }> {
    return (await this._player.update(async (draft) => {
      const signInRewards: ItemBundle[] = [];
      const subscriptionRewards: ItemBundle[] = [];
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
      const { monthlySubscriptionStartTime, monthlySubscriptionEndTime } =
        draft.status;
      if (
        checkBetween(
          now(),
          monthlySubscriptionStartTime,
          monthlySubscriptionEndTime,
        )
      ) {
        const currentMonthlySubId = excel.CheckinTable.currentMonthlySubId;
        subscriptionRewards.push(
          ...excel.CheckinTable.monthlySubItem[currentMonthlySubId][1].items,
        );
      }
      draft.checkIn.checkInHistory.push(0);
      await this._trigger.emit("items:get", [
        subscriptionRewards.concat(signInRewards),
      ]);
      return { signInRewards, subscriptionRewards };
    }))!;
  }
}
