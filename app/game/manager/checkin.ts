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
      // 防御：当前时间无匹配签到组（数据缺失/时间跨度断档）时保持原组，不 500
      const group = Object.values(excel.CheckinTable.groups).find((t) =>
        checkBetween(now(), t.signStartTime, t.signEndTime),
      );
      if (!group) {
        return;
      }
      draft.checkIn.checkInGroupId = group.groupId;
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
      const groupItems =
        excel.CheckinTable.groups[draft.checkIn.checkInGroupId]?.items ?? [];
      // 修复：奖励索引越界（组内物品数少于连续签到天数）时钳制到末位，不 500
      const idx = Math.min(
        draft.checkIn.checkInRewardIndex,
        groupItems.length - 1,
      );
      const item = groupItems[idx];
      if (!item) {
        return;
      }
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
