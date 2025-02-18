import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class StoryreviewManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  async unlockStoryByCoin(args: { storyId: string }) {
    await this._player.update(async (draft) => {
      const { storyId } = args;
      draft.storyreview.groups[storyId].stories.push({
        id: storyId,
        uts: now(),
        rc: 0,
      });
      await this._trigger.emit("items:use", [
        [{ id: "STORY_REVIEW_COIN", count: 1 }],
      ]);
    });
  }

  async readStory(args: { storyId: string }) {
    await this._player.update(async (draft) => {
      const { storyId } = args;
      draft.storyreview.groups[storyId].stories.find(
        (story) => story.id == storyId,
      )!.rc += 1;
    });
  }

  async rewardGroup(args: { groupId: string }) {
    return await this._player.update(async (draft) => {
      const { groupId } = args;
      draft.storyreview.groups[groupId].rts = now();
      const items = excel.StoryReviewTable[groupId].rewards!;
      await this._trigger.emit("items:get", [items]);
      return items;
    });
  }

  async markStoryAcceKnown() {
    await this._player.update(async (draft) => {
      draft.storyreview.tags.knownStoryAcceleration = 1;
    });
  }

  async trailReward(args: {
    groupId: string;
    rewardIdList: string[];
  }): Promise<ItemBundle[]> {
    return await this._player.update(async (draft) => {
      const { groupId, rewardIdList } = args;
      const group =
        excel.StoryReviewMetaTable.miniActTrialData.miniActTrialDataMap[
          groupId
        ];
      const rewardList = group.rewardList.filter((reward) =>
        rewardIdList.includes(reward.trialRewardId),
      );
      const items = rewardList.map((reward) => reward.item);
      await this._trigger.emit("items:get", [items]);
      draft.storyreview.groups[groupId].trailRewards?.push(...rewardIdList);
      return items;
    });
  }
}
