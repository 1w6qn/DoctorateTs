import EventEmitter from "events";
import { PlayerStoryReview } from "../model/playerdata";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";

export class StoryreviewManager {
  storyreview: PlayerStoryReview;
  _trigger: EventEmitter;

  constructor(storyreview: PlayerStoryReview, _trigger: EventEmitter) {
    this.storyreview = storyreview;
    this._trigger = _trigger;
  }

  unlockStoryByCoin(args: { storyId: string }) {
    this.storyreview.groups[args.storyId].stories.push({
      id: args.storyId,
      uts: now(),
      rc: 0,
    });
    this._trigger.emit("useItems", [{ id: "STORY_REVIEW_COIN", count: 1 }]);
  }

  readStory(args: { storyId: string }) {
    this.storyreview.groups[args.storyId].stories.find(
      (story) => story.id == args.storyId,
    )!.rc += 1;
  }

  rewardGroup(args: { groupId: string }) {
    this.storyreview.groups[args.groupId].rts = now();
    const items = excel.StoryReviewTable[args.groupId].rewards;
    this._trigger.emit("gainItems", items);
    return items;
  }

  markStoryAcceKnown() {
    this.storyreview.tags.knownStoryAcceleration = 1;
  }

  trailReward(args: { groupId: string; rewardIdList: string[] }): ItemBundle[] {
    const group =
      excel.StoryReviewMetaTable.miniActTrialData.miniActTrialDataMap[
        args.groupId
      ];
    const rewardList = group.rewardList.filter((reward) =>
      args.rewardIdList.includes(reward.trialRewardId),
    );
    const items = rewardList.map((reward) => reward.item);
    this._trigger.emit("gainItems", items);
    this.storyreview.groups[args.groupId].trailRewards?.push(
      ...args.rewardIdList,
    );
    return items;
  }

  toJSON(): PlayerStoryReview {
    return this.storyreview;
  }
}
