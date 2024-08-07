import EventEmitter from "events";
import { PlayerStoryReview } from "../model/playerdata";
import excel from "../../excel/excel";
import { now } from "@utils/time";
import { ItemBundle } from "@excel/character_table";

export class StoryreviewManager {
    storyreview:PlayerStoryReview
    _trigger:EventEmitter
    constructor(storyreview:PlayerStoryReview,_trigger:EventEmitter) {
        this.storyreview = storyreview
        this._trigger = _trigger

    }
    unlockStoryByCoin(args:{storyId:string}){
        this.storyreview.groups[args.storyId].stories.push({
            id:args.storyId,
            uts:now(),
            rc:0
        })
        this._trigger.emit("useItems",[{id:"STORY_REVIEW_COIN",count:1}])
    }
    readStory(args:{storyId:string}){
        this.storyreview.groups[args.storyId].stories.find(story=>story.id==args.storyId)!.rc+=1
    }
    rewardGroup(args:{groupId:string}){
        this.storyreview.groups[args.groupId].rts=now()
        let items=excel.StoryReviewTable[args.groupId].rewards
        this._trigger.emit("gainItems",items)
        return items
    }
    markStoryAcceKnown(){
        this.storyreview.tags["knownStoryAcceleration"]=1
    }
    trailReward(args:{groupId:string,rewardIdList:string[]}):ItemBundle[]{
        let group=excel.StoryReviewMetaTable.miniActTrialData.miniActTrialDataMap[args.groupId]
        let rewardList=group.rewardList.filter((reward)=>args.rewardIdList.includes(reward.trialRewardId))                
        let items=rewardList.map(reward=>reward.item)
        this._trigger.emit("gainItems",items)
        this.storyreview.groups[args.groupId].trailRewards?.push(...args.rewardIdList)
        return items
    }
    toJSON() {
        return this.storyreview
    }
}