import EventEmitter from "events";
import { PlayerStoryReview } from "../model/playerdata";
import excel from "../../excel/excel";
import { now } from "@utils/time";

export class StoryreviewManager {
    storyreview:PlayerStoryReview
    _trigger:EventEmitter
    constructor(storyreview:PlayerStoryReview,_trigger:EventEmitter) {
        this.storyreview = storyreview
        this._trigger = _trigger

    }
    unlockStoryByCoin(storyId:string){

        this._trigger.emit("useItems",[{id:"STORY_REVIEW_COIN",count:1}])
    }
    readStory(storyId:string){
        this.storyreview.groups[storyId].stories.find(story=>story.id==storyId)!.rc+=1
    }
    rewardGroup(groupId:string){
        this.storyreview.groups[groupId].rts=now()
    }
    markStoryAcceKnown(){
        this.storyreview.tags["knownStoryAcceleration"]=1
    }
    trailReward(groupId:string,rewardIdList:string[]){
        let rewardList=excel.StoryReviewMetaTable.miniActTrialData.miniActTrialDataMap[groupId].rewardList.filter((reward)=>reward.trialRewardId in rewardIdList)
        let items=rewardList.map(reward=>reward.item)
        //TODO
        this._trigger.emit("gainItems",items)
        this.storyreview.groups[groupId].trailRewards?.concat(rewardIdList)

    }
    toJSON() {
        return this.storyreview
    }
}