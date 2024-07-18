import { ItemBundle } from "./character_table";
import { StageCondition } from "./story_table";

export type StoryTable = {[key: string]:StoryReviewGroupClientData}
export interface StoryReviewGroupClientData {
    id:                   string;
    name:                 string;
    entryType:            StoryReviewEntryType;
    actType:              StoryReviewType;
    startTime:            number;
    endTime:              number;
    startShowTime:        number;
    endShowTime:          number;
    remakeStartTime:      number;
    remakeEndTime:        number;
    storyEntryPicId:      null | string;
    storyPicId:           null | string;
    storyMainColor:       null | string;
    customType:           number;
    storyCompleteMedalId: null | string;
    rewards:              ItemBundle[] | null;
    infoUnlockDatas:      StoryReviewInfoClientData[];
}

export enum StoryReviewType {
    ActivityStory = "ACTIVITY_STORY",
    MainStory = "MAIN_STORY",
    MiniStory = "MINI_STORY",
    None = "NONE",
}

export enum StoryReviewEntryType {
    Activity = "ACTIVITY",
    Mainline = "MAINLINE",
    MiniActivity = "MINI_ACTIVITY",
    None = "NONE",
}

export interface StoryReviewInfoClientData {
    storyReviewType: StoryReviewType;
    storyId:         string;
    storyGroup:      string;
    storySort:       number;
    storyDependence: null | string;
    storyCanShow:    number;
    storyCode:       null | string;
    storyName:       string;
    storyPic:        null | string;
    storyInfo:       null | string;
    storyCanEnter:   number;
    storyTxt:        string;
    avgTag:          string;
    unLockType:      StoryReviewUnlockType;
    costItemType:    string;//ItemType;
    costItemId:      string | null;
    costItemCount:   number;
    stageCount:      number;
    requiredStages:  StageCondition[] | null;
}




export enum StoryReviewUnlockType {
    StageClear = "STAGE_CLEAR",
    UseItem = "USE_ITEM",
}

