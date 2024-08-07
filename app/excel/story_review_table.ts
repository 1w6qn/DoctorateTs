import { ItemBundle } from "./character_table";
import { StageCondition } from "./story_table";

export type StoryReviewTable = {[key: string]:StoryReviewGroupClientData}
export interface StoryReviewGroupClientData {
    id:                   string;
    name:                 string;
    entryType:            string;
    actType:              string;
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

export interface StoryReviewInfoClientData {
    storyReviewType: string;
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
    unLockType:      string;
    costItemType:    string;//ItemType;
    costItemId:      string | null;
    costItemCount:   number;
    stageCount:      number;
    requiredStages:  StageCondition[] | null;
}

