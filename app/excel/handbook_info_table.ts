import { ItemBundle } from "./character_table";

export interface HandbookInfoTable {
    handbookDict:                 { [key: string]: HandbookInfoData };
    npcDict:                      { [key: string]: NPCData };
    teamMissionList:              { [key: string]: HandbookTeamMission };
    handbookDisplayConditionList: { [key: string]: HandbookDisplayCondition };
    handbookStageData:            { [key: string]: HandbookStoryStageData };
    handbookStageTime:            HandbookStageTimeData[];
}

export interface HandbookInfoData {
    charID:          string;
    infoName:        string;
    isLimited:       boolean;
    storyTextAudio:  HandBookStoryViewData[];
    handbookAvgList: HandbookAvgGroupData[];
}

export interface HandbookAvgGroupData {
    storySetId:   string;
    storySetName: string;
    sortId:       number;
    storyGetTime: number;
    rewardItem:   ItemBundle[];
    unlockParam:  HandbookUnlockParam[];
    avgList:      HandbookAvgData[];
    charId:       string;
}

export interface HandbookAvgData {
    storyId:      string;
    storySetId:   string;
    storySort:    number;
    storyCanShow: boolean;
    storyIntro:   string;
    storyInfo:    string;
    storyTxt:     string;
}

export interface HandbookUnlockParam {
    unlockType:   string;
    unlockParam1: string;
    unlockParam2: null | string;
    unlockParam3: null|string;
}


export interface HandBookStoryViewData {
    stories:     HandBookStoryViewData.StoryText[];
    storyTitle:  string;
    unLockorNot: boolean;
}
export namespace HandBookStoryViewData {
export interface StoryText {
    storyText:    string;
    unLockType:   string;
    unLockParam:  string;
    unLockString: string;
    patchIdList:  string[] | null;
}
}

export interface HandbookDisplayCondition {
    charId:          string;
    conditionCharId: string;
    type:            string;
}

export interface HandbookStoryStageData {
  charId: string;
  stageId: string;
  levelId: string;
  zoneId: string;
  code: string;
  name: string;
  loadingPicId: string;
  description: string;
  unlockParam: HandbookUnlockParam[];
  rewardItem: ItemBundle[];
  stageNameForShow?: string;
  zoneNameForShow?: string;
  picId?: string;
  stageGetTime: number;
}



export interface HandbookStageTimeData {
    timestamp: number;
    charSet:   string[];
}

export interface NPCData {
    npcId:                string;
    name:                 string;
    appellation:          string;
    profession:           string;
    illustList:           string[];
    designerList:         null;
    cv:                   string;
    displayNumber:        string;
    nationId:             string;
    groupId:              null | string;
    teamId:               null;
    resType:              string;
    npcShowAudioInfoFlag: boolean;
    unlockDict:           {[key: string]: NPCUnlock};
}
export interface NPCUnlock {
    unLockType:   string;
    unLockParam:  string;
    unLockString: null;
}

export interface HandbookTeamMission {
    id:         string;
    sort:       number;
    powerId:    string;
    powerName:  string;
    item:       ItemBundle;
    favorPoint: number;
}
