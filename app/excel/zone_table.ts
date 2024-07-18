import { ItemBundle } from "./character_table";
import { StageDiffGroup } from "./stage_table";

export interface ZoneTable {
    zones:                 { [key: string]: ZoneData };
    weeklyAdditionInfo:    { [key: string]: WeeklyZoneData };
    zoneValidInfo:         { [key: string]: ZoneValidInfo };
    mainlineAdditionInfo:  { [key: string]: MainlineZoneData };
    zoneRecordGroupedData: { [key: string]: ZoneRecordGroupData };
    zoneRecordRewardData:  { [key: string]: string[] };
    zoneMetaData:          ZoneMetaData;
}

export interface MainlineZoneData {
    zoneId:          string;
    chapterId:       string;
    preposedZoneId:  null | string;
    zoneIndex:       number;
    startStageId:    string;
    endStageId:      string;
    mainlneBgName:   string;
    recapId:         string;
    recapPreStageId: string;
    buttonName:      string;
    buttonStyle:     ZoneReplayBtnType;
    spoilAlert:      boolean;
    zoneOpenTime:    number;
    diffGroup:       StageDiffGroup[];
}

export enum ZoneReplayBtnType {
    None = "NONE",
    Recap = "RECAP",
    Replay = "REPLAY",
}


export interface WeeklyZoneData {
    daysOfWeek: number[];
    type:       string;
}

export interface ZoneMetaData {
    ZoneRecordMissionData: { [key: string]: ZoneRecordMissionData };
}

export interface ZoneRecordMissionData {
    missionId:     string;
    recordStageId: string;
    templateDesc:  string;
    desc:          string;
}



export interface ZoneRecordGroupData {
    zoneId:     string;
    records:    ZoneRecordData[];
    unlockData: ZoneRecordUnlockData;
}

export interface ZoneRecordData {
    recordId:        string;
    zoneId:          string;
    recordTitleName: string;
    preRecordId:     null | string;
    nodeTitle1:      null | string;
    nodeTitle2:      null | string;
    rewards:         RecordRewardInfo[];
}

export interface RecordRewardInfo {
    bindStageId:  string;
    stageDiff1:   string;//RecordRewardStageDiff
    stageDiff:    StageDiffGroup;
    picRes:       null | string;
    textPath:     null | string;
    textDesc:     null | string;
    recordReward: ItemBundle[] | null;
}


export interface ZoneRecordUnlockData {
    noteId:            string;
    zoneId:            string;
    initialName:       string;
    finalName:         null | string;
    accordingExposeId: null | string;
    initialDes:        string;
    finalDes:          null | string;
    remindDes:         null | string;
}



export interface ZoneValidInfo {
    startTs: number;
    endTs:   number;
}

export interface ZoneData {
    zoneID:                 string;
    zoneIndex:              number;
    type:                   ZoneType;
    zoneNameFirst:          null | string;
    zoneNameSecond:         null | string;
    zoneNameTitleCurrent:   null | string;
    zoneNameTitleUnCurrent: null | string;
    zoneNameTitleEx:        string | null;
    zoneNameThird:          null | string;
    lockedText:             string | null;
    canPreview:             boolean;
    hasAdditionalPanel:     boolean;
}


export enum ZoneType {
    Activity = "ACTIVITY",
    Branchline = "BRANCHLINE",
    Campaign = "CAMPAIGN",
    ClimbTower = "CLIMB_TOWER",
    Guide = "GUIDE",
    Mainline = "MAINLINE",
    Roguelike = "ROGUELIKE",
    Sidestory = "SIDESTORY",
    Weekly = "WEEKLY",
}
