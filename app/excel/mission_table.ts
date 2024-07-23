import { ItemBundle } from "./character_table";

export interface MissionTable {
    missions:                  { [key: string]: MissionData };
    missionGroups:             { [key: string]: MissionGroup };
    periodicalRewards:         { [key: string]: MissionDailyRewardConf };
    weeklyRewards:             { [key: string]: MissionWeeklyRewardConf };
    dailyMissionGroupInfo:     {};
    dailyMissionPeriodInfo:    DailyMissionGroupInfo[];
    crossAppShareMissions:     { [key: string]: CrossAppShareMission };
    crossAppShareMissionConst: CrossAppShareMissionConst;
}

export interface CrossAppShareMissionConst {
    nameCardShareMissionId: string;
}


export interface CrossAppShareMission {
    shareMissionId:   string;
    missionType:      string;
    relateActivityId: null | string;
    startTime:        number;
    endTime:          number;
    limitCount:       number;
    condTemplate:     null;
    condParam:        any[];
    rewardsList:      null;
}



export interface DailyMissionGroupInfo {
    startTime:  number;
    endTime:    number;
    tagState:   null;
    periodList: PeriodInfo[];
}

export interface PeriodInfo {
    missionGroupId: string;
    rewardGroupId:  string;
    period:         number[];
}


export interface MissionGroup {
    id:              string;
    title:           null | string;
    type:            string;
    preMissionGroup: null | string;
    period:          null;
    rewards:         ItemBundle[] | null;
    missionIds:      string[];
    startTs:         number;
    endTs:           number;
}



export interface MissionData {
    id:                     string;
    sortId:                 number;
    description:            string;
    type:                   string;
    itemBgType:             string;
    preMissionIds:          string[] | null;
    template:               string;
    templateType:           string;
    param:                  string[];
    unlockCondition:        string | null;
    unlockParam:            string[] | null;
    missionGroup:           string;
    toPage:                 null;
    periodicalPoint:        number;
    rewards:                ItemBundle[] | null;
    backImagePath:          null | string;
    foldId:                 null | string;
    haveSubMissionToUnlock: boolean;
}


export interface MissionDailyRewardConf {
    groupId:             string;
    id:                  string;
    periodicalPointCost: number;
    type:                string;
    sortIndex:           number;
    rewards:             ItemBundle[];
    beginTime?:          number;
    endTime?:            number;
}
export interface MissionWeeklyRewardConf {
    groupId:             string;
    id:                  string;
    periodicalPointCost: number;
    type:                string;
    sortIndex:           number;
    rewards:             ItemBundle[];
    beginTime?:          number;
    endTime?:            number;
}