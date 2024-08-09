import { ItemBundle } from "./character_table";
import { MissionData, MissionGroup } from "./mission_table";

export interface OpenServerSchedule {
    schedule:                 OpenServerScheduleItem[];
    dataMap:                  {[key: string]:OpenServerData};
    constant:                 OpenServerConst;
    playerReturn:             ReturnData;
    playerReturnV2:           ReturnV2Data;
    newbieCheckInPackageList: NewbieCheckInPackageData[];
}

export interface OpenServerConst {
    firstDiamondShardMailCount:     number;
    initApMailEndTs:                number;
    resFullOpenUnlockStageId:       string;
    resFullOpenDuration:            number;
    resFullOpenTitle:               string;
    resFullOpenDesc:                string;
    resFullOpenGuideGroupThreshold: string;
    resFullOpenStartTime:           number;
}



export interface OpenServerData {
    openServerMissionGroup: MissionGroup;
    openServerMissionData:  MissionData[];
    checkInData:            TotalCheckinData[];
    chainLoginData:         ChainLoginData[];
    totalCheckinCharData:   string[];
    chainLoginCharData:     string[];
}

export interface TotalCheckinData {
    order:   number;
    item:    OpenServerItemData;
    colorId: number;
}
export type ChainLoginData=TotalCheckinData
export interface OpenServerItemData {
    itemId:   string;
    itemType: string;
    count:    number;
    name:     null | string;
}

export interface NewbieCheckInPackageData {
    groupId:            string;
    startTime:          number;
    endTime:            number;
    bindGPGoodId:       string;
    checkInDuration:   number;
    totalCheckInDay:    number;
    iconId:             string;
    checkInRewardDict: { [key: string]: NewbieCheckInPackageRewardData[] };
}
export interface ReturnV2PackageCheckInRewardData {
    groupId:            string;
    startTime:          number;
    endTime:            number;
    getTime:           number;
    bindGPGoodId:       string;
    iconId:             string;
    totalCheckInDay:    number;
    rewardDict:        { [key: string]: ReturnV2ItemData[] };
}
export interface ReturnV2ItemData extends ItemBundle{
    sortId: number;
}

export interface NewbieCheckInPackageRewardData {
    orderNum:   number;
    itemBundle: ItemBundle;
}

export interface ReturnData {
    constData:              ReturnConst;
    onceRewards:            ItemBundle[];
    intro:                  ReturnIntroData[];
    returnDailyTaskDic:     { [key: string]: ReturnDailyTaskData[] };
    returnLongTermTaskList: ReturnLongTermTaskData[];
    creditsList:            ItemBundle[];
    checkinRewardList:      ReturnCheckinData[];
}

export interface ReturnCheckinData {
    isImportant:        boolean;
    checkinRewardItems: ItemBundle[];
}

export interface ReturnConst {
    startTime:        number;
    systemTab_time:   number;
    afkDays:          number;
    unlockLv:         number;
    unlockLevel:      string;
    juniorClear:      boolean;
    ifvisitor:        boolean;
    permMission_time: number;
    needPoints:       number;
    defaultIntro:     string;
    pointId:          string;
}

export interface ReturnIntroData {
    sort:    number;
    pubTime: number;
    image:   string;
}

export interface ReturnDailyTaskData {
    groupId:     string;
    id:          string;
    groupSortId: number;
    taskSortId:  number;
    template:    string;
    param:       string[];
    desc:        string;
    rewards:     ItemBundle[];
    playPoint:   number;
}

export interface ReturnLongTermTaskData {
    id:        string;
    sortId:    number;
    template:  string;
    param:     string[];
    desc:      string;
    rewards:   ItemBundle[];
    playPoint: number;
}

export interface ReturnV2Data {
    constData:                ReturnV2Const;
    onceRewardData:           ReturnV2OnceRewardData[];
    checkInRewardData:        ReturnV2CheckInRewardData[];
    priceRewardData:          ReturnV2PriceRewardGroupData[];
    missionGroupData:         ReturnV2MissionGroupData[];
    dailySupplyData:          ReturnV2DailySupplyData[];
    packageCheckInRewardData: ReturnV2PackageCheckInRewardData[];
}

export interface ReturnV2CheckInRewardData {
    groupId:      string;
    startTime:    number;
    endTime:      number;
    rewardList:  ReturnV2CheckInRewardItemData[];
}
export interface ReturnV2PriceRewardGroupData {
    groupId:      string;
    startTime:    number;
    endTime:      number;
    contentList: ReturnV2PriceRewardData[];
}
export interface ReturnV2PriceRewardData {
    contentId:    string;
    sortId:       number;
    pointRequire: number;
    desc:         string;
    iconId:       string;
    topIconId:    string;
    rewardList:   ReturnV2ItemData[];
}

export interface ReturnV2CheckInRewardItemData {
    sortId:      number;
    isImportant: boolean;
    rewardList:  ItemBundle[];
}

export interface ReturnV2Const {
    startTime:       number;
    unlockLv:        number;
    unlockStage:     string;
    permMissionTime: number;
    pointId:         string;
    returnPriceDesc: string;
    dailySupplyDesc: string;
}

export interface ReturnV2OnceRewardData {
    groupId:    string;
    startTime:  number;
    endTime:    number;
    rewardList: ReturnV2ItemData[];
}
export interface ReturnV2DailySupplyData {
    groupId:    string;
    startTime:  number;
    endTime:    number;
    rewardList: ItemBundle[];
}
export interface ReturnV2MissionGroupData {
    groupId:          string;
    sortId:           number;
    tabTitle:         string;
    title:            string;
    desc:             string;
    diffMissionCount: number;
    startTime:        number;
    endTime:          number;
    imageId:          string;
    iconId:           string;
    missionList:      ReturnV2MissionItemData[];
}

export interface ReturnV2MissionItemData {
    missionId:  string;
    groupId:    string;
    sortId:     number;
    jumpType:   string;
    jumpParam:  null | string;
    desc:       string;
    rewardList: ItemBundle[];
}
export interface OpenServerScheduleItem {
    id:                    string;
    versionId:             string;
    startTs:               number;
    endTs:                 number;
    totalCheckinDescption: string;
    chainLoginDescription: string;
    charImg:               string;
}
