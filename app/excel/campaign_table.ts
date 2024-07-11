import { ItemBundle } from "./character_table";
import { DisplayDetailRewards, DisplayRewards } from "./stage_table";

export interface CampaignTable {
    campaigns:                      { [key: string]: CampaignData };
    campaignGroups:                 { [key: string]: CampaignGroupData };
    campaignRegions:                { [key: string]: CampaignRegionData };
    campaignZones:                  { [key: string]: CampaignZoneData };
    campaignMissions:               { [key: string]: CampaignMissionData };
    stageIndexInZoneMap:            { [key: string]: number };
    campaignConstTable:             CampaignConstTable;
    campaignRotateStageOpenTimes:   CampaignRotateOpenTimeData[];
    campaignTrainingStageOpenTimes: CampaignTrainingOpenTimeData[];
    campaignTrainingAllOpenTimes:   CampaignTrainingAllOpenTimeData[];
}

export interface CampaignConstTable {
    systemPreposedStage: string;
    rotateStartTime:     number;
    rotatePreposedStage: string;
    zoneUnlockStage:     string;
    firstRotateRegion:   string;
    sweepStartTime:      number;
}

export interface CampaignTrainingOpenTimeData {
    groupId:      string;
    startTs:      number;
    endTs:        number;
    stages:      string[];
}
export interface CampaignTrainingAllOpenTimeData {
    groupId:      string;
    startTs:      number;
    endTs:        number;
}
export interface CampaignGroupData {
    groupId:      string;
    activeCamps: string[];
    startTs:      number;
    endTs:        number;
}


export interface CampaignMissionData {
    id:          string;
    sortId:      number;
    param:       string[];
    description: string;
    breakFeeAdd: number;
}

export interface CampaignRegionData {
    id:        string;
    isUnknwon: number;
}

export interface CampaignRotateOpenTimeData {
    groupId:        string;
    stageId:        string;
    mapId:          string;
    unknownRegions: string[];
    duration:       number;
    startTs:        number;
    endTs:          number;
}

export interface CampaignZoneData {
    id:         string;
    name:       string;
    regionId:   string;
    templateId: string;
}

export interface CampaignData {
    stageId:      string;
    isSmallScale: number;
    breakLadders: BreakRewardLadder[];
    isCustomized: boolean;
    dropGains:    { [key: string]: DropGainInfo };
}

export interface BreakRewardLadder {
    killCnt:     number;
    breakFeeAdd: number;
    rewards:     ItemBundle[];
}

export interface DropGainInfo {
    dropLadders:          DropLadder[];
    gainLadders:          GainLadder[];
    displayRewards:       DisplayRewards[];
    displayDetailRewards: DisplayDetailRewards[];
}




export interface DropLadder {
    killCnt:  number;
    dropInfo: CampaignDropInfo;
}

export interface CampaignDropInfo {
    firstPassRewards:     null;
    passRewards:          null;
    displayDetailRewards: null;
}

export interface GainLadder {
    killCnt:              number;
    apFailReturn:         number;
    favor:                number;
    expGain:              number;
    goldGain:             number;
    displayDiamondShdNum: number;
}
