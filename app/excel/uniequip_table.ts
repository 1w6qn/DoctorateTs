import { ItemBundle } from "./character_table";

export interface UniEquipTable {
    equipDict:      { [key: string]: UniEquipData };
    missionList:    { [key: string]: UniEquipMissionData };
    subProfDict:    { [key: string]: SubProfessionData };
    charEquip:      { [key: string]: string[] };
    equipTrackDict: UniEquipTimeInfo[];
}

export interface UniEquipData {
    uniEquipId:        string;
    uniEquipName:      string;
    uniEquipIcon:      string;
    uniEquipDesc:      string;
    typeIcon:          string;
    typeName1:         string;
    typeName2:         string | null;
    equipShiningColor: string;
    showEvolvePhase:   string;//EvolvePhase
    unlockEvolvePhase: string;//EvolvePhase
    charId:            string;
    tmplId:            null | string;
    showLevel:         number;
    unlockLevel:       number;
    unlockFavorPoint?:  number;
    missionList:       string[];
    itemCost:          { [key: string]: ItemBundle[] } | null;
    type:              string;//UniEquipType;
    uniEquipGetTime:   number;
    charEquipOrder:    number;
}




export interface UniEquipTimeInfo {
    timeStamp: number;
    trackList: UniEquipTrack[];
}

export interface UniEquipTrack {
    charId:  string;
    equipId: string;
}

export interface UniEquipMissionData {
    template:            string;
    desc:                string;
    paramList:           string[];
    uniEquipMissionId:   string;
    uniEquipMissionSort: number;
    uniEquipId:          string;
    jumpStageId:         null | string;
}

export interface SubProfessionData {
    subProfessionId:       string;
    subProfessionName:     string;
    subProfessionCatagory: number;
}
