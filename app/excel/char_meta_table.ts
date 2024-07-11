import { ItemBundle } from "./character_table";

export interface CharMetaTable {
    spCharGroups:          { [key: string]: string[] };
    spCharMissions:        { [key: string]: { [key: string]: SpCharMissionData } };
    spCharVoucherSkinTime: { [key: string]: number };
}



export interface SpCharMissionData {
    charId:    string;
    missionId: string;
    sortId:    number;
    condType:  string;
    param:     string[];
    rewards:   ItemBundle[];
}