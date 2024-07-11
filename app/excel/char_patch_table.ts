import { CharacterData } from "./character_table";

export interface CharPatchTable {
    infos:               { [key: string]: PatchInfo };
    patchChars:          { [key: string]: CharacterData };
    unlockConds:         { [key: string]: UnlockCond };
    patchDetailInfoList: { [key: string]: PatchDetailInfo };
}

export interface PatchInfo {
    tmplIds: string[];
    default: string;
}


export interface PatchDetailInfo {
    patchId:     string;
    sortId:      number;
    infoParam:   string;
    transSortId: number;
}



export interface UnlockCond {
    conds: Item[];
}

export interface Item {
    stageId:       string;
    completeState: string;
    unlockTs:      number;
}
