import { ItemBundle } from "./character_table";

export interface MedalData {
    medalList:     MedalPerData[];
    medalTypeData: {[key:string]:MedalTypeData};
}

export interface MedalPerData {
    medalId:          string;
    medalName:        string;
    medalType:        string;
    slotId:           number;
    preMedalIdList:   string[] | null;
    rarity:           string;
    template:         null | string;
    unlockParam:      string[];
    getMethod:        null | string;
    description:      null | string;
    advancedMedal:    null | string;
    originMedal:      null | string;
    displayTime:      number;
    expireTimes:      MedalExpireTime[];
    medalRewardGroup: MedalRewardGroupData[];
    isHidden:         boolean;
}

export interface MedalExpireTime {
    start: number;
    end:   number;
    type:  string;
}

export interface MedalRewardGroupData {
    groupId:  string;
    slotId:   number;
    itemList: ItemBundle[];
}


export interface MedalTypeData {
    medalGroupId: string;
    sortId:       number;
    medalName:    string;
    groupData:    MedalGroupData[];
}

export interface MedalGroupData {
    groupId:           string;
    groupName:         string;
    groupDesc:         string;
    medalId:           string[];
    sortId:            number;
    groupBackColor:    string;
    groupGetTime:      number;
    sharedExpireTimes: MedalExpireTime[] | null;
}
