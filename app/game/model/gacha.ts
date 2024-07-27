import { ItemBundle } from "../../excel/character_table"

export interface GachaResult{
    charInstId:number
    charId:string
    isNew:number
    itemGet:ItemBundle[]
    potent?:{
        delta:number
        now:number
    }
}
export interface GachaDetailTable {
    details: { [key: string]: GachaDetailData };
}

export interface GachaDetailData {
    gachaObjGroups:       GachaObjGroup[] | null;
    availCharInfo:        GachaAvailChar;
    upCharInfo:           GachaUpChar | null;
    limitedChar:          string[] | null;
    weightUpCharInfoList: GachaWeightUpChar[] | null;
    gachaObjList:         GachaObject[];
}

export interface GachaAvailChar {
    perAvailList: GachaPerAvail[];
}

export interface GachaPerAvail {
    rarityRank:   number;
    charIdList:   string[];
    totalPercent: number;
}

export interface GachaObjGroup {
    groupType:  number;
    startIndex: number;
    endIndex:   number;
}

export interface GachaObject {
    gachaObject: string;
    type:        number;
    imageType:   number;
    param:       null | string;
}

export interface GachaUpChar {
    perCharList: GachaPerChar[];
}

export interface GachaPerChar {
    rarityRank: number;
    charIdList: string[];
    percent:    number;
    count:      number;
}

export interface GachaWeightUpChar {
    rarityRank: number;
    charId:     string;
    weight:     number;
}
