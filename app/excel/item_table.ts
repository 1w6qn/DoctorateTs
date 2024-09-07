import { ItemBundle } from "./character_table";

export interface ServerItemTable {
    items: { [key: string]: ItemData };
    expItems: { [key: string]: ExpItemFeature };
    potentialItems: { [key: string]: { [key: string]: string } };
    apSupplies: { [key: string]: ApSupplyFeature };
    charVoucherItems: { [key: string]: CharVoucherItem };
    uniqueInfo: { [key: string]: number };
    itemTimeLimit: { [key: string]: number };
    uniCollectionInfo: { [key: string]: UniCollectionInfo };
    itemPackInfos: { [key: string]: ItemPackInfo };
    fullPotentialCharacters: { [key: string]: FullPotentialCharacterInfo };
    activityPotentialCharacters: { [key: string]: ActivityPotentialCharacterInfo };
    favorCharacters: { [key: string]: FavorCharacterInfo };
}


export interface ActivityPotentialCharacterInfo {
    charId: string;
}

export interface ApSupplyFeature {
    id: string;
    ap: number;
    hasTs: boolean;
}

export interface CharVoucherItem {
    id: string;
    displayType: string;//DisplayType;
}

export type DisplayType = "NONE" | "DIVIDE";

export interface ExpItemFeature {
    id: string;
    gainExp: number;
}



export interface FavorCharacterInfo {
    itemId: string;
    charId: string;
    favorAddAmt: number;
}

export interface FullPotentialCharacterInfo {
    itemId: string;
    ts: number;
}

export interface ItemPackInfo {
    packId: string;
    content: ItemBundle[];
}

export interface ItemData {
    itemId: string;
    name: string;
    description: null | string;
    rarity: string;//ItemRarity;
    iconId: string;
    overrideBkg: null|string;
    stackIconId: null | string;
    sortId: number;
    usage: null | string;
    obtainApproach: null | string;
    hideInItemGet: boolean;
    classifyType: string;//ItemClassifyType;
    itemType: number | string;
    stageDropList: ItemData.StageDropInfo[];
    buildingProductList: ItemData.BuildingProductInfo[];
    voucherRelateList: ItemData.VoucherRelateInfo[] | null;
}
export namespace ItemData {
    export interface BuildingProductInfo {
        roomType: string;//BuildingData.RoomType
        formulaId: string;
    }
    export interface VoucherRelateInfo {
        voucherId: string;
        voucherItemType: string;//ItemType
    }
    export interface StageDropInfo {
        stageId: string;
        occPer: string;//OccPer;
    }
}


export type ItemClassifyType = "MATERIAL" | "NORMAL" | "NONE" | "CONSUME";

export type ItemRarity = "TIER_2" | "TIER_3" | "TIER_4" | "TIER_5" | "TIER_6" | "TIER_1";



export type OccPer = "ALWAYS" | "USUAL" | "ALMOST" | "OFTEN" | "SOMETIMES";


export interface UniCollectionInfo {
    uniCollectionItemId: string;
    uniqueItem: ItemBundle[];
}
