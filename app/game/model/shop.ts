import { ItemBundle } from "app/excel/character_table";

export interface QCObject {
    goodId: string;
    item: ItemBundle;
    progressGoodId: string;
    displayName: string;
    slotId: number;
    originPrice: number;
    price: number;
    availCount: number;
    discount: number;
    priority: number;
    number: number;
    groupId: string;
    goodStartTime: number;
    goodEndTime: number;
    goodType: string;
}

export interface LowGoodList{
    goodList: QCObject[];
    groups:string[];
    shopEndTime:number;
    newFlag:string[]

}
export interface SkinGoodList{
    goodList: ShopSkinItemViewModel[];
    
}
export interface ShopSkinItemViewModel {
    goodId:        string;
    skinId:        string;
    skinName:      string;
    charId:        string;
    currencyUnit:  string;
    originPrice:   number;
    price:         number;
    discount:      number;
    desc1:         null|string;
    desc2:         null|string;
    startDateTime: number;
    endDateTime:   number;
    slotId:        number;
    isRedeem : boolean;
}
export interface CashGoodList{
    goodList: CashShopObject[];
    
}
export interface CashShopObject {
    goodId: string
    slotId: number
    price: number
    diamondNum: number
    doubleCount: number
    plusNum: number
    desc: string
}