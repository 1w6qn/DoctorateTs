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