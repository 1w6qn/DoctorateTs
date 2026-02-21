import { ItemBundle } from "@excel/character_table"

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
export enum GachaType {
    None = 4294967295,
    Diamond = 0,
    SingleTicket = 1,
    TenTicket = 2,
    LimitSingle = 3,
    UseItem = 4,
    TenSingleTkt = 5,
    ClassicSingleTicket = 6,
    ClassicTenTicket = 7,
    classicTenSingleTicket = 8,
    CombineTenTicket = 9
}
