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