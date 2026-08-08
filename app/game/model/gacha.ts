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

/**
 * gachaRuleType → 玩家数据 gacha 子结构名
 * （参考 OBS bp_gacha.GACHA_RULE_TYPE_DICT；gacha 路由与管理后台共用）
 */
export const GACHA_RULE_TYPE: { [rule: string]: string } = {
    NORMAL: "normal",
    ATTAIN: "attain",
    LIMITED: "limit",
    SINGLE: "single",
    CLASSIC: "classic",
    DOUBLE: "double",
    NEWBEE: "newbee",
    LINKAGE: "linkage",
};
