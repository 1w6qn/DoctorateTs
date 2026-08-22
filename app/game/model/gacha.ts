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
 * （参考 OBS bp_gacha.GACHA_RULE_TYPE_DICT；gacha 路由、抽卡控制器与管理后台共用）
 *
 * 补齐中坚甄选/回归/特殊等自选池的映射——此前这些规则类型未收录，
 * choosePoolUp 会把玩家自选 UP 误回落写入 "single"，导致自选既不落盘在
 * 正确子结构、抽卡时也读不到（自选形同虚设）。键名对齐
 * app/excel/types-playerdata.ts 的 PlayerGacha 字段（fesClassic/special/backflow/doubleGacha）。
 */
export const GACHA_RULE_TYPE: { [rule: string]: string } = {
    NORMAL: "normal",
    ATTAIN: "attain",
    LIMITED: "limit",
    SINGLE: "single",
    CLASSIC: "classic",
    CLASSIC_ATTAIN: "classic",
    CLASSIC_DOUBLE: "doubleGacha",
    FESCLASSIC: "fesClassic",
    SPECIAL: "special",
    BACKFLOW: "backflow",
    DOUBLE: "double",
    NEWBEE: "newbee",
    LINKAGE: "linkage",
};
