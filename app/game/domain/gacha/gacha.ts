import { ItemBundle } from "@excel/character_table"
import { randomChoices } from "@utils/random";
import { random } from "../util/random";

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

/**
 * 保底稀有度解析（纯函数，可注入随机源）
 *
 * 从抽卡详情与玩家保底状态计算本次抽取的稀有度下标（5=六星，4=五星）：
 * - 六星权重修正：非六星连续计数超过 50 后每抽 +2%（per6 = base + max(0, cnt-50) * 0.02）；
 * - 五星一次性保底：累计抽数恰达 maxCnt（默认 10）且未抽到五星及以上时强制升 4，
 *   只触发一次（计数器只增不减，无窗口回绕）。
 *
 * 由 GachaManager._getRarityRank 拆分而来：原实现把概率计算与 playerdata 写入
 * 混在一起，无法独立测试；此函数保持纯计算，写回仍由调用方负责。
 *
 * @param params.per6Base - 六星基础权重（totalPercent，缺省按 2）
 * @param params.beforeNonHitCnt - 抽前非六星连续计数（保底权重修正用）
 * @param params.nextCnt - 本次抽完后的累计抽数（五星保底点判断用）
 * @param params.maxCnt - 五星一次性保底点（缺省 10）
 * @param params.ranks - 详情稀有度列表（与 weights 等长）
 * @param params.weights - 详情权重列表（totalPercent）
 * @param params.rand - 随机源（默认 random；测试可注入固定值）
 * @returns 稀有度下标
 */
export function resolveGachaRank(params: {
    per6Base: number;
    beforeNonHitCnt: number;
    nextCnt: number;
    maxCnt?: number;
    ranks: number[];
    weights: number[];
    rand?: () => number;
}): number {
    const { per6Base, beforeNonHitCnt, nextCnt, ranks, weights } = params;
    const maxCnt = params.maxCnt ?? 10;
    const rand = params.rand ?? random;
    let per6 = per6Base;
    per6 += beforeNonHitCnt < 50 ? 0 : (beforeNonHitCnt - 50) * 0.02;
    // 一次性保底点：恰好第 maxCnt 抽强制五星
    const atGuarantee = nextCnt === maxCnt;
    if (rand() <= per6) {
        return 5;
    }
    const picked = randomChoices(ranks, weights, 1)[0];
    if (picked < 4 && atGuarantee) {
        return 4;
    }
    return picked;
}
