import { ItemBundle } from "./character_table";

export interface GachaData {
    gachaPoolClient: GachaPoolClientData[];
    newbeeGachaPoolClient: NewbeeGachaPoolClientData[];
    specialRecruitPool: any[];//SpecialRecruitPool[];
    gachaTags: GachaTag[];
    recruitPool: RecruitPool;
    potentialMaterialConverter: PotentialMaterialConverterConfig;
    classicPotentialMaterialConverter: PotentialMaterialConverterConfig;
    recruitRarityTable: { [key: string]: GachaData.RecruitRange };
    specialTagRarityTable: { [key: string]: number[] };
    recruitDetail: string;
    carousel: GachaData.CarouselData[];
    freeGacha: GachaData.FreeLimitGachaData[];
    limitTenGachaItem: GachaData.LimitTenGachaTkt[];
    linkageTenGachaItem: GachaData.LinkageTenGachaTkt[];
    normalGachaItem: GachaData.NormalGachaTkt[];
    fesGachaPoolRelateItem: { [key: string]: GachaData.FesGachaPoolRelateItem };
    dicRecruit6StarHint: { [key: string]: string };
}



export interface PotentialMaterialConverterConfig {
    items: { [key: string]: ItemBundle };
}



export interface GachaPoolClientData {
    gachaPoolId: string;
    gachaIndex: number;
    openTime: number;
    endTime: number;
    gachaPoolName: string;
    gachaPoolSummary: string;
    gachaPoolDetail: null | string;
    guarantee5Avail: number;
    guarantee5Count: number;
    LMTGSID: null | string;
    CDPrimColor: null | string;
    CDSecColor: null | string;
    freeBackColor: null | string;
    gachaRuleType: string;
    dynMeta: DynMeta | null;
    linkageRuleId: null | string;
    linkageParam: DynMeta | null;
    limitParam: DynMeta | null;
}

export interface DynMeta {
    base64?: string;
}

export interface GachaTag {
    tagId: number;
    tagName: string;
    tagGroup: number;
}




export interface NewbeeGachaPoolClientData {
    gachaPoolId: string;
    gachaIndex: number;
    gachaPoolName: string;
    gachaPoolDetail: string;
    gachaPrice: number;
    gachaTimes: number;
    gachaOffset: string;
}
export interface BaseRecruitPool {
    recruitConstants: BaseRecruitPool.RecruitConstants;
}
export namespace BaseRecruitPool {
    export interface RecruitConstants {
        tagPriceList: { [key: string]: number };
        maxRecruitTime: number;
    }
}
export interface RecruitPool extends BaseRecruitPool {
    recruitTimeTable: RecruitPool.RecruitTime[];
}

export namespace RecruitPool {

    export interface RecruitTime {
        timeLength: number;
        recruitPrice: number;
    }
}
export namespace GachaData {
    export interface RecruitRange {
        rarityStart: number;
        rarityEnd: number;
    }
    export interface CarouselData {
        poolId: string;
        index: number;
        startTime: number;
        endTime: number;
        spriteId: string;
    }
    export interface FreeLimitGachaData {
        poolId: string;
        openTime: number;
        endTime: number;
        freeCount: number;
    }
    export interface LimitTenGachaTkt {
        itemId: string;
        endTime: number;
    }
    export interface FesGachaPoolRelateItem {
        rarityRank5ItemId: string;
        rarityRank6ItemId: string;
    }
    export interface LinkageTenGachaTkt {
        itemId: string;
        endTime: number;
        gachaPoolId: string;
    }
    export interface NormalGachaTkt {
        itemId: string;
        endTime: number;
        gachaPoolId: string;
        isTen: boolean;
    }
}