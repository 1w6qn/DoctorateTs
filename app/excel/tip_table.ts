export interface TipTable {
    tips:          TipData[];
    worldViewTips: WorldViewTip[];
}

export interface TipData {
    tip:      string;
    weight:   number;
    category: Category;
}

export enum Category {
    Battle = "BATTLE",
    Building = "BUILDING",
    Gacha = "GACHA",
    Misc = "MISC",
}

export interface WorldViewTip {
    title:           string;
    description:     string;
    backgroundPicId: string;
    weight:          number;
}
