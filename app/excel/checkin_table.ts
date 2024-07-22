import { ItemBundle } from "./character_table";

export interface CheckinTable {
    groups:              { [key: string]: MonthlySignInGroupData };
    monthlySubItem:      { [key: string]: MonthlyDailyBonusGroup[] };
    currentMonthlySubId: string;
}

export interface MonthlySignInGroupData {
    groupId:       string;
    title:         string;
    description:   string;
    signStartTime: number;
    signEndTime:   number;
    items:         MonthlySignInData[];
}

export interface MonthlySignInData {
    itemId:   string;
    itemType: string;
    count:    number;
}


export interface MonthlyDailyBonusGroup {
    groupId:   string;
    startTime: number;
    endTime:   number;
    items:     ItemBundle[];
    imgId:     string;
    backId:    string;
}