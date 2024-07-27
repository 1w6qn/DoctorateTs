import { ItemBundle } from "app/excel/character_table";

export interface MailItem extends BaseMailItem {
    mailId:    number;
    items:     ItemBundle[];
    hasItem:   number;
}
export interface SurveyItem extends BaseMailItem {
    surveyMailId:    number;
}
export interface BaseMailItem{
    uid:       string;
    from:      string;
    subject:   string;
    content:   string;
    createAt:  number;
    expireAt:  number;
    receiveAt: number;
    state:     number;
    style:     MailStyle;
    platform:  number;
    type:      number;
}
export interface MailStyle {
    route:  number;
    banner: string;
}
export interface MailMetaInfo{
    mailId:number,
    createAt:number,
    state:number,
    hasItem:number,
    type:number,
}