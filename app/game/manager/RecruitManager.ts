import EventEmitter from "events";
import { PlayerRecruit } from "../model/playerdata";

export class RecruitManager {
    recruit:PlayerRecruit
    _trigger:EventEmitter
    constructor(recruit:PlayerRecruit,_trigger:EventEmitter) {
        this.recruit=recruit
        this._trigger=_trigger
    }
    refreshTags(slotId:number){

    }
    sync(){

    }
    cancle(slotId:number){
        this.recruit.normal.slots[slotId.toString()].state=1
        this.recruit.normal.slots[slotId.toString()].selectTags=[]
        this.recruit.normal.slots[slotId.toString()].startTs=-1
        this.recruit.normal.slots[slotId.toString()].maxFinishTs=-1
        this.recruit.normal.slots[slotId.toString()].realFinishTs=-1
        this.recruit.normal.slots[slotId.toString()].durationInSec=-1

    }
    buyRecruitSlot(slotId:number){

    }
    normalGacha(slotId:number,tagList:number[],specialTagId:number,duration:number){
        
    }
    finish(slotId:number){
        
    }
    boost(slotId:number,buy:number){
        this.recruit.normal.slots[slotId.toString()].state=3
        this.recruit.normal.slots[slotId.toString()].realFinishTs=parseInt((new Date().getTime()/1000).toString())
    }
    toJSON():PlayerRecruit{
        return this.recruit
    }
}