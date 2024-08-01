import EventEmitter from "events";
import {  PlayerDataMedal, PlayerDataModel } from '../model/playerdata';
import excel from "../../excel/excel";
import { ItemBundle } from "../../excel/character_table";
import { now } from "@utils/time";
export class MedalManager {
    medal: PlayerDataMedal;
    _trigger: EventEmitter;
    get dailyMissionPeriod(): string {
        let ts = now()
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => (new Date().getDay() + 1) in p.period)!.missionGroupId
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.medal = playerdata.medal;
        this._trigger = _trigger;
    }
    toJSON() {
        return this.medal
    }
}
export class MedalProgress {
    [key: string]: any
    progress: []
    state:number
    missionId: string;
    _trigger: EventEmitter;
    param!:string[]
    constructor(missionId: string, _trigger: EventEmitter) {
        this.missionId = missionId
        this.progress = []
        this._trigger = _trigger
        this.state = excel.MissionTable.missions[this.missionId].preMissionIds ? 1 : 2
        this.init()
        //this._trigger.on("mission:update", this.update.bind(this))
    }
    init() {
        const template = excel.MissionTable.missions[this.missionId].template
        this.param = excel.MissionTable.missions[this.missionId].param
        if(!(template in this)){
            throw new Error("template not implemented yet")
        }
        let func = this[template] as Function
        this.on(template, func.bind(this))
        func({},"init")

    }
    update() {

    }
    CompleteStageAnyType(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                //this.progress.push({ value: 0, target: parseInt(this.param[1]) })
                break
            case "update":
                let {completeState}=args
                if (completeState == parseInt(this.param[2])) {
                    //this.progress[0].value += 1
                }
                //if(this.progress[0].value == this.progress[0].target){
                //    this._trigger.emit("mission:complete", this.missionId)
                //}
                break
        }


    }


    toJSON() {
        return {
            state: this.state,
            progress: this.progress,
        }
    }
}