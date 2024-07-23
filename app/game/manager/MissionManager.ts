import EventEmitter from "events";
import { MissionCalcState, MissionPlayerData, MissionPlayerState, PlayerDataModel } from '../model/playerdata';
import excel from "../../excel/excel";
import { ItemBundle } from "../../excel/character_table";
function getProperty<Type, Key extends keyof Type>(obj: Type, key: Key) {
    return obj[key];
}
export class MissionManager {
    mission: MissionPlayerData;
    _trigger: EventEmitter;
    get dailyMissionPeriod(): string {
        let ts = new Date().getTime() / 1000
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => (new Date().getDay() + 1) in p.period)!.missionGroupId
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.mission = playerdata.mission;
        this._trigger = _trigger;
        this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))

    }
    dailyRefresh() {
        this.mission.missionRewards.dailyPoint = 0
        this.mission.missionRewards.rewards["DAILY"] = {}
        for (let missionId in excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds) {
            this.mission.missions.DAILY[missionId] = new MissionProgress(missionId, this._trigger).toJSON()
        }
    }
    weeklyRefresh() {
        this.mission.missionRewards.weeklyPoint = 0
        this.mission.missionRewards.rewards["WEEKLY"] = {}
    }
    toJSON() {
        return this.mission
    }
}
export class MissionProgress {
    [key: string]: any
    progress: MissionCalcState[]
    missionId: string;
    _trigger: EventEmitter;
    param!:string[]
    constructor(missionId: string, _trigger: EventEmitter) {
        this.missionId = missionId
        this.progress = []
        this._trigger = _trigger
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
                this.progress.push({ value: 0, target: parseInt(this.param[1]) })
                break
            case "update":
                let {completeState}=args
                if (completeState == parseInt(this.param[2])) {
                    this.progress[0].value += 1
                }
                if(this.progress[0].value == this.progress[0].target){
                    this._trigger.emit("mission:complete", this.missionId)
                }
                break
        }


    }


    toJSON(): MissionPlayerState {
        return {
            state: excel.MissionTable.missions[this.missionId].preMissionIds ? 1 : 2,
            progress: this.progress,
        }
    }
}