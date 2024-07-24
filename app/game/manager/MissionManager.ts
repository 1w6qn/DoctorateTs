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
    get dailyMissionRewardPeriod(): string {
        let ts = new Date().getTime() / 1000
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => (new Date().getDay() + 1) in p.period)!.rewardGroupId
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.mission = playerdata.mission;
        this._trigger = _trigger;
        this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))
        //this.init()

    }
    init(){
        for (let missionId of excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds) {
            let v=this.mission.missions.DAILY[missionId].progress[0].value
            this.mission.missions.DAILY[missionId] = new MissionProgress(missionId, this._trigger,this,v)
        }
    }
    getMissionById(missionId: string): MissionPlayerState {
        return this.mission.missions.DAILY[missionId]
    }
    dailyRefresh() {
        this.mission.missionRewards.dailyPoint = 0
        this.mission.missionRewards.rewards["DAILY"] = {}
        for(let reward of Object.values(excel.MissionTable.periodicalRewards)){
            if(reward.groupId==this.dailyMissionRewardPeriod){
                this.mission.missionRewards.rewards["DAILY"][reward.id]=0
            }
        }
        this.mission.missions.DAILY = {}
        for (let missionId of excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds) {
            this.mission.missions.DAILY[missionId] = new MissionProgress(missionId, this._trigger,this)
        }
    }
    weeklyRefresh() {
        this.mission.missionRewards.weeklyPoint = 0
        this.mission.missionRewards.rewards["WEEKLY"] = {}
        this.mission.missions.WEEKLY = {}
        for (let mission of Object.values(excel.MissionTable.missions).filter((m) => m.type=="WEEKLY")) {
            this.mission.missions.WEEKLY[mission.id] = new MissionProgress(mission.id, this._trigger,this).toJSON()
        }
    }
    completeMission(missionId: string){
        
    }
    confirmMission(missionId: string){

    }
    confirmMissionGroup(missionGroupId:string){
        
        let rewards=excel.MissionTable.missionGroups[missionGroupId].rewards
        if(rewards){
            this._trigger.emit("gainItems",rewards)
        }
        this.mission.missionGroups[missionGroupId]=1
    }
    autoConfirmMissions(type:string){

    }
    exchangeMissionRewards(targetRewardsId:string){

    }
    toJSON() {
        return this.mission
    }
}
export class MissionProgress implements MissionPlayerState {
    [key: string]: any
    progress: MissionCalcState[]
    missionId: string;
    _trigger: EventEmitter;
    param!:string[]
    value:number
    get state():number{
        if(this.progress[0].value==this.progress[0].target){
            return 3
        }else{
            let preMissionIds=excel.MissionTable.missions[this.missionId]?.preMissionIds
            if(!preMissionIds){
                return 2
            }
            for(let i of preMissionIds){
                if(this._manager.getMissionById(i).state!=3){
                    return 1
                }
            }
            return 2
        }
    }
    constructor(missionId: string, _trigger: EventEmitter,_manager:MissionManager,value=0) {
        this.missionId = missionId
        this.value=value
        this.progress = []
        this._trigger = _trigger
        this._manager=_manager
        this.init()
        //this._trigger.on("mission:update", this.update.bind(this))
    }
    init() {
        const template = excel.MissionTable.missions[this.missionId].template
        this.param = excel.MissionTable.missions[this.missionId].param
        console.log(template)
        if(!(template in this)){
            throw new Error("template not implemented yet")
        }
        this._trigger.on(template, this[template].bind(this))
        this[template]({},"init")

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
                this.progress.push({ value: this.value , target: parseInt(this.param[1]) })
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
    StageWithEnemyKill(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    EnemyKillInAnyStage(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    StageWithAssistChar(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    UpgradeChar(args:{},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                this.progress[0].value += 1
                if(this.progress[0].value == this.progress[0].target){
                    this._trigger.emit("mission:complete", this.missionId)
                }
                break
        }
    }
    ReceiveSocialPoint(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    BuyShopItem(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    NormalGacha(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                break
            case "update":
                
                break
        }
    }
    GainIntimacy(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    ManufactureItem(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    DeliveryOrder(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    RecoverCharBaseAp(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }
    VisitBuilding(args:{completeState:number},mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                break
            case "update":
                
                break
        }
    }

    toJSON(): MissionPlayerState {
        return {
            state: this.state,
            progress: this.progress,
        }
    }
}