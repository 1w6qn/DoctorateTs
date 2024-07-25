import EventEmitter from "events";
import { MissionCalcState, MissionDailyRewards, MissionPlayerData, MissionPlayerDataGroup, MissionPlayerState, PlayerDataModel } from '../model/playerdata';
import excel from "../../excel/excel";
import { ItemBundle } from "../../excel/character_table";
import { PlayerSquad } from "../model/character";
import { TroopManager } from "./TroopManager";

export class MissionManager {
    missions: { [key: string]: MissionProgress[] };
    missionRewards: MissionDailyRewards
    missionGroups: { [key: string]: number }
    _trigger: EventEmitter;
    get dailyMissionPeriod(): string {
        let ts = new Date().getTime() / 1000
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => p.period.includes(new Date().getDay() + 1))!.missionGroupId
    }
    get dailyMissionRewardPeriod(): string {
        let ts = new Date().getTime() / 1000
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => p.period.includes(new Date().getDay() + 1))!.rewardGroupId
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        playerdata.mission.missions["OPENSERVER"] = {}
        playerdata.mission.missions["ACTIVITY"] = {}

        this.missions = Object.fromEntries(Object.entries(playerdata.mission.missions).map(([type, v]) =>
            [type, Object.entries(v).map(([id, data]) => (new MissionProgress(id, _trigger, this, type, data.progress[0].value, data.state)))]
        ))
        this.missionRewards = playerdata.mission.missionRewards;
        this.missionGroups = playerdata.mission.missionGroups;
        this._trigger = _trigger;
        this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))
        this._trigger.on("mission:complete", this.completeMission.bind(this))


    }
    getMissionById(missionId: string): MissionProgress {
        let type = excel.MissionTable.missions[missionId].type
        return this.missions[type].filter((m) => m.missionId == missionId)[0]
    }
    async dailyRefresh() {
        await excel.initPromise
        this.missionRewards.dailyPoint = 0
        this.missionRewards.rewards["DAILY"] = {}
        for (let reward of Object.values(excel.MissionTable.periodicalRewards)) {
            if (reward.groupId == this.dailyMissionRewardPeriod) {
                this.missionRewards.rewards["DAILY"][reward.id] = 0
            }
        }
        this.missions["DAILY"] = []
        for (let missionId of excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds) {
            this.missions["DAILY"].push(new MissionProgress(missionId, this._trigger, this, "DAILY"))
        }
    }
    weeklyRefresh() {
        this.missionRewards.weeklyPoint = 0
        this.missionRewards.rewards["WEEKLY"] = {}
        this.missions["WEEKLY"] = []
        for (let mission of Object.values(excel.MissionTable.missions).filter((m) => m.type == "WEEKLY")) {
            this.missions["WEEKLY"].push(new MissionProgress(mission.id, this._trigger, this, "WEEKLY"))
        }
    }
    completeMission(missionId: string) {

        switch (excel.MissionTable.missions[missionId].type) {
            case "DAILY":
                //this.missionRewards.dailyPoint += 1
                break;

            default:
                break;
        }

    }
    confirmMission(missionId: string): ItemBundle[] {
        let items: ItemBundle[] = []
        this.getMissionById(missionId).confirmed = true
        switch (excel.MissionTable.missions[missionId].type) {
            case "DAILY":
                this.missionRewards.dailyPoint += excel.MissionTable.missions[missionId].periodicalPoint
                Object.entries(this.missionRewards.rewards["DAILY"]).reduce((acc, [k, v]) => {
                    if (v == 0&&this.missionRewards.dailyPoint >= excel.MissionTable.periodicalRewards[k].periodicalPointCost) {
                        this.missionRewards.dailyPoint -= excel.MissionTable.periodicalRewards[k].periodicalPointCost
                        items.push(...excel.MissionTable.periodicalRewards[k].rewards)
                        //console.log(items)
                        this.missionRewards.rewards["DAILY"][k] = 1
                    }
                    return 0
                }, 0)
                break;
            case "WEEKLY":
                this.missionRewards.weeklyPoint += excel.MissionTable.missions[missionId].periodicalPoint
                break;
            default:
                break;
        }
        this._trigger.emit("gainItems", items)
        return items
    }
    confirmMissionGroup(missionGroupId: string) {

        let rewards = excel.MissionTable.missionGroups[missionGroupId].rewards
        if (rewards) {
            this._trigger.emit("gainItems", rewards)
        }
        this.missionGroups[missionGroupId] = 1
    }
    autoConfirmMissions(type: string):ItemBundle[] {
        let items:ItemBundle[]=[]
        for (let mission of this.missions[type]) {
            if(mission.state==2 && mission.progress[0].value==mission.progress[0].target){
                items.push(...this.confirmMission(mission.missionId))
            }
        }
        return items
    }
    exchangeMissionRewards(targetRewardsId: string) {

    }
    toJSON(): MissionPlayerData {
        return {
            missions: Object.fromEntries(Object.entries(this.missions).map(([type, v]) =>
                [type, v.reduce((acc, v) => ({ ...acc, [v.missionId]: v.toJSON() }), {} as { [k: string]: MissionPlayerState })]
            )),
            missionRewards: this.missionRewards,
            missionGroups: this.missionGroups,
        }
    }
}
export class MissionProgress implements MissionPlayerState {
    [key: string]: any
    progress: MissionCalcState[]
    missionId: string;
    _trigger: EventEmitter;
    _manager: MissionManager;
    param!: string[]
    value: number
    type: string
    confirmed: boolean
    get state(): number {
        if (!("value" in this.progress[0])) {
            console.log(this)
            return 0
        }
        if (this.progress[0].value == this.progress[0].target && this.confirmed) {
            return 3
        } else {
            let preMissionIds = excel.MissionTable.missions[this.missionId]?.preMissionIds
            if (!preMissionIds) {
                return 2
            }
            for (let i of preMissionIds) {
                if (this._manager.getMissionById(i).state != 3) {
                    return 1
                }
            }
            return 2
        }
    }
    constructor(missionId: string, _trigger: EventEmitter, _manager: MissionManager, type: string, value = 0, state = -1) {
        this.missionId = missionId
        this.value = value
        this.progress = []
        this._trigger = _trigger
        this._manager = _manager
        this.type = type
        this.confirmed = state == 3;
        this.init()
        //this._trigger.on("mission:update", this.update.bind(this))
    }
    async init() {
        await excel.initPromise
        let template
        if (this.type == "ACTIVITY") {
            template
        } else {
            template = excel.MissionTable.missions[this.missionId].template
            this.param = excel.MissionTable.missions[this.missionId].param
        }
        if (!template) {
            console.log(this.missionId)
            return
        }
        if (template && !(template in this)) {
            console.log(template)
            throw new Error("template not implemented yet")
        }
        this._trigger.on(template, this[template].bind(this))
        this[template]({}, "init")

    }

    update() {

    }
    CompleteStageAnyType(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":
                let { completeState } = args
                if (completeState == parseInt(this.param[2])) {
                    this.progress[0].value += 1
                }
                if (this.progress[0].value == this.progress[0].target) {
                    this._trigger.emit("mission:complete", this.missionId)
                }
                break
        }


    }
    StageWithEnemyKill(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    EnemyKillInAnyStage(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    StageWithAssistChar(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    UpgradeChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":
                this.progress[0].value += 1
                if (this.progress[0].value == this.progress[0].target) {
                    this._trigger.emit("mission:complete", this.missionId)
                }
                break
        }
    }
    ReceiveSocialPoint(args: { socialPoint: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value+=args.socialPoint
                break
        }
    }
    BuyShopItem(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    NormalGacha(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    GainIntimacy(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    ManufactureItem(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    DeliveryOrder(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    RecoverCharBaseAp(args: { charNum: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += args.charNum
                break
        }
    }
    VisitBuilding(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    UpgradeSkill(args: {targetLevel:number}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    SquadFormation(args: { squad: PlayerSquad }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                break
            case "update":
                //TODO
                break
        }
    }
    CompleteStage(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 })
                break
            case "update":

                break
        }
    }
    UpgradePlayer(args: { level: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value=args.level
                break
        }
    }
    CompleteAnyStage(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: 1 })
                break
            case "update":

                break
        }
    }
    HasChar(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    HasEquipment(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    EvolveChar(args: { troop: TroopManager }, mode: string = "update",) {
        /**
         * 1:num;2:evolve phase
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1])})
                break
            case "update":
                this.progress[0].value=args.troop.chars.reduce((acc, char) => {
                    acc+=char.evolvePhase==parseInt(this.param[2])?1:0
                    return acc
                },0)
                break
        }
    }
    DiyComfort(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    HasRoom(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    WorkshopSynthesis(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    UpgradeSpecialization(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    BattleWithEnemyKill(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    CharIntimacy(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    CompleteBreakReward(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[0]) })
                break
            case "update":

                break
        }
    }
    StartInfoShare(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    EditBusinessCard(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[0]) })
                break
            case "update":

                break
        }
    }
    SetAssistCharList(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    ChangeSquadName(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":
                this.progress[0].value += 1
                break
        }
    }
    StageWithReplay(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    TakeOverReplay(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    CompleteCampaign(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    SetBuildingAssist(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[0]) })
                break
            case "update":

                break
        }
    }
    BoostPotential(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    WorkshopExBonus(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    BoostNormalGacha(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    CompleteMainStage(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    SendClue(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    GainTeamChar(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[1]) || 1 }) ?? 1
                break
            case "update":

                break
        }
    }
    AccelerateOrder(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        switch (mode) {
            case "init":
                this.progress.push({ value: this.value, target: parseInt(this.param[0]) })
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