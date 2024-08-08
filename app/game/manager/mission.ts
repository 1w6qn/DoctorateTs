import EventEmitter from "events";
import { MissionCalcState, MissionDailyRewards, MissionPlayerData, MissionPlayerState, PlayerDataModel } from '../model/playerdata';
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { PlayerCharacter, PlayerSquad } from "../model/character";
import { BattleData } from '../model/battle';
import { now } from "@utils/time";

export class MissionManager {
    missions: { [key: string]: MissionProgress[] };
    missionRewards: MissionDailyRewards
    missionGroups: { [key: string]: number }
    _trigger: EventEmitter;
    get dailyMissionPeriod(): string {
        let ts = now()
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => p.period.includes(new Date().getDay() + 1))!.missionGroupId
    }
    get dailyMissionRewardPeriod(): string {
        let ts = now()
        let period = excel.MissionTable.dailyMissionPeriodInfo.find((p) => p.startTime <= ts && p.endTime >= ts)
        return period!.periodList.find((p) => p.period.includes(new Date().getDay() + 1))!.rewardGroupId
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        playerdata.mission.missions["ACTIVITY"] = {}
        this.missions = Object.fromEntries(Object.entries(playerdata.mission.missions).map(([type, v]) =>
            [type, Object.entries(v).map(([id, data]) => { return (new MissionProgress(id, _trigger, this, type, data.progress[0].value ?? 0, data.state)) })]
        ))
        this.missionRewards = playerdata.mission.missionRewards;
        this.missionGroups = playerdata.mission.missionGroups;
        this._trigger = _trigger;
        this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))
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

    confirmMission(missionId: string): ItemBundle[] {
        let items: ItemBundle[] = []
        this.getMissionById(missionId).confirmed = true
        switch (excel.MissionTable.missions[missionId].type) {
            case "DAILY":
                this.missionRewards.dailyPoint += excel.MissionTable.missions[missionId].periodicalPoint
                Object.entries(this.missionRewards.rewards["DAILY"]).reduce((acc, [k, v]) => {
                    if (v == 0 && this.missionRewards.dailyPoint >= excel.MissionTable.periodicalRewards[k].periodicalPointCost) {
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
    autoConfirmMissions(type: string): ItemBundle[] {
        let items: ItemBundle[] = []
        for (let mission of this.missions[type]) {
            if (mission.state == 2 && mission.progress[0].value == mission.progress[0].target) {
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
            console.log(this.missionId)
            return 0
        }
        if (this.progress[0].value >= (this.progress[0].target as number) && this.confirmed) {
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
        let template: string
        if (this.type == "ACTIVITY") {
            template = ""
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
        this._trigger.on(template, (args: {}, mode:string="update") => {
            this[template](args, mode)
            //console.log(`[MissionManager] ${this.missionId} update ${this.progress[0].value}/${this.progress[0].target}`)
            if (this.progress[0].value >= this.progress[0].target!) {
                console.log(`[MissionManager] ${this.missionId} complete`)
                this._trigger.removeListener(template, this[template])
            }
        })
        this[template]({}, "init")

    }

    update() {

    }
    CompleteStageAnyType(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData) => {
                    let { completeState } = args
                    if (completeState >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    StageWithEnemyKill(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData) => {
                    let { completeState } = args
                    if (completeState >= 2) {
                        this.progress[0].value += args.killCnt
                    }
                }
            },
            "2": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData) => {
                    const enemies = this.param[2].split("^")
                    args.battleData.stats.enemyStats.forEach((stat) => {
                        if (enemies.includes(stat.Key.enemyId) && stat.Key.counterType == "HP_ZERO") {
                            this.progress[0].value += stat.Value
                        }
                    })
                }
            },
            "5": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stages = this.param[1].split("^")
                    if (stages.includes(args.stageId) && args.completeState >= 2) {
                        this.progress[0].value += args.killCnt
                    }
                }
            },
            "6": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[3]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stages = this.param[1].split("^")
                    if (!stages.includes(args.stageId)) {
                        return
                    }
                    if (args.completeState < parseInt(this.param[3])) {
                        return
                    }
                    if (args.killCnt >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            },
        }
        funcs[this.param[0]][mode](args)

    }
    EnemyKillInAnyStage(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData) => {
                    if (args.completeState < parseInt(this.param[2])) {
                        return
                    }
                    this.progress[0].value += args.killCnt
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    StageWithAssistChar(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: BattleData) => {
                    //TODO
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    UpgradeChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": () => {
                    this.progress[0].value += 1
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    if (args.char.evolvePhase < parseInt(this.param[2])) {
                        return
                    }
                    if (args.char.level >= parseInt(this.param[3])) {
                        this.progress[0].value += 1
                    }
                }
            },
            "2": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { exp: number }) => {
                    this.progress[0].value += args.exp
                }
            },
        }
        funcs[this.param[0]][mode](args)
    }
    ReceiveSocialPoint(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */

        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { socialPoint: number }) => {
                    this.progress[0].value += args.socialPoint
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    BuyShopItem(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { type: string }) => {
                    const shops = "LS^HS^ES".split("^")
                    if (shops.includes(args.type)) {
                        this.progress[0].value += 1
                    }
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { type: string }) => {
                    if (args.type == "SOCIAL") {
                        this.progress[0].value += 1
                    }

                }
            },
            "3": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { type: string, socialPoint: number }) => {
                    if (args.type != "SOCIAL") {
                        return
                    }
                    this.progress[0].value += args.socialPoint
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    NormalGacha(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    GainIntimacy(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { count: number }) => {
                    this.progress[0].value += args.count
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    ManufactureItem(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { item: ItemBundle }) => {
                    if (args.item.id == this.param[2]) {
                        this.progress[0].value += args.item.count
                    }
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { count: number }) => {
                    this.progress[0].value += args.count
                }
            },
            "2": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { item: ItemBundle }) => {
                    const items = this.param[2].split("#")
                    if (items.includes(args.item.id)) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    DeliveryOrder(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { count: number }) => {
                    this.progress[0].value += args.count
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    RecoverCharBaseAp(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { count: number }) => {
                    this.progress[0].value += args.count
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    VisitBuilding(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    UpgradeSkill(args: { targetLevel: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { targetLevel: number }) => {
                    this.progress[0].value += args.targetLevel
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    SquadFormation(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: PlayerSquad) => {
                    let flag = false
                    //TODO
                    this.progress[0].value += flag ? 1 : 0
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    CompleteStage(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stages = this.param[1].split("^")
                    if (!stages.includes(args.stageId)) {
                        return
                    }
                    if (args.completeState >= 2) {
                        this.progress[0].value += 1
                    }
                }
            },
            "2": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: BattleData) => {
                    if (args.completeState >= parseInt(this.param[1])) {
                        this.progress[0].value += 1
                    }
                }
            },
            "3": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData & { isPractice: number }) => {
                    if (!args.isPractice) {
                        return
                    }
                    if (args.completeState >= 2) {
                        this.progress[0].value += 1
                    }
                }
            },
            "4": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    if (!args.stageId.includes("#f#")) {
                        return
                    }
                    if (args.completeState >= 3) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)

    }
    UpgradePlayer(args: { level: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { level: number }) => {
                    this.progress[0].value = args.level
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    CompleteAnyStage(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stages = this.param[1].split("^")
                    if (!stages.includes(args.stageId)) {
                        return
                    }
                    if (args.completeState >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    HasChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    const data = excel.CharacterTable[args.char.charId]
                    if (args.char.evolvePhase < parseInt(this.param[2])) {
                        return
                    }
                    if (args.char.level < parseInt(this.param[3])) {
                        return
                    }
                    if (data.rarity.slice(-1) != this.param[4] && this.param[4] != "-1") {
                        return
                    }
                    if (data.profession != this.param[5] && this.param[5] != "ALL") {
                        return
                    }
                    this.progress[0].value += 1
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    const data = excel.CharacterTable[args.char.charId]
                    if (args.char.evolvePhase < parseInt(this.param[2])) {
                        return
                    }
                    if (args.char.level < parseInt(this.param[3])) {
                        return
                    }
                    if (data.rarity.slice(-1) != this.param[4] && this.param[4] != "-1") {
                        return
                    }
                    if (data.profession != this.param[5] && this.param[5] != "ALL") {
                        return
                    }
                    this.progress[0].value += 1
                }
            },
        }
        funcs[this.param[0]][mode](args)
    }
    HasEquipment(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[3]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    const data = excel.CharacterTable[args.char.charId]
                    const rarities = this.param[1].split("^")
                    const levels = this.param[2].split("^")
                    if (args.char.evolvePhase < 2) {
                        return
                    }
                    if (!rarities.includes(data.rarity.slice(-1))) {
                        return
                    }
                    Object.values(args.char.equip!).forEach(e => {
                        if (levels.includes(e.level.toString())) {
                            this.progress[0].value += 1
                        }
                    })
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    EvolveChar(args: {}, mode: string = "update",) {
        /**
         * 1:num;2:evolve phase
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    if (args.char.evolvePhase >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    DiyComfort(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    //TODO
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    //TODO
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    HasRoom(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { char: PlayerCharacter }) => {
                    //TODO
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    WorkshopSynthesis(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { item: ItemBundle }) => {
                    if (args.item.id == this.param[2]) {
                        this.progress[0].value += args.item.count
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    UpgradeSpecialization(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            },
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: { targetLevel: number }) => {
                    if (args.targetLevel >= parseInt(this.param[1])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    BattleWithEnemyKill(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[2]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stages = this.param[1].split("^")
                    if (!stages.includes(args.stageId)) {
                        return
                    }
                    if (args.killCnt >= this.progress[0].value) {
                        this.progress[0].value = args.killCnt
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    CharIntimacy(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { favorPoint: number }) => {
                    let percent: number = 0
                    if (args.favorPoint == excel.FavorTable.maxFavor) {
                        percent = 200
                    }
                    percent = excel.FavorTable.favorFrames.find((f, idx, table) => {
                        return args.favorPoint >= table[idx].level && args.favorPoint < table[idx + 1].level
                    })!.data.percent
                    if (percent >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    CompleteBreakReward(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: {}) => {
                    //TODO
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    StartInfoShare(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    EditBusinessCard(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    SetAssistCharList(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    ChangeSquadName(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    StageWithReplay(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { isReplay: number }) => {
                    if (args.isReplay) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    TakeOverReplay(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData) => {
                    if (args.battleData.stats.autoReplayCancelled) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)

    }
    CompleteCampaign(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: BattleData & { stageId: string }) => {
                    const stageType = excel.StageTable.stages[args.stageId].stageType
                    if (args.completeState < 2) {
                        return
                    }
                    if (stageType == "CAMPAIGN") {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    SetBuildingAssist(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    BoostPotential(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: { targetRank: number }) => {
                    if (args.targetRank >= parseInt(this.param[2])) {
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    WorkshopExBonus(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    BoostNormalGacha(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    CompleteMainStage(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "1": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: BattleData & {stageId: string}) => {
                    if(args.stageId!=this.param[1]){
                        return
                    }
                    if(args.completeState>=2){
                        this.progress[0].value += 1
                    }
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    SendClue(args: { completeState: number }, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: parseInt(this.param[1]) })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    GainTeamChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: {}) => {
                    //TODO
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }
    AccelerateOrder(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs: { [key: string]: { [key: string]: (args: any) => void } } = {
            "0": {
                "init": () => {
                    this.progress.push({ value: this.value, target: 1 })
                },
                "update": (args: {}) => {
                    this.progress[0].value += 1
                }
            }
        }
        funcs[this.param[0]][mode](args)
    }



    toJSON(): MissionPlayerState {
        return {
            state: this.state,
            progress: this.progress,
        }
    }
}