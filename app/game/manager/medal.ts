import EventEmitter from "events";
import { PlayerMedal, PlayerDataModel, PlayerPerMedal, PlayerMedalCustom, PlayerMedalCustomLayout, PlayerCampaign } from '../model/playerdata';
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import moment from "moment";
import { DungeonManager } from "./dungeon";
export class MedalManager implements PlayerMedal {
    medals: { [key: string]: PlayerPerMedal };
    custom: PlayerMedalCustom;
    _trigger: EventEmitter;

    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.medals = playerdata.medal.medals;
        this.custom = playerdata.medal.custom;
        this._trigger = _trigger;

    }
    setCustomData(args: { index: string, data: PlayerMedalCustomLayout }) {
        this.custom.currentIndex = args.index
        this.custom.customs[args.index] = args.data
    }
    rewardMedal(args: { medalId: string, group: string }) {
        const medalRewardGroup = excel.MedalTable.medalList.find(m => m.medalId == args.medalId)!.medalRewardGroup
        const items: ItemBundle[] = medalRewardGroup.find(m => m.groupId == args.group)!.itemList
        this.medals[args.medalId].rts = now()
        this._trigger.emit("gainItems", items)
        return items
    }
    toJSON() {
        return {
            medals: this.medals,
            customs: this.custom,
        }
    }
}
//TODO:complete the template
export class MedalProgress implements PlayerPerMedal {
    [key: string]: any
    val: number[][]
    id: string;
    rts: number;
    fts: number;
    reward:string
    _trigger: EventEmitter;
    _v:number
    param!: string[]
    constructor(item: PlayerPerMedal, _trigger: EventEmitter) {
        this.id = item.id
        this.val=[[]]
        this.rts = item.rts
        this.fts = item.fts
        this.reward=item.reward||""
        this._v=item.val[0][0]||0
        this._trigger = _trigger
        if (!this.fts) {
            this.init()
        }
        this.val = item.val

    }
    init() {
        const medalInfo=excel.MedalTable.medalList.find(m => m.medalId == this.id)!
        const template = medalInfo.template
        if(!template){
            this.val = []
            return
        }
        this.param = medalInfo.unlockParam
        if (template&&!(template in this)) {
            throw new Error("template not implemented yet")
        }
        this._trigger.on(template, (args:Object,mode:string)=>{
            this[template](args, mode)
            if (this.val[0][0] >= this.val[0][0]!) {
                console.log(`[MedalManager] ${this.id} complete`)
                this._trigger.removeListener(template, this[template])
            }
        })
        this[template]({}, "init")
        

    }
    update() {

    }
    PlayerLevel(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{level:number})=>{
                this.val[0][0] = args.level
            }
        }
        funcs[mode](args)
    }
    JoinGameDays(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharNum(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{curCharInstId:number})=>{
                this.val[0][0] = args.curCharInstId
            }
        }
        funcs[mode](args)
    }
    RecruitCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{})=>{
                this.val[0][0] +=1
            }
        }
        funcs[mode](args)
    }
    PassStageSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[2])),
            "update":(args:DungeonManager)=>{
                const stages:string[]=this.param[1].split(";")
                let count=0
                Object.values(args.stages).forEach((stage)=>{
                    if(stages.includes(stage.stageId)&&stage.state>=parseInt(this.param[0])){
                        count+=1
                    }
                })
                this.val[0][0] = count
            }
        }
        funcs[mode](args)
    }
    CampaignsDiamondLimit(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:PlayerCampaign)=>{
                this.val[0][0] = args.campaignTotalFee
            }
        }
        funcs[mode](args)
    }
    CampaignsComplete(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,1),
            "update":(args:PlayerCampaign)=>{
                if(args.instances[this.param[0]].maxKills!=400){
                    return
                }
                if(args.instances[this.param[0]].rewardStatus.includes(0)){
                    return 
                }
                this.val[0][0] +=1
            }
        }
        funcs[mode](args)
    }
    PassTower(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharEvolveCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharSkillCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharSkillSpecCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharFavorCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    GotChars(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharPotential(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharStoryUnlock(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2UpgradeBase(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2FinishQuest(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2BattleFinishWithChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2UnlockCook(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2PlaceBuilding(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2PassRiftLevel(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2PassRiftCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2CatchAnimal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2UnlockTech(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2SurviveDays(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Sbv2KillBoss(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2PassNode(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2BpLevel(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PermUpgrade(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    UseAlchemy(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2Recruit(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2GetTeamReward(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2EndingCollect(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2CollectRelic(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2FinishBattleWithSpecChar(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2EndingWithModeGrade(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2UnlockBand(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2TotemResonance(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2CompleteNodeMission(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Rlv2GainCapsule(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    BuildingGotFurnitureThemeCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    BuildingManufactureProductTimes(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    BuildingWorkshopSynthesisGroupByID(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    GotCharsBeforeTime(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityCoinCost(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    MissionCompleteSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityPassStageWithSimpleTokenCountMore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act35SideFinishCarving(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithSimpleCountMore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithDetailDiffCountMore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithSimpleTokenCountLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageKilledTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActMultiplayVerify2StageTotalScore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActMultiplayVerify2PassStageWithScore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityMilestonePoint(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    GotItemBeforeTime(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithSimpleTokenCountMore(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisV2DimScoreTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisV2NodeSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisV2DimScoreSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisV2UseAssist(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithBossRush(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithSimpleCountLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    TotalSimpleTokenCount(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithSimpleTokenCountMax(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act29SideInvestigateDailyNPC(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    SimpleTokenCountMoreInManyStages(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act29SideSyncthesizeMelody(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act42D0UnlockArea(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act42D0UseAssistPassStage(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act42D0FinishChallenge(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithTrapSurvivedLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityAct38d1DimScoreTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityAct38d1DimScoreSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityAct38d1UnlockNodeSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityAct38d1UseAssist(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStoryStageSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act25SideSimpleEventAtLeast(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    Act25SideFinInvestigation(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisStageScoreSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisTempClearSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisTaskSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisUnlockPermRuneSome(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisUseAssist(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithKillSurvive(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithTrapSurvived(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithReedResidue(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityLikeOperaComment(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityFinishCharCardTask(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityUnlockSiracusaArea(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    GainCarAccessories(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageKilled(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageKilledLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityTechTreeActive(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityTreasureGain(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithTechTree(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithEnemyActiveLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithAtLeast(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityCostAgenda(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityReachPrestigeLevel(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityMilestoneReward(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CharmUnlock(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityCharmRecycleReward(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithActiveTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithActiveLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithDeadInLess(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityHoldTaichi(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithLessDeploy(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithoutBossShield(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityConfinementTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityKilledTotal(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityCasimirReadNews(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivityCutTree(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithCutTree(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    PassStageWithTower(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivitySandboxCreateItem(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    ActivitySandboxAchieveEnding(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    UnlockStoryGroup(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    FullPotentialOverflow(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }
    CrisisStageScoreBeforeTime(args: {}, mode: string = "update",) {
        /**
         * 
         * 
         */
        const funcs:{[key:string]:(args:any)=>void}={
            "init":(args:{})=>this.val[0].push(0,parseInt(this.param[0])),
            "update":(args:{registerTs:number})=>{
                this.val[0][0] = moment().diff(moment(args.registerTs), 'days')
            }
        }
        funcs[mode](args)
    }


    toJSON():PlayerPerMedal {
        return {
            id:this.id,
            val:this.val,
            fts:this.fts,
            rts:this.rts,
            ...this.reward?{reward:this.reward}:{}
        }
    }
}