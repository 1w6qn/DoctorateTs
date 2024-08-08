import EventEmitter from "events";
import { PlayerMedal, PlayerDataModel, PlayerPerMedal, PlayerMedalCustom, PlayerMedalCustomLayout } from '../model/playerdata';
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import moment from "moment";
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
export class MedalProgress implements PlayerPerMedal {
    [key: string]: any
    val: number[][]
    id: string;
    rts: number;
    fts: number;
    reward:string
    _trigger: EventEmitter;
    _param!: string[]
    constructor(item: PlayerPerMedal, _trigger: EventEmitter) {
        this.id = item.id
        this.val = item.val
        this.rts = item.rts
        this.fts = item.fts
        this.reward=item.reward||""
        this._trigger = _trigger
        if (!this.fts) {
            this.init()
        }

    }
    init() {
        const medalInfo=excel.MedalTable.medalList.find(m => m.medalId == this.id)!
        const template = medalInfo.template
        if(!template){
            this.val = []
            return
        }
        this._param = medalInfo.unlockParam
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