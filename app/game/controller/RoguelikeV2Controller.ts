import EventEmitter from "events";
import { PlayerRoguelikeV2, RoguelikeNodePosition } from '../model/rlv2';
import excel from "@excel/excel";
import _ from "lodash"
import { readFileSync } from "fs";
import { RoguelikeInventoryManager } from "./rlv2/inventory";
import { TroopManager } from "../manager/troop";
import { RoguelikeBuffManager } from "./rlv2/buff";
import { RoguelikePlayerStatusManager } from "./rlv2/status";
import { now } from "@utils/time";
import { RoguelikeModuleManager } from "./rlv2/module";
import roexcel from "./rlv2/excel";
import { RoguelikeTroopManager } from "./rlv2/troop";
import { RoguelikeMapManager } from "./rlv2/map";
import { PlayerSquad } from "@game/model/character";
import { RoguelikePendingEvent } from "./rlv2/events";
import { RoguelikeBattleManager } from "./rlv2/battle";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { RoguelikeFragmentManager } from "./rlv2/modules/fragment";
import { BattleData } from "@game/model/battle";
import { RoguelikePoolManager } from "./rlv2/pool";
export class RoguelikeV2Config {
    choiceScenes: { [key: string]: { choices: { [key: string]: number } } }
    constructor() {
        this.choiceScenes = JSON.parse(readFileSync(`${__dirname}/../../../data/rlv2/choices.json`, "utf-8"))
    }
}
export class RoguelikeV2Controller {
    pinned?: string;
    outer: { [key: string]: PlayerRoguelikeV2.OuterData; };
    current: PlayerRoguelikeV2.CurrentData;
    troop: RoguelikeTroopManager
    _map!: RoguelikeMapManager
    _status!: RoguelikePlayerStatusManager
    _buff!: RoguelikeBuffManager
    _module!: RoguelikeModuleManager
    _battle!: RoguelikeBattleManager
    _troop: TroopManager
    _pool:RoguelikePoolManager
    _data: RoguelikeV2Config;
    _player: PlayerDataManager
    _trigger: EventEmitter
    inventory!: RoguelikeInventoryManager | null;
    setPinned(id: string): void {
        this.pinned = id
    }
    giveUpGame(): void {
        this.current.game = {
            mode: "NONE",
            predefined: "",
            theme: "",
            outer: {
                support: false
            },
            start: -1,
            modeGrade: 0,
            equivalentGrade: 0
        }
        this.current.buff = {
            tmpHP: 0,
            capsule: null,
            squadBuff: []
        }
        this.current.record = { brief: null }
        this._trigger.emit("rlv2:init", this)
    }
    async createGame(args: { 
        theme: string, 
        mode: string, 
        modeGrade: number, 
        predefinedId: string | null 
    }): Promise<void> {
        //TODO
        await roexcel.initPromise
        await excel.initPromise
        console.log("[RLV2] Game creation", args)
        this.current.game = {
            mode: args.mode,
            predefined: args.predefinedId,
            theme: args.theme,
            outer: {
                support: false
            },
            start: now(),
            modeGrade: args.modeGrade,
            equivalentGrade: args.modeGrade
        }
        this.current.buff = {
            tmpHP: 0,
            capsule: null,
            squadBuff: []
        }
        this.current.record = { brief: null }
        this.current.map = { zones: {} }
        this._trigger.emit("rlv2:create", this)

        

    }

    async chooseInitialRelic(args: { select: string }) {
        let event = this._status.pending.shift()
        let relic = event!.content.initRelic!.items[args.select]
        await this.inventory!._relic.gain(relic)

    }
    async chooseInitialRecruitSet(args: { select: string }) {
        await roexcel.initPromise
        const theme = this.current.game!.theme
        let event = this._status.pending.shift()
        let event2 = this._status.pending.find(e => e.type === "GAME_INIT_RECRUIT")!
        //TODO
        roexcel.RoguelikeConsts[theme].recruitGrps[args.select].forEach(r => {
            console.log("gain recruit", r)
            this._trigger.emit("rlv2:recruit:gain", r, "initial", 0)
        })
        event2.content.initRecruit!.tickets = Object.values(this.inventory!.recruit).filter(r => r.from == "initial").map(r => r.index)


    }
    activeRecruitTicket(args: { id: string }) {
        this._trigger.emit("rlv2:recruit:active", args.id)
    }
    recruitChar(args: { 
        ticketIndex: string, 
        optionId: string 
    }): PlayerRoguelikeV2.CurrentData.RecruitChar[] {
        this._trigger.emit("rlv2:recruit:done", args.ticketIndex, args.optionId)
        return [this.inventory?.recruit[args.ticketIndex].result!]
    }
    finishEvent() {
        this._status.pending.shift()
        this._status.cursor.zone = 1
        this._status.cursor.position=null
        this._trigger.emit("rlv2:zone:new", this._status.cursor.zone)
        this._status.state="WAIT_MOVE"
    }
    async moveAndBattleStart(args: { 
        to: RoguelikeNodePosition, 
        stageId: string, 
        squad: PlayerSquad 
    }): Promise<string> {

        await this.moveTo(args)
        let nodeId = args.to.x * 100 + args.to.y
        let stageId = this._map.zones[this._status.cursor.zone].nodes[nodeId].stage
        this._trigger.emit("rlv2:battle:start", stageId)
        return ""
    }
    async moveTo(args: { to: RoguelikeNodePosition }): Promise<void> {
        await excel.initPromise
        const theme = this.current.game!.theme
        const detail=excel.RoguelikeTopicTable.details.rogue_4.gameConst
        let pos = this._status.cursor.position
        this._status.state = "PENDING"
        if (pos) {
            let nodeId = pos.x * 100 + pos.y
            let node = this._map.zones[this._status.cursor.zone].nodes[nodeId]
            if (node.next.find(n => n.x === args.to.x && n.y === args.to.y)?.key) {
                this._trigger.emit("rlv2:get:items", [{
                    id:detail.unlockRouteItemId,
                    count:detail.unlockRouteItemCount,
                }])
            }
        }
        this._buff.filterBuffs("overweight_move_cost").forEach(b => {
            this._trigger.emit("rlv2:get:items", [{id:b.blackboard[0].valueStr,count:-b.blackboard[1].value!}])
        })
        this._trigger.emit("rlv2:move")
        this._status.trace.push({zone:this._status.cursor.zone,position:args.to})
        
        this._status.cursor.position = args.to

    }
    battleFinish(args: {battleLog:string,data:string,battleData:BattleData} ){
        this._trigger.emit("rlv2:battle:finish", args)
    }
    chooseBattleReward(args:{index:number,sub:number}){
        let rewardGrp=this._status.pending[0].content.battleReward!.rewards.find(r=>r.index==args.index)!
        let reward=rewardGrp.items.find(r=>r.sub==args.sub)
        this._trigger.emit("rlv2:get:items",[reward])
        
        rewardGrp.done=1
    }

    setTroopCarry(args:{troopCarry: string[]}) {
        this._trigger.emit("rlv2:fragment:set_troop_carry",args.troopCarry)
    }
    constructor(player: PlayerDataManager, _trigger: EventEmitter) {
        this.outer = player._playerdata.rlv2.outer
        this.current = player._playerdata.rlv2.current
        this.pinned = player._playerdata.rlv2.pinned
        this._player = player
        this._trigger = _trigger
        this._data = new RoguelikeV2Config()
        this._troop = player.troop
        this.current.game = {
            mode: "NONE",
            predefined: "",
            theme: "",
            outer: {
                support: false
            },
            start: -1,
            modeGrade: 0,
            equivalentGrade: 0
        }

        this.current.buff = {
            tmpHP: 0,
            capsule: null,
            squadBuff: []
        }
        this.current.record = { brief: null }

        this.troop = new RoguelikeTroopManager(this, this._trigger)
        this._status = new RoguelikePlayerStatusManager(this, this._trigger)
        this.inventory = new RoguelikeInventoryManager(this, this._trigger)
        this._buff = new RoguelikeBuffManager(this, this._trigger)
        this._map = new RoguelikeMapManager(this, this._trigger)
        this._module = new RoguelikeModuleManager(this, this._trigger)
        this._battle = new RoguelikeBattleManager(this, this._trigger)
        this._pool=new RoguelikePoolManager(this,this._trigger)
        this._trigger.emit("rlv2:init", this)
    }
    toJSON(): PlayerRoguelikeV2 {
        return {
            outer: this.outer,
            current: {
                player: this._status,
                record: this.current.record,
                map: this._map,
                inventory: this.inventory,
                game: this.current.game,
                troop: this.troop,
                buff: this.current.buff,
                module: this._module
            },
            pinned: this.pinned
        }
    }
}
