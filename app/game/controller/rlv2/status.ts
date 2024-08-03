import { EventEmitter } from "events"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from '../../model/rlv2';

import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import excel from "@excel/excel";
import { RoguelikeEventManager, RoguelikePendingEvent } from "./events";



export class RoguelikePlayerStatusManager implements PlayerRoguelikeV2.CurrentData.PlayerStatus {
    state!:string
    property!: PlayerRoguelikeV2.CurrentData.PlayerStatus.Properties
    cursor!: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition;
    trace!: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition[];
    status!: PlayerRoguelikeV2.CurrentData.PlayerStatus.Status;
    toEnding!: string;
    chgEnding!: boolean;
    _pending:RoguelikeEventManager
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this.init()
        this._pending = new RoguelikeEventManager(this._player, _trigger)
        this._trigger = _trigger
        this._trigger.on("rlv2:create", this.create.bind(this))
        this._trigger.on('rlv2:get:items', (items: RoguelikeItemBundle[])=>items.forEach(item=>this.getItem(item)))
    }
    get pending(): RoguelikePendingEvent[] {
        return this._pending._pending
    }
    init(){
        let _status = this._player.current.player || {
            state: "NONE",
            property: {
                exp: 0,
                level: 1,
                maxLevel: 0,
                hp: { current: 0, max: 0 },
                gold: 0,
                shield: 0,
                capacity: 0,
                population: { cost: 0, max: 0 },
                conPerfectBattle: 0,
                hpShowState: "NORMAL"
            },
            cursor: { zone: 0, position: null },
            trace: [],
            pending: [],
            status: { bankPut: 0 },
            toEnding: "",
            chgEnding: false
        }
        this.state = _status.state
        this.property = _status.property
        this.cursor = _status.cursor
        this.trace = _status.trace
        this.chgEnding = _status.chgEnding
        this.toEnding = _status.toEnding
        this.status = _status.status
    }
    async create() {
        await excel.initPromise
        let game = this._player.current.game!
        let init = excel.RoguelikeTopicTable.details.rogue_4.init.find(
            i => (i.modeGrade == game.modeGrade && i.predefinedId == game.predefined && i.modeId == game.mode)
        )!
        this.state = "INIT"
        this.property.hp.current = init.initialHp
        this.property.hp.max = init.initialHp
        this.property.gold = init.initialGold
        this.property.capacity = init.initialSquadCapacity
        this.property.population.max = init.initialPopulation
        this.property.shield = init.initialShield
        this.toEnding = `ro${game.theme.slice(-1)}_ending_1`
    }

    bankPut() {
        let theme = this._player.current.game!.theme
        let succeed = Math.random() <= 0.5
        if (succeed && this._player.outer[theme].bank.current <= 999) {
            this.status.bankPut += 1
            this._player.outer[theme].bank.current += 1
            this._trigger.emit("rlv2:bankPut", succeed)
        }

    }
    getItem(item: RoguelikeItemBundle){
        const type=item.type||excel.RoguelikeTopicTable.details.rogue_4.items[item.id].type
        
        switch (type) {
            case "HP":
                this.property.hp.current += item.count
                if (this.property.hp.current > this.property.hp.max) {
                    this.property.hp.current = this.property.hp.max
                }
                break;
            case "HPMAX":
                this.property.hp.current += item.count
                this.property.hp.max += item.count
                break;
            case "GOLD":
                this.property.gold += item.count
                break;
            case "POPULATION":
                if(item.count>=0){
                    this.property.population.max += item.count
                }else{
                    this.property.population.cost -= item.count
                }
                
                break;
            case "EXP":
                this.property.exp += item.count
                let map=excel.RoguelikeTopicTable.details.rogue_4.detailConst.playerLevelTable
                while(this.property.exp >= map[this.property.level+1].exp){
                    this.property.level += 1
                    this.property.exp -= map[this.property.level+1].exp
                    this._trigger.emit("rlv2:levelup",this.property.level)
                    this.property.population.max += map[this.property.level+1].populationUp
                    this.property.capacity += map[this.property.level+1].squadCapacityUp
                    this.property.hp.max += map[this.property.level+1].maxHpUp
                    this.property.hp.current += map[this.property.level+1].populationUp
                    
                }
                break;
            case "SQUAD_CAPACITY":
                this.property.capacity += item.count
                break;
            case "SHIELD":
                this.property.shield+=item.count
                break;
            default:
                break;
        }
        
    }
    toJSON(): PlayerRoguelikeV2.CurrentData.PlayerStatus {
        return {
            state: this.state,
            property: this.property,
            cursor: this.cursor,
            trace: this.trace,
            pending: this.pending,
            status: this.status,
            toEnding: this.toEnding,
            chgEnding: this.chgEnding,
        }
    }
}

