import { EventEmitter } from "events"
import { PlayerRoguelikePendingEvent, PlayerRoguelikeV2 } from "../../model/rlv2"

import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import excel from "@excel/excel";
import { RoguelikeGameInitData } from "app/excel/roguelike_topic_table";
import { RoguelikeEventManager, RoguelikePendingEvent } from "./events";



export class RoguelikePlayerStatusManager implements PlayerRoguelikeV2.CurrentData.PlayerStatus {
    property: PlayerRoguelikeV2.CurrentData.PlayerStatus.Properties
    cursor: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition
    trace: PlayerRoguelikeV2.CurrentData.PlayerStatus.NodePosition[]
    status: PlayerRoguelikeV2.CurrentData.PlayerStatus.Status
    toEnding: string
    chgEnding: boolean
    _pending:RoguelikeEventManager
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
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
        this.property = _status.property
        this.cursor = _status.cursor
        this.trace = _status.trace
        this.chgEnding = _status.chgEnding
        this.toEnding = _status.toEnding
        this.status = _status.status
        this._pending = new RoguelikeEventManager(this._player, _trigger)
        this._trigger = _trigger
        this._trigger.on("rlv2:create", this.create.bind(this))
    }
    get pending(): RoguelikePendingEvent[] {
        return this._pending._pending
    }
    get state(): string {
        if (this._player.current.game!.start == -1) return "NONE"
        if (this.pending.some(e => e.type.includes("INIT"))) return "INIT"
        if (this.pending) return "PENDING"
        return "WAIT_MOVE"
    }
    async create() {
        await excel.initPromise
        let game = this._player.current.game!
        let init = excel.RoguelikeTopicTable.details.rogue_4.init.find(
            i => (i.modeGrade == game.modeGrade && i.predefinedId == game.predefined && i.modeId == game.mode)
        )!
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

