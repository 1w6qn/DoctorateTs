import EventEmitter from "events";
import { PlayerRoguelikePendingEvent, PlayerRoguelikeV2, RoguelikeNodePosition } from '../model/rlv2';
import excel from "../../excel/excel";
import { RoguelikeGameInitData } from "../../excel/roguelike_topic_table";
import _ from "lodash"
import { readFileSync } from "fs";
import { RoguelikeInventoryManager } from "./rlv2/InventoryManager";
import { TroopManager } from "../manager/TroopManager";
import { RoguelikeBuffManager } from "./rlv2/BuffManager";
import { RoguelikePendingEvent } from "./rlv2/EventManager";
import { RoguelikePlayerStatusManager } from "./rlv2/PlayerStatusManager";
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
    pending!: RoguelikePendingEvent[]
    _status!:RoguelikePlayerStatusManager
    _buff: RoguelikeBuffManager
    _troop: TroopManager
    _data: RoguelikeV2Config;
    _trigger: EventEmitter
    inventory!: RoguelikeInventoryManager | null;
    setPinned(id: string): void {
        this.pinned = id
    }
    giveUpGame(): void {
        this.current = {
            player: null,
            record: null,
            map: null,
            inventory: null,
            game: null,
            troop: null,
            buff: null,
            module: null
        }
    }
    async createGame(args: { theme: string, mode: string, modeGrade: number, predefinedId: string }): Promise<void> {
        //TODO
        await excel.initPromise
        console.log("create game", args)
        let init
        this.current.game = {
            mode: "NONE",
            predefined: null,
            theme: "",
            outer: {
                support: false
            },
            start: -1,
            modeGrade: 0,
            equivalentGrade: 0
        }
        this.current.player = new RoguelikePlayerStatusManager(this, this._trigger)
        this.current.troop = {
            chars: {},
            expedition: [],
            expeditionDetails: {},
            expeditionReturn: null,
            hasExpeditionReturn: false
        };
        this.current.buff = {
            tmpHP: 0,
            capsule: null,
            squadBuff: []
        }
        this.current.record = { brief: null }
        this.inventory = new RoguelikeInventoryManager(this, this._trigger)
        this.current.map = { zones: {} }
        switch (args.theme) {
            case "rogue_1":
                break;
            case "rogue_2":
                break;
            case "rogue_3":
                break;
            case "rogue_4":
                //this.current.module!.fragment=new RoguelikeFragmentManager(this,this._trigger)
                this.current.module = {}

                break
            default:
                break;
        }
    }
    moveTo(to: RoguelikeNodePosition): void {
        this.current.player!.cursor.position = to
        this.current.player!.state = "PENDING"
        //TODO

    }
    chooseInitialRelic(select: string) {
        let event = this.current.player!.pending.shift()
        let relic = event!.content.initRelic!.items[select]
        this.inventory?.relic.gain(relic.id, relic.count)

    }



    setTroopCarry(troopCarry: string[]) {
        this.current.module!.fragment

    }
    constructor(data: PlayerRoguelikeV2, troop: TroopManager, _trigger: EventEmitter) {
        this.outer = data.outer
        this.current = data.current
        this.pinned = data.pinned
        this._trigger = _trigger
        this._data = new RoguelikeV2Config()
        this._buff = new RoguelikeBuffManager(this, this._trigger)

        this._troop = troop
    }
    toJSON(): PlayerRoguelikeV2 {
        return {
            outer: this.outer,
            current: {
                player: this._status,
                record: this.current.record,
                map: this.current.map,
                inventory: this.inventory?.toJSON() || null,
                game: this.current.game,
                troop: this.current.troop,
                buff: this.current.buff,
                module: this.current.module
            },
            pinned: this.pinned
        }
    }
}
