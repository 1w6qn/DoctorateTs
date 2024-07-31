import EventEmitter from "events";
import {  PlayerRoguelikeV2, RoguelikeNodePosition } from '../model/rlv2';
import excel from "@excel/excel";
import _ from "lodash"
import { readFileSync } from "fs";
import { RoguelikeInventoryManager } from "./rlv2/inventory";
import { TroopManager } from "../manager/TroopManager";
import { RoguelikeBuffManager } from "./rlv2/buff";
import { RoguelikePlayerStatusManager } from "./rlv2/status";
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
    _status!:RoguelikePlayerStatusManager
    _buff!: RoguelikeBuffManager
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
    async createGame(args: { theme: string, mode: string, modeGrade: number, predefinedId: string|null }): Promise<void> {
        //TODO
        await excel.initPromise
        console.log("create game", args)
        this.giveUpGame()
        this.current.game = {
            mode: args.mode,
            predefined: args.predefinedId,
            theme: args.theme,
            outer: {
                support: false
            },
            start: parseInt((new Date().getTime() / 1000).toString()),
            modeGrade: args.modeGrade,
            equivalentGrade: args.modeGrade
        }
        
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
        
        this.current.map = { zones: {} }
        this.current.module = {}
        
        this._trigger.emit("rlv2:create",this)
        switch (args.theme) {
            case "rogue_1":
                break;
            case "rogue_2":
                break;
            case "rogue_3":
                break;
            case "rogue_4":
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
    chooseInitialRelic(args:{select: string}) {
        let event = this.current.player!.pending.filter(e => e.type === "GAME_INIT_RELIC").shift()
        let relic = event!.content.initRelic!.items[args.select]
        this._trigger.emit("rlv2:relic:gain", relic)

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
        this._troop = troop
        this._status = new RoguelikePlayerStatusManager(this, this._trigger)
        this.inventory = new RoguelikeInventoryManager(this, this._trigger)
        this._buff = new RoguelikeBuffManager(this, this._trigger)
        this._trigger.emit("rlv2:init", this)
    }
    toJSON(): PlayerRoguelikeV2 {
        return {
            outer: this.outer,
            current: {
                player: this._status,
                record: this.current.record,
                map: this.current.map,
                inventory: this.inventory,
                game: this.current.game,
                troop: this.current.troop,
                buff: this.current.buff,
                module: this.current.module
            },
            pinned: this.pinned
        }
    }
}
