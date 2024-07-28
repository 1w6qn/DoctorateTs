import EventEmitter from "events";
import { PlayerRoguelikePendingEvent, PlayerRoguelikeV2, RoguelikeNodePosition } from "../model/rlv2";
import excel from "../../excel/excel";
import { RoguelikeGameInitData } from "../../excel/roguelike_topic_table";
import _ from "lodash"
import { readFileSync } from "fs";
import { RoguelikeInventoryManager } from "./rlv2/InventoryManager";
import { TroopManager } from "../manager/TroopManager";
import { RoguelikeBuffManager } from "./rlv2/BuffManager";
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
            "mode": "NONE",
            "predefined": null,
            "theme": "",
            "outer": {
                "support": false
            },
            "start": -1,
            "modeGrade": 0,
            "equivalentGrade": 0
        }
        this.current.player = {
            state: "INIT",
            property: {
                exp: 0,
                level: 1,
                maxLevel: 10,
                hp: { current: 4, max: 4 },
                gold: 20,
                shield: 2,
                capacity: 7,
                population: { cost: 0, max: 6 },
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
                init = excel.RoguelikeTopicTable.details.rogue_4.init.find(
                    i => (i.modeGrade == args.modeGrade && i.predefinedId == args.predefinedId && i.modeId == args.mode)
                ) as RoguelikeGameInitData
                this.current.player.property.hp.current = init.initialHp
                this.current.player.property.hp.max = init.initialHp
                this.current.player.property.gold = init.initialGold
                this.current.player.property.capacity = init.initialSquadCapacity
                this.current.player.property.population.max = init.initialPopulation
                this.current.player.property.shield = init.initialShield
                this.current.player.property.hpShowState = "NORMAL"
                this.current.player.toEnding = "ro4_ending_1"



                let pending: RoguelikePendingEvent[] = []
                pending.push(new RoguelikePendingEvent("GAME_INIT_RELIC", 0, { step: 1, initConfig: init }))
                pending.push(new RoguelikePendingEvent("GAME_INIT_SUPPORT", 1, { step: 2, initConfig: init }))
                pending.push(new RoguelikePendingEvent("GAME_INIT_RECRUIT_SET", 2, { step: 3, initConfig: init }))
                pending.push(new RoguelikePendingEvent("GAME_INIT_RECRUIT", 3, { step: 4, initConfig: init }))
                this.pending = pending
                this.current.player.pending = pending.map(e => e.toJSON())
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
        this.current.module!.fragment!.troopCarry = troopCarry
        this.current.module!.fragment!.limitWeight = this.current.module!.fragment!.troopCarry.reduce(
            (acc, cur) => acc + this.current.module!.fragment!.troopWeights[cur], 0
        )
        this.current.module!.fragment!.overWeight = Math.floor(this.current!.module!.fragment!.limitWeight * 1.5)

    }
    constructor(data: PlayerRoguelikeV2, troop: TroopManager, _trigger: EventEmitter) {
        this.outer = data.outer
        this.current = data.current
        this.pinned = data.pinned
        this._trigger = _trigger
        this._data = new RoguelikeV2Config()
        this._buff = new RoguelikeBuffManager(this.current, this._trigger)

        this._troop = troop
    }
    toJSON(): PlayerRoguelikeV2 {
        return {
            outer: this.outer,
            current: {
                player: this.current.player,
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
export class RoguelikePendingEvent {
    index: number
    type: string
    content: PlayerRoguelikePendingEvent.Content
    [key: string]: any
    constructor(type: string, index: number, args: {}) {
        this.type = type
        this.index = index
        this.content = this[type](args) as PlayerRoguelikePendingEvent.Content
    }
    GAME_INIT_RELIC(args: { step: number, initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initRelic: {
                step: [args.step, 4],
                items: args.initConfig.initialBandRelic.reduce((acc, cur, idx) => {
                    return { ...acc, [idx.toString()]: { id: cur, count: 1 } }
                }, {})
            }
        }
    }
    GAME_INIT_SUPPORT(args: { step: number, initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initSupport: {
                step: [args.step, 4],
                scene: {
                    id: "scene_ro4_startbuff_enter",
                    choices: _.sampleSize(this._data, 3).reduce((acc, cur) => ({ ...acc, [cur]: 1 }), {})
                }
            }
        }
    }
    GAME_INIT_RECRUIT_SET(args: { step: number, initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initRecruitSet: {
                step: [args.step, 4],
                option: args.initConfig.initialRecruitGroup as string[]
            }
        }
    }
    GAME_INIT_RECRUIT(args: { step: number, initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initRecruit: {
                step: [args.step, 4],
                tickets: [],
                showChar: [],
                team: null
            }
        }
    }
    RECRUIT(args: { tickets: string }): PlayerRoguelikePendingEvent.Content {
        return {
            recruit: {
                ticket: args.tickets
            }
        }
    }

    toJSON(): PlayerRoguelikePendingEvent {
        return {
            index: `e_${this.index}`,
            type: this.type,
            content: this.content
        }
    }

}