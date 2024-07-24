import EventEmitter from "events";
import { CurrentData, OuterData, PlayerRoguelikePendingEvent, PlayerRoguelikeV2, RoguelikeNodePosition } from "../model/rlv2";
import excel from "../../excel/excel";
import { Init } from "../../excel/roguelike_topic_table";

export class RoguelikeV2Controller {
    pinned?: string;
    outer: { [key: string]: OuterData; };
    current: CurrentData;
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
    async createGame(theme: string, mode: string, modeGrade: number, predefinedId: string): Promise<void> {
        //TODO
        await excel.initPromise
        let init
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
        switch (theme) {
            case "rogue_1":
                break;
            case "rogue_2":
                break;
            case "rogue_3":
                break;
            case "rogue_4":
                init = excel.RoguelikeTopicTable.details.rogue_4.init.find(
                    i => (i.modeGrade == modeGrade && i.predefinedId == predefinedId && i.modeId == mode)
                ) as Init
                this.current.player.property.hp.current = init.initialHp
                this.current.player.property.hp.max = init.initialHp
                this.current.player.property.gold = init.initialGold
                this.current.player.property.capacity = init.initialSquadCapacity
                this.current.player.property.population.max = init.initialPopulation
                this.current.player.property.shield = init.initialShield
                this.current.player.property.hpShowState = "NORMAL"
                this.current.player.toEnding = "ro4_ending_1"
                this.current.map = { zones: {} }
                this.current.troop = {
                    chars: {},
                    expedition: [],
                    expeditionDetails: {},
                    expeditionReturn: null,
                    hasExpeditionReturn: false
                };
                this.current.inventory = {
                    relic: {},
                    recruit: {},
                    trap: null,
                    consumable: {},
                    exploreTool: {}
                }
                this.current.buff = {
                    tmpHP: 0,
                    capsule: null,
                    squadBuff: []
                }
                this.current.record={
                    brief:null
                }
                let pending: PlayerRoguelikePendingEvent[] = []
                pending.push({
                    index: "",
                    type: "GAME_INIT_RELIC",
                    content: {
                        initRelic: {
                            step: [1, 4],
                            items: init.initialBandRelic.reduce((acc, cur, idx) => {
                                return { ...acc, [idx.toString()]: { id: cur, count: 1 } }
                            }, {})
                        }
                    }
                })
                pending.push({
                    index: "",
                    type: "GAME_INIT_SUPPORT",
                    content: {
                        initSupport: {
                            step: [2, 4],
                            scene: {
                                id: "scene_ro4_startbuff_enter",
                                choices: {
                                    "choice_ro4_startbuff_5": 1,
                                    "choice_ro4_startbuff_3": 1,
                                    "choice_ro4_startbuff_6": 1
                                }
                            }
                        }
                    }
                })
                pending.push({
                    index: "",
                    type: "GAME_INIT_RECRUIT_SET",
                    content: {
                        initRecruitSet: {
                            step: [3, 4],
                            option: init.initialRecruitGroup
                        }
                    }
                })
                pending.push({
                    index: "",
                    type: "GAME_INIT_RECRUIT",
                    content: {
                        initRecruit: {
                            step: [4, 4],
                            tickets: [],
                            showChar: [],
                            team: null
                        }
                    }
                })
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




    //PENDING
    gameInit(init: Init): PlayerRoguelikePendingEvent[] {


        return []
    }

    constructor(data: PlayerRoguelikeV2, _trigger: EventEmitter) {
        this.outer = data.outer
        this.current = data.current
        this.pinned = data.pinned
    }
}