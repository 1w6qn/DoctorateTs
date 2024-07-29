import { RoguelikeGameInitData } from "../../../excel/roguelike_topic_table"
import { PlayerRoguelikePendingEvent } from "../../model/rlv2"
import _ from "lodash"
import { RoguelikeV2Controller } from "../RoguelikeV2Controller"

export class RoguelikePendingEvent implements PlayerRoguelikePendingEvent {
    
    type: string
    content: PlayerRoguelikePendingEvent.Content
    _index: number
    _player: RoguelikeV2Controller
    [key: string]: any
    constructor(_player: RoguelikeV2Controller,type: string, index: number, args: {}) {
        this._player = _player
        this.type = type
        this._index = index
        this.content = this[type](args) as PlayerRoguelikePendingEvent.Content
    }
    get index():string{
        return `e_${this._index}`
    }
    GAME_INIT_RELIC(args: { step: number[], initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initRelic: {
                step: args.step,
                items: args.initConfig.initialBandRelic.reduce((acc, cur, idx) => {
                    return { ...acc, [idx.toString()]: { id: cur, count: 1 } }
                }, {})
            }
        }
    }
    GAME_INIT_SUPPORT(args: { step: number[]}): PlayerRoguelikePendingEvent.Content {
        return {
            initSupport: {
                step: args.step,
                scene: {
                    id: "scene_ro4_startbuff_enter",
                    choices: _.sampleSize(this._data, 3).reduce((acc, cur) => ({ ...acc, [cur]: 1 }), {})
                }
            }
        }
    }
    GAME_INIT_RECRUIT_SET(args: { step: number[], initConfig: RoguelikeGameInitData }): PlayerRoguelikePendingEvent.Content {
        return {
            initRecruitSet: {
                step: args.step,
                option: args.initConfig.initialRecruitGroup as string[]
            }
        }
    }
    GAME_INIT_RECRUIT(args: { step: number[]}): PlayerRoguelikePendingEvent.Content {
        return {
            initRecruit: {
                step: args.step,
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
    BATTLE_SHOP(args: {}): PlayerRoguelikePendingEvent.Content {
        this._trigger.on("rlv2:bankPut", (broken:boolean)=>{
            this.content.battleShop!.bank.canPut=broken
        })
        return {
            /*
            battleShop: {
                bank:{
                    open:true,
                    canPut:true,
                    canWithdraw:true,
                    withdraw:0,
                    cost:1,
                    withdrawLimit:20
                },
            }*/
        }
    }
    
    toJSON(): PlayerRoguelikePendingEvent {
        return {
            index: this.index,
            type: this.type,
            content: this.content
        }
    }

}