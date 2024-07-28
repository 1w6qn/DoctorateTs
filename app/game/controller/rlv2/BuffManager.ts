import { RoguelikeGameItemData } from "../../../excel/roguelike_topic_table"
import { Blackboard } from "../../../excel/character_table"
import excel from "../../../excel/excel"
import { PlayerRoguelikeV2, RoguelikeBuff } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from "../RoguelikeV2Controller"

export class RoguelikeBuffManager {
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    _buffs: RoguelikeBuff[]
    _status:PlayerRoguelikeV2.CurrentData.PlayerStatus
    [key: string]: any
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._status = this._player.current!.player as PlayerRoguelikeV2.CurrentData.PlayerStatus
        this._buffs = Object.values(player.inventory!.relic).reduce((acc, relic) => {
            let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[relic.id].buffs.filter(buff => buff.key != "immediate_reward")
            return [...acc, ...buffs]
        }, [] as RoguelikeBuff[])
        this._trigger = _trigger
        this._trigger.on("rlv2:buff:apply", this.applyBuffs.bind(this))
    }
    applyBuffs(...args: RoguelikeBuff[]) {
        args.forEach(arg => {
            if (arg.key == "immediate_reward") {
                this.immediate_reward(arg.blackboard)
            } else {
                this._buffs.push(arg)
            }
        })
    }
    filterBuffs(key: string): RoguelikeBuff[] {
        return this._buffs.filter(buff => buff.key == key)
    }
    generateBuff(key:string,id:string,value:number):RoguelikeBuff{
        switch(key){
            case "immediate_reward":
                return {key:key,blackboard:[{key: "id",value: 0.0,valueStr: id},{key: "count",value: value,valueStr: null}]}
                break
        }
        return {key:key,blackboard:[]}
    }
    immediate_reward(blackboard: Blackboard) {
        let item: RoguelikeGameItemData = excel.RoguelikeTopicTable.details.rogue_4.items[blackboard[0].valueStr as string]
        switch (item.type) {
            case "HP":
                this._status!.property.hp.current += blackboard[1].value
                if (this._status!.property.hp.current > this._status!.property.hp.max) {
                    this._status!.property.hp.current = this._status!.property.hp.max
                }
                break;
            case "HPMAX":
                this._status!.property.hp.current += blackboard[1].value
                this._status!.property.hp.max += blackboard[1].value
                break;
            case "GOLD":
                this._status!.property.gold += blackboard[1].value
                break;
            case "POPULATION":
                this._status!.property.population.max += blackboard[1].value
                break;
            case "EXP":
                this._status!.property.exp += blackboard[1].value
                let map=excel.RoguelikeTopicTable.details.rogue_4.detailConst.playerLevelTable
                while(this._status!.property.exp >= map[this._status!.property.level+1].exp){

                    this._status!.property.level += 1
                    this._status!.property.exp -= map[this._status!.property.level+1].exp
                    this._trigger.emit("rlv2:levelup",this._status!.property.level)

                    this._status!.property.population.max += map[this._status!.property.level+1].populationUp
                    this._status!.property.capacity += map[this._status!.property.level+1].squadCapacityUp
                    this._status!.property.hp.max += map[this._status!.property.level+1].maxHpUp
                    this._status!.property.hp.current += map[this._status!.property.level+1].populationUp
                    
                }
                break;
            case "SQUAD_CAPACITY":
                this._status!.property.capacity += blackboard[1].value
                break;
            case "MAX_WEIGHT":
                this._trigger.emit("rlv2:fragment:max_weight:add", blackboard[1].value)
                break
            default:
                console.log(blackboard[0].valueStr)
                break;
        }
    }
}
/*
// Assembly-CSharp
enum Torappu.RoguelikeGameItemType : System.Enum
{
    System.Int32 value__; // 0x8
    static Torappu.RoguelikeGameItemType NONE = 0;
    static Torappu.RoguelikeGameItemType HP = 1;
    static Torappu.RoguelikeGameItemType HPMAX = 2;
    static Torappu.RoguelikeGameItemType GOLD = 3;
    static Torappu.RoguelikeGameItemType POPULATION = 4;
    static Torappu.RoguelikeGameItemType EXP = 5;
    static Torappu.RoguelikeGameItemType SQUAD_CAPACITY = 6;
    static Torappu.RoguelikeGameItemType RECRUIT_TICKET = 7;
    static Torappu.RoguelikeGameItemType UPGRADE_TICKET = 8;
    static Torappu.RoguelikeGameItemType RELIC = 9;
    static Torappu.RoguelikeGameItemType BP_POINT = 10;
    static Torappu.RoguelikeGameItemType GROW_POINT = 11;
    static Torappu.RoguelikeGameItemType BAND = 12;
    static Torappu.RoguelikeGameItemType ACTIVE_TOOL = 13;
    static Torappu.RoguelikeGameItemType CAPSULE = 14;
    static Torappu.RoguelikeGameItemType POOL = 15;
    static Torappu.RoguelikeGameItemType RL_BP = 16;
    static Torappu.RoguelikeGameItemType RL_GP = 17;
    static Torappu.RoguelikeGameItemType KEY_POINT = 18;
    static Torappu.RoguelikeGameItemType SAN_POINT = 19;
    static Torappu.RoguelikeGameItemType DICE_POINT = 20;
    static Torappu.RoguelikeGameItemType DICE_TYPE = 21;
    static Torappu.RoguelikeGameItemType SHIELD = 22;
    static Torappu.RoguelikeGameItemType LOCKED_TREASURE = 23;
    static Torappu.RoguelikeGameItemType CUSTOM_TICKET = 24;
    static Torappu.RoguelikeGameItemType TOTEM = 25;
    static Torappu.RoguelikeGameItemType TOTEM_EFFECT = 26;
    static Torappu.RoguelikeGameItemType FEATURE = 27;
    static Torappu.RoguelikeGameItemType VISION = 28;
    static Torappu.RoguelikeGameItemType CHAOS = 29;
    static Torappu.RoguelikeGameItemType CHAOS_PURIFY = 30;
    static Torappu.RoguelikeGameItemType CHAOS_LEVEL = 31;
    static Torappu.RoguelikeGameItemType EXPLORE_TOOL = 32;
    static Torappu.RoguelikeGameItemType FRAGMENT = 33;
    static Torappu.RoguelikeGameItemType MAX_WEIGHT = 34;
    static Torappu.RoguelikeGameItemType DISASTER = 35;
    static Torappu.RoguelikeGameItemType DISASTER_TYPE = 36;
    static Torappu.RoguelikeGameItemType ABSTRACT_DISASTER = 37;
    
}
*/