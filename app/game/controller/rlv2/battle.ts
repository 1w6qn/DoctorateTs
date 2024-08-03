import { EventEmitter } from "events"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import { BattleData } from "@game/model/battle";
import { decryptBattleData, decryptBattleLog } from "@utils/crypt";

export class RoguelikeBattleManager {

    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        
        this._player = player
        this._trigger = _trigger
        this._trigger.on('rlv2:battle:start', this.start.bind(this))
        this._trigger.on('rlv2:battle:finish', this.finish.bind(this))
    }
    start(stageId: string){
        let battleId="1"
        let sanity=0
        let diceRoll=[]
        if("SANCHECK" in this._player._module._modules){
            sanity=this._player._module.toJSON().san?.sanity||sanity
        }
        if("DICE" in this._player._module._modules){
            //TODO
        }
        this._trigger.emit('rlv2:event:create',"BATTLE",{
            state: 1,
            chestCnt: 1,
            goldTrapCnt: 0,
            diceRoll: [],
            boxInfo: {},
            tmpChar: [],
            sanity: sanity,
            unKeepBuff: this._player._buff._buffs
        })
        this._trigger.emit("save:battle",battleId,{stageId:stageId})
    }
    async finish(args:{battleLog:string,data:string,battleData:BattleData}){
        let battleId="1"
        const loginTime=this._player._player.loginTime
        const data=decryptBattleData(args.data,loginTime)
        //const battleLog=await decryptBattleLog(args.battleLog)
        console.log(data)
        //console.log(battleLog)
        let info=this._player._player.getBattleInfo(battleId)
        let event=this._player._status.pending.shift()
        //TODO: 处理战斗结果
        this._player._status.state="WAIT_MOVE"
    }
}

