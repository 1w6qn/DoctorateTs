import excel from "@excel/excel"
import { PlayerRoguelikeV2 } from "../../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../../RoguelikeV2Controller';

export class RoguelikeFragmentManager {
    index: number
    limitWeight: number
    _fragments: { [key: string]: PlayerRoguelikeV2.CurrentData.Module.InventoryFragment }
    _troopCarry: string[]
    _currInspiration: PlayerRoguelikeV2.CurrentData.Module.InventoryInspiration | null
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    get _totalWeight(): number {
        return Object.values(this._fragments).filter(f =>!f.used).reduce((acc, cur) => acc + cur.weight, 0)
    }
    get _troopWeights(): { [key: string]: number } {
        let chars = this._player.current.troop!.chars
        return Object.fromEntries(Object.entries(chars).map(([k, v]) => {
            let data = excel.CharacterTable[v.charId]
            let rarity = parseInt(data.rarity.slice(-1));
            let weight = [[2, 2, 2, 2, 3, 4], [-1, -1, -1, 4, 5, 6]][v.evolvePhase == 2 ? 1 : 0][rarity - 1]
            if (v.charId == "char_4151_tinman") {
                weight += 0
                if (v.evolvePhase > 0) {
                    weight+=v.evolvePhase==1?3:9
                    if (v.potentialRank == 2) {
                        weight += 1
                    }
                }
            }
            //TODO outbuff
            return [k, weight]
        }))
    }
    alchemy(fragmentIndex:[string,string]){
        let [f1,f2]=fragmentIndex
        //TODO
    }
    alchemyReward(fragmentIndex:[string,string]){
        let [f1,f2]=fragmentIndex
        //TODO
    }
    useInspiration(fragmentIndex: string): void {
        this._fragments[fragmentIndex].used = true
        this._currInspiration = {
            instId:fragmentIndex,
            id:this._fragments[fragmentIndex].id,
            ei:-1,
        }
    }
    use(id: string,count:number){
        for(let i=0;i<count;i++){
            let f=Object.values(this._fragments).filter(f => f.id == id &&!f.used)[i]!
            f.used=true
        }
    }
    lose(fragmentIndex: string): void {
        this._fragments[fragmentIndex].used = true
    }
    gain(id: string): void {
        let data = excel.RoguelikeTopicTable.modules.rogue_4.fragment?.fragmentData[id]
        this._fragments[id] = {
            index: `f_${this.index}`,
            id: id,
            used: false,
            ts: parseInt((new Date().getTime() / 1000).toString()),
            weight: data!.weight,
            value: data!.value,
            ei: -1
        }
        this.index += 1

    }
    init(){
        this.index = 0
        this.limitWeight = 5
    }
    continue(){}
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.index = 0
        this.limitWeight = 0
        this._fragments = player.current.module?.fragment?.fragments || {}
        this._troopCarry = player.current.module?.fragment?.troopCarry || []
        this._currInspiration = player.current.module?.fragment?.currInspiration || null
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:module:init", this.init.bind(this))
        this._trigger.on("rlv2:continue", this.continue.bind(this))
        this._trigger.on("rlv2:fragment:gain", this.gain.bind(this))
        this._trigger.on("rlv2:fragment:max_weight:add", (count)=>{
            this.limitWeight+=count
        })
        this._trigger.on("rlv2:fragment:use", this.use.bind(this))
        this._trigger.on("rlv2:fragment:lose", this.lose.bind(this))
        this._trigger.on("rlv2:fragment:use:inspiration", this.useInspiration.bind(this))

        this._trigger.on("rlv2:levelup", targetLevel => {
            this.limitWeight += excel.RoguelikeTopicTable.modules.rogue_4.fragment?.fragmentLevelData[targetLevel].weightUp as number
        })
    }



    toJSON(): PlayerRoguelikeV2.CurrentData.Module.Fragment {
        return {
            totalWeight: this._totalWeight,
            limitWeight: this.limitWeight,
            overWeight: Math.floor(this.limitWeight*1.5),
            fragments: this._fragments,
            troopWeights: this._troopWeights,
            troopCarry: this._troopCarry,
            currInspiration: this._currInspiration,
        }
    }
}