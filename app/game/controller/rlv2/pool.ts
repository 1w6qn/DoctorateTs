import excel from "@excel/excel"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../rlv2';
import { now } from "@utils/time";
import { randomChoice } from "@utils/random";

export class RoguelikePoolManager {
    _pools:{[id:string]:string[]}
    
    _player: RoguelikeV2Controller
    _trigger: EventEmitter


    
    recycle(id: string):void{

    }
    put(id: string): void {
        
    }
    init(){
        this._pools = {}
    }
    async create(){
        await excel.initPromise
        const theme=this._player.current.game!.theme
        this._pools["pool_sacrifice_n"]=[]
        this._pools["pool_sacrifice_r"]=[]
        let fragment=excel.RoguelikeTopicTable.modules[theme].fragment
        if(fragment){
            this._pools["pool_fragment_3"]=[]
            this._pools["pool_fragment_4"]=[]
            this._pools["pool_fragment_5"]=[]
            Object.values(fragment.fragmentData).forEach(data=>{
                if(data.type=="INSPIRATION"){
                    this._pools["pool_fragment_3"].push(data.id)
                }else if(data.type=="WISH"){
                    this._pools["pool_fragment_4"].push(data.id)
                }else if(data.type=="IDEA"){
                    this._pools["pool_fragment_5"].push(data.id)
                }
                
            })
        }
        Object.values(excel.RoguelikeTopicTable.details[theme].items).filter(data=>data.canSacrifice).forEach(data=>{
            if(data.value==8){
                this._pools["pool_sacrifice_n"].push(data.id)
            }
            else if(data.value==12){
                this._pools["pool_sacrifice_r"].push(data.id)
            }
        })
        
        
    }
    get(id: string,putback=false): RoguelikeItemBundle {
        let res=this._pools[id]?randomChoice(this._pools[id]):""
        if(putback){
            
        }else{
            this._pools[id].splice(this._pools[id].indexOf(res),1)
        }
        return {id:res,count:1}
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._pools = {}
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:relic:recycle", this.recycle.bind(this))
        this._trigger.on("rlv2:init",this.init.bind(this))
        this._trigger.on("rlv2:create",this.create.bind(this))
    }
    


    
}