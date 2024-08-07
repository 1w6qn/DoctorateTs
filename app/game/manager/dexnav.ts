import EventEmitter from "events";
import { PlayerCharacterRecord, PlayerDexNav, PlayerEnemyHandBook, PlayerFormulaUnlockRecord } from "../model/playerdata";

import { max } from "lodash";
import { PlayerDataManager } from "./PlayerDataManager";


export class DexNavManager implements PlayerDexNav {
    
    character: { [key: string]: PlayerCharacterRecord; };
    formula: PlayerFormulaUnlockRecord;
    enemy: PlayerEnemyHandBook;
    teamV2: { [key: string]: { [key: string]: number; }; };
    _trigger: EventEmitter;
    constructor(player: PlayerDataManager, _trigger: EventEmitter) {
        this.character=player._playerdata.dexNav.character;
        this.formula=player._playerdata.dexNav.formula;
        this.enemy=player._playerdata.dexNav.enemy;
        this.teamV2=player._playerdata.dexNav.teamV2;
        this._trigger = _trigger;
        this._trigger.on("char:get", (charId: string, args: {from:string}={from:"NORMAL"}) => {
            if(charId in this.character){
                if (args.from === "CLASSIC") {
                    this.character[charId].classicCount=1+this.character[charId].count||0
                }else{
                    this.character[charId].count+=1
                }
            }else{
                this.character[charId] = {
                    charInstId:max(Object.values(this.character).map(k=>k.count))!+1,
                    count:1
                }
            }
        })
    }
    get teamV2Info():{[key:string]:number}{
        return Object.entries(this.teamV2).reduce((acc, [k,v])=>(
            {...acc, [k]:Object.keys(v).length}
        ),{})
    }

    toJSON():PlayerDexNav {
        return {
            character: this.character,
            formula:this.formula,
            enemy:this.enemy,
            teamV2:this.teamV2
        }
    }

}