import EventEmitter from "events";
import { DexNav, PlayerBuilding } from "../model/playerdata";
import excel from "@excel/excel";
import { PlayerCharacter } from "@game/model/character";
import { now } from "@utils/time";
import { max } from "lodash";


export class BuildingManager {
    _dexnav: DexNav;
    _trigger: EventEmitter;
    constructor(dexnav: DexNav, _trigger: EventEmitter) {

        this._dexnav = dexnav;
        this._trigger = _trigger;
        this._trigger.on("char:get", (charId: string, args: {from:string}={from:"NORMAL"}) => {
            if(charId in this._dexnav.character){
                if (args.from === "CLASSIC") {
                    this._dexnav.character[charId].classicCount=1+this._dexnav.character[charId].count||0
                }else{
                    this._dexnav.character[charId].count+=1
                }
            }else{
                this._dexnav.character[charId] = {
                    charInstId:max(Object.values(this._dexnav.character).map(k=>k.count))!+1,
                    count:1
                }
            }
        })
    }

    toJSON() {
        return {
            dex: this._dexnav
        }
    }

}