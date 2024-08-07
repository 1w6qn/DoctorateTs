import EventEmitter from "events";
import { PlayerBuilding } from "../model/playerdata";
import excel from "@excel/excel";
import { PlayerCharacter } from "@game/model/character";
import { now } from "@utils/time";


export class BuildingManager {
    _building: PlayerBuilding;
    _trigger: EventEmitter;
    constructor(building: PlayerBuilding, _trigger: EventEmitter) {

        this._building = building;
        this._trigger = _trigger;
        this._trigger.on("building:char:init", (char: PlayerCharacter) => {
            this._building.chars[char.instId]={
                charId:char.charId,
                lastApAddTime:now(),
                ap:8640000,
                roomSlotId:"",
                index:-1,
                changeScale:0,
                bubble:{
                    normal:{
                        add:-1,
                        ts:0
                    },
                    assist:{
                        add:-1,
                        ts:0
                    }
                },
                workTime:0
            }
        })
    }

    toJSON() {
        return {
            building: this._building
        }
    }

}