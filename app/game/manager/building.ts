import EventEmitter from "events";
import { PlayerBuilding, PlayerBuildingChar, PlayerBuildingFurnitureInfo, PlayerBuildingRoom, PlayerBuildingRoomSlot, PlayerBuildingSolution, PlayerBuildingStatus } from "../model/playerdata";
import excel from "@excel/excel";
import { PlayerCharacter } from "@game/model/character";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";


export class BuildingManager implements PlayerBuilding {
    status: PlayerBuildingStatus;
    chars: { [key: string]: PlayerBuildingChar; };
    roomSlots: { [key: string]: PlayerBuildingRoomSlot; };
    rooms: PlayerBuildingRoom;
    furniture: { [key: string]: PlayerBuildingFurnitureInfo; };
    diyPresetSolutions: {};
    assist: number[];
    solution: PlayerBuildingSolution;
    _trigger: EventEmitter;
    constructor(player: PlayerDataManager, _trigger: EventEmitter) {
        this.status=player._playerdata.building.status
        this.chars=player._playerdata.building.chars
        this.roomSlots=player._playerdata.building.roomSlots
        this.rooms=player._playerdata.building.rooms
        this.furniture=player._playerdata.building.furniture
        this.diyPresetSolutions=player._playerdata.building.diyPresetSolutions
        this.assist=player._playerdata.building.assist
        this.solution=player._playerdata.building.solution
        this._trigger = _trigger;
        this._trigger.on("building:char:init", (char: PlayerCharacter) => {
            this.chars[char.instId]={
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
    get boardInfo():string[]{
        return Object.keys(Object.values(this.rooms.MEETING)[0].board)
    }
    get infoShare():number{
        return Object.values(this.rooms.MEETING)[0].infoShare.ts
    }
    get furnCnt():number{
        //TODO
        return Object.keys(this.furniture).length
    }
    toJSON():PlayerBuilding {
        return {
            status:this.status,
            chars:this.chars,
            roomSlots:this.roomSlots,
            rooms:this.rooms,
            furniture:this.furniture,
            diyPresetSolutions:this.diyPresetSolutions,
            assist:this.assist,
            solution:this.solution
        }
    }

}