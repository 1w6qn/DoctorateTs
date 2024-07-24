import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import EventEmitter from "events";

export class BattleManager {
    _playerdata: PlayerDataModel;
    _config: { [key: string]: { [key: string]: string; }; };
    _trigger: EventEmitter;
    
    constructor(_playerdata:PlayerDataModel,config:{[key:string]:{[key:string]:string}},_trigger:EventEmitter) {
        this._playerdata = _playerdata;
        this._config = config;
        this._trigger = _trigger;
        
    }
    start(...args:[]){

    }
    finish(...args:[]){

    }
    
}
