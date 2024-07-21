import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import EventEmitter from "events";
import { PlayerDataManager } from './PlayerDataManager';

export class AccountManager {
    data:{[key:string]:PlayerDataManager}
    _trigger:EventEmitter
    constructor(_trigger:EventEmitter=new EventEmitter()) {
        this.data = {
            "1":new PlayerDataManager(JSON.parse(readFileSync(`${__dirname}/../../../t.json`, 'utf8'))as PlayerDataModel)
        };
        this._trigger = _trigger;
        this._trigger.on("save",this.savePlayerData.bind(this));
    }
    getPlayerData(secret:string):PlayerDataManager {
        return this.data[secret || "1"];
    }
    savePlayerData(secret:string):void {
        writeFileSync(`${__dirname}/../../../t.json`, JSON.stringify(this.data[secret||"1"]));
    }
}
export const accountManager = new AccountManager();