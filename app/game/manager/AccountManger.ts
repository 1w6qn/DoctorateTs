import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import EventEmitter from "events";
import { PlayerDataManager } from './PlayerDataManager';

export class AccountManager {
    data:{[key:string]:PlayerDataManager}
    constructor() {
        this.data = {
            "1":new PlayerDataManager(JSON.parse(readFileSync(`${__dirname}/../../../t.json`, 'utf8'))as PlayerDataModel)
        };
        for(let secret in this.data){
            this.data[secret]._trigger.on("save",()=>this.savePlayerData(secret));
        }
        
    }
    getPlayerData(secret:string):PlayerDataManager {
        return this.data[secret || "1"];
    }
    savePlayerData(secret:string):void {
        writeFileSync(`${__dirname}/../../../t.json`, JSON.stringify(this.data[secret||"1"],null,4));
    }
}
export const accountManager = new AccountManager();