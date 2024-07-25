import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from './PlayerDataManager';

export class AccountManager {
    data:{[key:string]:PlayerDataManager}
    battleReplays:{[key:string]:{[key:string]:string}}
    constructor() {
        this.battleReplays = JSON.parse(readFileSync(`${__dirname}/../../../data/user/battle.json`, 'utf8'))
        this.data = {
            "1":new PlayerDataManager(JSON.parse(readFileSync(`${__dirname}/../../../t.json`, 'utf8'))as PlayerDataModel,this.battleReplays)
        };
        for(let secret in this.data){
            this.data[secret]._trigger.on("save",()=>this.savePlayerData(secret));
        }
        
    }
    getPlayerData(secret:string):PlayerDataManager {
        return this.data[secret || "1"];
    }
    savePlayerData(secret:string):void {
        writeFileSync(`${__dirname}/../../../${secret||"1"}.json`, JSON.stringify(this.data[secret||"1"],null,4));
    }
}
export const accountManager = new AccountManager();