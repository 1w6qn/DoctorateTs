import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from './PlayerDataManager';

export class AccountManager {
    data: { [key: string]: PlayerDataManager }
    configs: { [key: string]: UserConfig }
    constructor() {
        this.configs = JSON.parse(readFileSync(`${__dirname}/../../../data/user/users.json`, 'utf8'))
        this.data = {}
        for (let uid in this.configs) {
            this.data[uid]=new PlayerDataManager(JSON.parse(readFileSync(`${__dirname}/../../../data/user/databases/${uid||"1"}.json`, 'utf8')) as PlayerDataModel)
            this.data[uid]._playerdata.status.uid=uid
            this.data[uid]._trigger.on("save", () => {
                this.savePlayerData(uid)
            });
        }
        console.log(`AccountManager initialized;${Object.keys(this.configs).length} users loaded.`);
    }
    getBattleReplay(uid: string, stageId: string): string {
        return this.configs[uid]?.battle.replays[stageId] || "";
    }
    saveBattleReplay(uid: string,stageId: string, replay: string): void {
        this.configs[uid]!.battle.replays[stageId]=replay
        this.saveUserConfig()
    }
    saveUserConfig(): void {
        writeFileSync(`${__dirname}/../../../data/user/users.json`, JSON.stringify(this.configs, null, 4));
    }
    getBattleInfo(uid: string,battleId:string):BattleInfo|undefined{
        return this.configs[uid]?.battle.infos[battleId];
    }
    saveBattleInfo(uid: string,battleId:string,info:BattleInfo):void{
        this.configs[uid]!.battle.infos[battleId]=info
        this.saveUserConfig()
    }
    getPlayerData(uid: string): PlayerDataManager {
        return this.data[uid || "1"];
    }
    savePlayerData(uid: string): void {
        writeFileSync(`${__dirname}/../../../data/user/databases/${uid || "1"}.json`, JSON.stringify(this.data[uid || "1"], null, 4));
    }

    getBeforeNonHitCnt(uid: string,gachaType:string):number{
        return this.configs[uid]!.gacha[gachaType].beforeNonHitCnt
    }
    saveBeforeNonHitCnt(uid: string,gachaType:string,cnt:number):void{
        this.configs[uid]!.gacha[gachaType].beforeNonHitCnt=cnt
        this.saveUserConfig()
    }
    deleteFriend(uid: string, friendUid: string): void {
        const social=this.configs[uid]!.social
        social.friends.splice(social.friends.indexOf(friendUid), 1);
        this.saveUserConfig();
    }
    addFriend(uid: string, friendUid: string): void {
        this.configs[uid]!.social.friends.push(friendUid);
        this.saveUserConfig();
    }
    searchPlayer(keyword: string): string[] {
        return []
    }
}
export interface UserConfig {
    uid: string
    social:{
        friends: string[]
    }
    battle: {
        stageId: string,
        replays: { [key: string]: string },
        infos: { [key: string]: BattleInfo }
    },
    gacha:{
        [key:string]:{
            beforeNonHitCnt:number,
        }
    },
    rlv2: {}
}
export interface BattleInfo {
    stageId:string
}
export const accountManager = new AccountManager();