import { readFileSync, writeFileSync } from "fs";
import { PlayerDataModel } from "../model/playerdata";
import EventEmitter from "events";
import { PlayerSquad, SquadFriendData } from "../model/character";
import excel from "../../excel/excel";
import CryptoJS from "crypto-js";
export interface CommonStartBattleRequest {
    isRetro: number
    pray: number
    battleType: number
    continuous: {
        battleTimes: number
    }
    usePracticeTicket: number,
    stageId: string,
    squad: PlayerSquad
    assistFriend: null | SquadFriendData
    isReplay: number
    startTs: number
}


const LOG_TOKEN_KEY = "pM6Umv*^hVQuB6t&";


export class BattleManager {
    _playerdata: PlayerDataModel;
    _config: { [key: string]: { [key: string]: string; }; };
    _trigger: EventEmitter;

    constructor(_playerdata: PlayerDataModel, config: { [key: string]: { [key: string]: string } }, _trigger: EventEmitter) {
        this._playerdata = _playerdata;
        this._config = config;
        this._trigger = _trigger;

    }
    decryptBattleData(data: string) {
        const battleData = CryptoJS.enc.Hex.parse(data.slice(0, data.length - 32));
        const src = LOG_TOKEN_KEY + this._playerdata.pushFlags.status.toString();
        const key = CryptoJS.MD5(src).toString(CryptoJS.enc.Hex);
        const iv = CryptoJS.enc.Hex.parse(data.slice(data.length - 32));
        console.log(key.toString(), iv.toString())
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: battleData
        });
        const decrypt = CryptoJS.AES.decrypt(cipherParams, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        const jsonData = JSON.parse(decrypt.toString(CryptoJS.enc.Utf8));
        return jsonData
    }
    async start(args: CommonStartBattleRequest) {
        await excel.initPromise
        let zoneId = excel.StageTable.stages[args.stageId].zoneId
        let apFailReturn = excel.StageTable.stages[args.stageId].apFailReturn
        let ts = parseInt((new Date().getTime() / 1000).toString())
        let inApProtectPeriod = false;
        if (zoneId in excel.StageTable.apProtectZoneInfo) {
            inApProtectPeriod = excel.StageTable.apProtectZoneInfo[zoneId].timeRanges.some(range => ts >= range.startTs && ts <= range.endTs)
        }

        let isApProtect = 0
        if (this._playerdata.dungeon.stages[args.stageId].noCostCnt == 1) {
            isApProtect = 1
            apFailReturn = excel.StageTable.stages[args.stageId].apCost
        }
        if (inApProtectPeriod) {
            isApProtect = 1
        }
        if (args.usePracticeTicket == 1) {
            isApProtect = 0
            apFailReturn = 0
            this._playerdata.status.practiceTicket -= 1
            this._playerdata.dungeon.stages[args.stageId].practiceTimes += 1
        }
        this._playerdata.dungeon.stages[args.stageId].startTimes += 1

        return {
            apFailReturn: apFailReturn,
            battleId: 'abcdefgh-1234-5678-a1b2c3d4e5f6',
            inApProtectPeriod: inApProtectPeriod,
            isApProtect: isApProtect,
            notifyPowerScoreNotEnoughIfFailed: false,
            result: 0
        }
    }
    finish(args: { data: string, battleData: { isCheat: string, completeTime: number } }) {
        try {
            console.log(this.decryptBattleData(args.data))
        } catch (error) {
            console.log(error)
        }
        
        return {
            result: 0,
            apFailReturn: 0,
            expScale: 1.2,
            goldScale: 1.2,
            rewards: [],
            firstRewards: [],
            unlockStages: [],
            unusualRewards: [],
            additionalRewards: [],
            furnitureRewards: [],
            alert: [],
            suggestFriend: false,
            pryResult: [],
        }
    }

}
