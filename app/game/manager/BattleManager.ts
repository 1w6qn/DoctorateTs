import { accountManager } from '../manager/AccountManger';
import { PlayerDataModel } from "../model/playerdata";
import EventEmitter from "events";
import { PlayerSquad, SquadFriendData } from "../model/character";
import excel from "@excel/excel";
import { decryptBattleData } from '@utils/crypt';
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

export class BattleManager {
    _playerdata: PlayerDataModel;
    _trigger: EventEmitter;

    constructor(_playerdata: PlayerDataModel,  _trigger: EventEmitter) {
        this._playerdata = _playerdata;
        this._trigger = _trigger;

    }
    async start(args: CommonStartBattleRequest) {
        await excel.initPromise
        let battleId="1"
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
        accountManager.saveBattleInfo(this._playerdata.status.uid,battleId,{stageId:args.stageId})
        return {
            apFailReturn: apFailReturn,
            battleId: battleId,
            inApProtectPeriod: inApProtectPeriod,
            isApProtect: isApProtect,
            notifyPowerScoreNotEnoughIfFailed: false,
            result: 0
        }
    }
    finish(args: { data: string, battleData: { isCheat: string, completeTime: number } }) {
        let battleData=decryptBattleData(args.data,this._playerdata.pushFlags.status)
        let stageId=accountManager.getBattleInfo(this._playerdata.status.uid,battleData.battleId)?.stageId
        this._trigger.emit('CompleteStageAnyType', battleData)
        this._trigger.emit('CompleteStage', {...battleData,stageId:stageId})
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
    loadReplay(stageId:string):string{
        return accountManager.getBattleReplay(this._playerdata.status.uid,stageId)
    }
    saveReplay(battleId:string,battleReplay:string):void{
        let stageId=accountManager.getBattleInfo(this._playerdata.status.uid,battleId)?.stageId
        return accountManager.saveBattleReplay(this._playerdata.status.uid,stageId as string,battleReplay)
    }

}
