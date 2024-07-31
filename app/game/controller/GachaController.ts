import EventEmitter from "events"
import { PlayerGacha } from '../model/playerdata';
import { GachaDetailData, GachaDetailTable, GachaPerChar, GachaResult } from "../model/gacha";
import { readFileSync } from "fs";
import excel from "@excel/excel";
import { TroopManager } from "../manager/TroopManager";
import _ from "lodash";
import { accountManager } from "../manager/AccountManger";
import { ItemBundle } from "@excel/character_table";
import { randomChoice, randomChoices } from "@utils/random";

export class GachaController {
    gacha: PlayerGacha
    uid: string
    _troop: TroopManager
    _table: GachaDetailTable
    _trigger: EventEmitter
    constructor(gacha: PlayerGacha, uid: string, troop: TroopManager, _trigger: EventEmitter) {
        this.gacha = gacha
        this.uid = uid
        this._troop = troop
        this._table = JSON.parse(readFileSync(`${__dirname}/../../../data/gacha_detail_table.json`, 'utf8'))
        this._trigger = _trigger
    }
    async advancedGacha(args: { poolId: string, useTkt: number, itemId: string }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
        let costs: ItemBundle[] = []
        //TODO
        this._trigger.emit("useItems", costs)
        return await this.doAdvancedGacha(args)
    }
    async tenAdvancedGacha(args: { poolId: string, useTkt: number, itemId: string }): Promise<(GachaResult & { logInfo: { beforeNonHitCnt: number } })[]> {
        let costs: ItemBundle[] = []
        let res: (GachaResult & { logInfo: { beforeNonHitCnt: number } })[] = []
        //TODO
        for (let i = 0; i < 10; i++) {
            res.push(await this.doAdvancedGacha(args))
        }
        this._trigger.emit("useItems", costs)
        return res
    }

    async doAdvancedGacha(args: { poolId: string, useTkt: number, itemId: string }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
        await excel.initPromise
        let { poolId, useTkt, itemId } = args
        if (!(poolId in this.gacha.normal)) {
            this.gacha.normal[poolId] = {
                cnt: 0,
                maxCnt: 10,
                rarity: 4,
                avail: true,
            }
        }
        let charId = ""
        let ruleType = excel.GachaTable.gachaPoolClient.find((g) => g.gachaPoolId === poolId)!.gachaRuleType
        let detail = this._table.details[poolId]
        let beforeNonHitCnt = accountManager.getBeforeNonHitCnt(this.uid, ruleType)
        let rank: number
        //TODO
        switch (ruleType) {
            case "NORMAL":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            case "LIMITED":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            case "LINKAGE":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            case "ATTAIN":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            case "CLASSIC":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            case "SINGLE":
                let ensure=""
                this.gacha.single[poolId].singleEnsureCnt += 1
                if (this.gacha.single[poolId]) {
                    if (this.gacha.single[poolId].singleEnsureCnt == 150) {
                        this.gacha.single[poolId].singleEnsureUse = true
                        ensure=this.gacha.single[poolId].singleEnsureChar
                    }
                } else {
                    this.gacha.single[poolId] = {
                        singleEnsureCnt: 0,
                        singleEnsureUse: false,
                        singleEnsureChar: detail.upCharInfo!.perCharList[0].charIdList[0]
                    }
                }
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {ensure: ensure})
                break;
            case "FESCLASSIC":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0

                charId = this._getRandomChar(poolId, rank, {})
                break
            case "CLASSIC_ATTAIN":
                rank = this._getRarityRank(poolId, { beforeNonHitCnt })
                beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0
                charId = this._getRandomChar(poolId, rank, {})
                break;
            default:

                break;
        }
        accountManager.saveBeforeNonHitCnt(this.uid, ruleType, beforeNonHitCnt)
        return {
            ...this._troop.gainChar(charId, { from: ruleType }),
            logInfo: {
                beforeNonHitCnt: beforeNonHitCnt,
            }
        }
    }
    _getRandomChar(poolId: string, rank: number, args: { ensure?: string }): string {
        let charId = ""
        let detail = this._table.details[poolId]
        let perChar = detail.upCharInfo!.perCharList.find((c) => c.rarityRank === rank) as GachaPerChar
        let rr = Math.random()
        if (perChar) {
            if (rr < perChar.percent * perChar.count) {
                charId = randomChoice(perChar.charIdList)
            } else {
                let l = detail.availCharInfo.perAvailList.find((c) => c.rarityRank === rank)?.charIdList as string[]
                charId = randomChoice(l.filter((c) => !perChar.charIdList.includes(c)))
            }
        } else {
            charId = randomChoice(detail.availCharInfo.perAvailList.find((c) => c.rarityRank === rank)!.charIdList)
        }

        return args.ensure || charId
    }
    _getRarityRank(poolId: string, args: { beforeNonHitCnt: number },): number {
        let detail = this._table.details[poolId]
        let per6 = detail.availCharInfo.perAvailList.find((c) => c.rarityRank === 5)!.totalPercent
        let rank = 2
        per6 += args.beforeNonHitCnt < 50 ? 0 : (args.beforeNonHitCnt - 50) * 0.02
        if (Math.random() <= per6) {
            rank = 5
        } else {
            let perAvailList = detail.availCharInfo.perAvailList.filter((c) => c.rarityRank != 5)
            let ranks = perAvailList.map((c) => c.rarityRank)
            let weights = perAvailList.map((r) => r.totalPercent)
            rank = randomChoices(ranks, weights, 1)[0]
            if (rank < 4 && this.gacha.normal[poolId].avail && this.gacha.normal[poolId].cnt == this.gacha.normal[poolId].maxCnt) {
                rank = 4
            }
        }
        this.gacha.normal[poolId].cnt += 1
        if (this.gacha.normal[poolId].avail && rank >= 4) {
            this.gacha.normal[poolId].avail = false
        }
        return rank
    }
    getPoolDetail(poolId: string): GachaDetailData {
        return this._table.details[poolId]
    }
    toJSON(): PlayerGacha {
        return this.gacha
    }
}