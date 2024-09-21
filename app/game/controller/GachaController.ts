import EventEmitter from "events";
import { PlayerGacha } from "../model/playerdata";
import { GachaResult } from "../model/gacha";
import {
  GachaDetailData,
  GachaDetailTable,
  GachaPerChar,
} from "@excel/gacha_detail_table";
import excel from "@excel/excel";
import { TroopManager } from "../manager/troop";
import { accountManager } from "../manager/AccountManger";
import { ItemBundle } from "@excel/character_table";
import { randomChoice, randomChoices } from "@utils/random";

export class GachaController {
  gacha: PlayerGacha;
  uid: string;
  _troop: TroopManager;
  _table: GachaDetailTable;
  _trigger: EventEmitter;

  constructor(
    gacha: PlayerGacha,
    uid: string,
    troop: TroopManager,
    _trigger: EventEmitter,
  ) {
    this.gacha = gacha;
    this.uid = uid;
    this._troop = troop;
    this._table = excel.GachaDetailTable;
    this._trigger = _trigger;
  }

  fix() {}

  async advancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const costs: ItemBundle[] = [];
    //TODO
    this._trigger.emit("useItems", costs);
    return await this.doAdvancedGacha(args);
  }

  async tenAdvancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string;
  }): Promise<(GachaResult & { logInfo: { beforeNonHitCnt: number } })[]> {
    const costs: ItemBundle[] = [];
    const res: (GachaResult & { logInfo: { beforeNonHitCnt: number } })[] = [];
    //TODO
    for (let i = 0; i < 10; i++) {
      res.push(await this.doAdvancedGacha(args));
    }
    this._trigger.emit("useItems", costs);
    return res;
  }

  async doAdvancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const { poolId, useTkt, itemId } = args;
    if (!(poolId in this.gacha.normal)) {
      this.gacha.normal[poolId] = {
        cnt: 0,
        maxCnt: 10,
        rarity: 4,
        avail: true,
      };
    }
    let charId = "";
    const ruleType = excel.GachaTable.gachaPoolClient.find(
      (g) => g.gachaPoolId === poolId,
    )!.gachaRuleType;
    const extras: { [key: string]: object | string; from: string } = {
      from: ruleType,
    };
    const detail = this._table.details[poolId];
    let beforeNonHitCnt = accountManager.getBeforeNonHitCnt(this.uid, ruleType);
    const rank: number = 0;

    const funcs: { [key: string]: () => string } = {
      NORMAL: () => this._handleGacha(poolId, { beforeNonHitCnt }),
      LIMITED: () => {
        extras.extraItem = {
          id: excel.GachaTable.gachaPoolClient.find(
            (g) => g.gachaPoolId === poolId,
          )!.LMTGSID,
          count: 1,
        };
        return this._handleGacha(poolId, { beforeNonHitCnt });
      },
      LINKAGE: () => this._handleGacha(poolId, { beforeNonHitCnt }),
      ATTAIN: () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC: () => this._handleGacha(poolId, { beforeNonHitCnt }),
      SINGLE: () => {
        let ensure = "";
        if (!this.gacha.single[poolId]) {
          this.gacha.single[poolId] = {
            singleEnsureCnt: 0,
            singleEnsureUse: false,
            singleEnsureChar: detail.upCharInfo!.perCharList[0].charIdList[0],
          };
        }
        this.gacha.single[poolId].singleEnsureCnt += 1;
        if (this.gacha.single[poolId].singleEnsureCnt == 150) {
          this.gacha.single[poolId].singleEnsureUse = true;
          ensure = this.gacha.single[poolId].singleEnsureChar;
        }
        this._handleGacha(poolId, { beforeNonHitCnt, ensure });
        return charId;
      },
      FESCLASSIC: () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC_ATTAIN: () => this._handleGacha(poolId, { beforeNonHitCnt }),
    };

    charId = funcs[ruleType]();
    beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0;
    accountManager.saveBeforeNonHitCnt(this.uid, ruleType, beforeNonHitCnt);
    return {
      ...this._troop.gainChar(charId, extras),
      logInfo: {
        beforeNonHitCnt: beforeNonHitCnt,
      },
    };
  }

  _handleGacha(
    poolId: string,
    args: { beforeNonHitCnt: number; ensure?: string },
  ): string {
    const rank = this._getRarityRank(poolId, args);
    return this._getRandomChar(poolId, rank, args);
  }

  _getRandomChar(
    poolId: string,
    rank: number,
    args: { ensure?: string },
  ): string {
    let charId: string;
    const detail = this._table.details[poolId];
    const perChar = detail.upCharInfo!.perCharList.find(
      (c) => c.rarityRank === rank,
    ) as GachaPerChar;
    const rr = Math.random();
    if (perChar) {
      if (rr < perChar.percent * perChar.count) {
        charId = randomChoice(perChar.charIdList);
      } else {
        const charList = detail.availCharInfo.perAvailList.find(
          (c) => c.rarityRank === rank,
        )!.charIdList;
        detail.weightUpCharInfoList?.forEach((c) => {
          if (c.rarityRank === rank) {
            charList.push(...new Array(4).fill(c.charId));
          }
        });
        charId = randomChoice(
          charList.filter((c) => !perChar.charIdList.includes(c)),
        );
      }
    } else {
      charId = randomChoice(
        detail.availCharInfo.perAvailList.find((c) => c.rarityRank === rank)!
          .charIdList,
      );
    }

    return args.ensure || charId;
  }

  _getRarityRank(poolId: string, args: { beforeNonHitCnt: number }): number {
    const detail = this._table.details[poolId];
    let per6 = detail.availCharInfo.perAvailList.find(
      (c) => c.rarityRank === 5,
    )!.totalPercent;
    let rank: number;
    per6 += args.beforeNonHitCnt < 50 ? 0 : (args.beforeNonHitCnt - 50) * 0.02;
    if (Math.random() <= per6) {
      rank = 5;
    } else {
      const perAvailList = detail.availCharInfo.perAvailList.filter(
        (c) => c.rarityRank != 5,
      );
      const ranks = perAvailList.map((c) => c.rarityRank);
      const weights = perAvailList.map((r) => r.totalPercent);
      rank = randomChoices(ranks, weights, 1)[0];
      if (
        rank < 4 &&
        this.gacha.normal[poolId].avail &&
        this.gacha.normal[poolId].cnt == this.gacha.normal[poolId].maxCnt
      ) {
        rank = 4;
      }
    }
    this.gacha.normal[poolId].cnt += 1;
    if (this.gacha.normal[poolId].avail && rank >= 4) {
      this.gacha.normal[poolId].avail = false;
    }
    return rank;
  }

  getPoolDetail(args: { poolId: string }): GachaDetailData {
    return this._table.details[args.poolId];
  }

  toJSON(): PlayerGacha {
    return this.gacha;
  }
}
