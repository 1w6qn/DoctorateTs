import { PlayerGacha } from "../model/playerdata";
import { GachaResult } from "../model/gacha";
import {
  GachaDetailData,
  GachaDetailTable,
  GachaPerChar,
} from "@excel/gacha_detail_table";
import excel from "@excel/excel";
import { accountManager } from "../manager/AccountManger";
import { ItemBundle } from "@excel/character_table";
import { randomChoice, randomChoices } from "@utils/random";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class GachaController {
  _table: GachaDetailTable;
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._table = excel.GachaDetailTable;
    this._player = player;
    this._trigger = _trigger;
  }

  get uid(): string {
    return this._player.uid;
  }

  get gacha(): PlayerGacha {
    return this._player._playerdata.gacha;
  }

  async advancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const costs: ItemBundle[] = [];
    //TODO
    await this._trigger.emit("items:use", [costs]);
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
    await this._trigger.emit("items:use", [costs]);
    return res;
  }

  async doAdvancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const { poolId } = args;
    //TODO: cost items
    await this._player.update(async (draft) => {
      if (!(poolId in draft.gacha.normal)) {
        draft.gacha.normal[poolId] = {
          cnt: 0,
          maxCnt: 10,
          rarity: 4,
          avail: true,
        };
      }
    });

    const ruleType = excel.GachaTable.gachaPoolClient.find(
      (g) => g.gachaPoolId === poolId,
    )!.gachaRuleType;
    const extras: { [key: string]: object | string; from: string } = {
      from: ruleType,
    };
    const detail = this._table.details[poolId];
    let beforeNonHitCnt = accountManager.getBeforeNonHitCnt(this.uid, ruleType);
    const rank: number = 0;

    const funcs: { [key: string]: () => Promise<string> } = {
      NORMAL: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      LIMITED: async () => {
        extras.extraItem = {
          id: excel.GachaTable.gachaPoolClient.find(
            (g) => g.gachaPoolId === poolId,
          )!.LMTGSID,
          count: 1,
        };
        return this._handleGacha(poolId, { beforeNonHitCnt });
      },
      LINKAGE: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      ATTAIN: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      SINGLE: async () => {
        let ensure = "";
        await this._player.update(async (draft) => {
          if (!draft.gacha.single[poolId]) {
            draft.gacha.single[poolId] = {
              singleEnsureCnt: 0,
              singleEnsureUse: false,
              singleEnsureChar: detail.upCharInfo!.perCharList[0].charIdList[0],
            };
          }
          draft.gacha.single[poolId].singleEnsureCnt += 1;
          if (draft.gacha.single[poolId].singleEnsureCnt == 150) {
            draft.gacha.single[poolId].singleEnsureUse = true;
            ensure = draft.gacha.single[poolId].singleEnsureChar;
          }
        });

        return this._handleGacha(poolId, { beforeNonHitCnt, ensure });
      },
      FESCLASSIC: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC_ATTAIN: async () =>
        this._handleGacha(poolId, { beforeNonHitCnt }),
    };

    const charId = await funcs[ruleType]();
    beforeNonHitCnt = rank != 5 ? beforeNonHitCnt + 1 : 0;
    await accountManager.saveBeforeNonHitCnt(
      this.uid,
      ruleType,
      beforeNonHitCnt,
    );
    let result!: GachaResult;
    await this._trigger.emit("char:get", [
      charId,
      { from: "NORMAL" },
      (res: GachaResult) => {
        result = res;
      },
    ]);
    return {
      ...result,
      logInfo: {
        beforeNonHitCnt: beforeNonHitCnt,
      },
    };
  }

  async _handleGacha(
    poolId: string,
    args: { beforeNonHitCnt: number; ensure?: string },
  ): Promise<string> {
    const rank = await this._getRarityRank(poolId, args);
    return this._getRandomChar(poolId, rank, args);
  }

  async _getRandomChar(
    poolId: string,
    rank: number,
    args: { ensure?: string },
  ): Promise<string> {
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

  async _getRarityRank(
    poolId: string,
    args: { beforeNonHitCnt: number },
  ): Promise<number> {
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
    await this._player.update(async (draft) => {
      draft.gacha.normal[poolId].cnt += 1;
      if (draft.gacha.normal[poolId].avail && rank >= 4) {
        draft.gacha.normal[poolId].avail = false;
      }
    });

    return rank;
  }

  async getPoolDetail(args: { poolId: string }): Promise<GachaDetailData> {
    return this._table.details[args.poolId];
  }
}
