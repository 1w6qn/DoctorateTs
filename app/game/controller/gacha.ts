/**
 * 抽卡控制器类
 * 
 * 负责处理抽卡相关的核心业务逻辑，包括单抽、十连抽、保底机制、稀有度概率计算等。
 * 使用抽卡数据表配置和玩家数据管理器协同工作。
 */

import { PlayerGacha } from "../model/playerdata";
import { GachaResult, GachaType } from "../model/gacha";
import {
  GachaDetailData,
  GachaDetailTable,
  GachaPerChar,
} from "@excel/gacha_detail_table";
import excel from "@excel/excel";
import { accountManager } from "../manager/AccountManger";
import { ItemBundle } from "@excel/character_table";
import { randomChoice, randomChoices } from "@utils/random";
import { logger } from "@utils/logger";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class GachaController {
  /** 抽卡详情数据表 */
  _table: GachaDetailTable;
  /** 玩家数据管理器 */
  _player: PlayerDataManager;
  /** 事件触发器 */
  _trigger: TypedEventEmitter;
  /** 缺详情卡池的回退详情（首个结构完整的卡池，去掉 UP 干员走通用池） */
  private _fallbackDetail: GachaDetailData | null = null;

  /**
   * 构造函数
   * @param player - 玩家数据管理器
   * @param _trigger - 事件触发器
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._table = excel.GachaDetailTable;
    this._player = player;
    this._trigger = _trigger;
  }

  /**
   * 安全获取卡池详情
   *
   * 修复：gachaPoolClient 中有但 gacha_detail_table.details 缺失的卡池
   * （如 LIMITED_76_0_1/SINGLE_75_0_3 等新池未合并详情）会导致
   * detail.availCharInfo 解引用 500。缺详情时回退到首个结构完整的卡池详情
   * （upCharInfo 置空走通用池），并记录 WARN 便于补数据。
   */
  private _poolDetail(poolId: string): GachaDetailData {
    const d = this._table.details[poolId];
    if (d) return d;
    if (!this._fallbackDetail) {
      const first = Object.values(this._table.details).find(
        (x) => x?.availCharInfo?.perAvailList?.length,
      );
      this._fallbackDetail = first
        ? ({ ...first, upCharInfo: { perCharList: [] } } as GachaDetailData)
        : ({
            upCharInfo: { perCharList: [] },
            availCharInfo: { perAvailList: [] },
          } as unknown as GachaDetailData);
    }
    logger.warn(
      "gacha",
      `卡池 ${poolId} 无详情数据（gacha_detail_table 缺失），回退通用池`,
    );
    return this._fallbackDetail;
  }

  /**
   * 获取用户ID
   * @returns 用户ID
   */
  get uid(): string {
    return this._player.uid;
  }

  /**
   * 获取玩家抽卡数据
   * @returns 玩家抽卡数据
   */
  get gacha(): PlayerGacha {
    return this._player._playerdata.gacha;
  }

  /**
   * 执行单次高级抽卡
   * 
   * 根据抽卡类型扣除相应消耗，然后执行抽卡逻辑。
   * @param args - 抽卡参数
   * @param args.poolId - 抽卡池ID
   * @param args.useTkt - 使用的抽卡类型
   * @param args.itemId - 使用的物品ID（当useTkt为UseItem时）
   * @returns 抽卡结果和保底计数信息
   */
  async advancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string | null;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const {poolId,useTkt,itemId}=args
    const costs: ItemBundle[] = [];
    switch (useTkt) {
      case GachaType.Diamond:
        if(poolId.startsWith("BOOT")){
          costs.push({id:"4003",type:"DIAMOND_SHD",count:380})
        }else{
          costs.push({id:"4003",type:"DIAMOND_SHD",count:600})
        }
        break;
      case GachaType.SingleTicket:
        costs.push({id:"TKT_GACHA",type:"TKT_GACHA",count:1})
        break;
      case GachaType.LimitSingle:
        costs.push({id:"LIMITED_FREE_GACHA",type:"LIMITED_FREE_GACHA",count:1})
        break;
      case GachaType.UseItem:
        costs.push({id:itemId ?? "",count:1})
        break;
      case GachaType.ClassicSingleTicket:
        costs.push({id:"CLASSIC_TKT_GACHA",type:"CLASSIC_TKT_GACHA",count:1})
        break;
    }
    await this._trigger.emit("items:use", [costs]);
    return await this.doAdvancedGacha(args);
  }

  /**
   * 执行十连高级抽卡
   * 
   * 根据抽卡类型扣除相应消耗，执行10次单抽逻辑。
   * @param args - 抽卡参数
   * @param args.poolId - 抽卡池ID
   * @param args.useTkt - 使用的抽卡类型
   * @param args.itemList - 使用的物品列表（当useTkt为CombineTenTicket或UseItem时）
   * @returns 抽卡结果数组和保底计数信息
   */
  async tenAdvancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemList: ItemBundle[];
  }): Promise<(GachaResult & { logInfo: { beforeNonHitCnt: number } })[]> {
    const {poolId,useTkt,itemList}=args
    const costs: ItemBundle[] = [];
    switch (useTkt) {
      case GachaType.Diamond:
        if(poolId.startsWith("BOOT")){
          costs.push({id:"4003",type:"DIAMOND_SHD",count:3800})
        }else{
          costs.push({id:"4003",type:"DIAMOND_SHD",count:6000})
        }
        break;
      case GachaType.TenTicket:
        costs.push({id:"TKT_GACHA_10",type:"TKT_GACHA_10",count:1})
        break;
      case GachaType.TenSingleTkt:
        costs.push({id:"TKT_GACHA",type:"TKT_GACHA",count:10})
        break;
      case GachaType.ClassicTenTicket:
        costs.push({id:"CLASSIC_TKT_GACHA_10",type:"CLASSIC_TKT_GACHA_10",count:1})
        break;
      case GachaType.classicTenSingleTicket:
        costs.push({id:"CLASSIC_TKT_GACHA",type:"CLASSIC_TKT_GACHA",count:10})
        break;
      case GachaType.CombineTenTicket:
        costs.push(...itemList)
        break;
      case GachaType.UseItem:
        costs.push(...itemList)
        break;
    }
    const res: (GachaResult & { logInfo: { beforeNonHitCnt: number } })[] = [];
    for (let i = 0; i < 10; i++) {
      res.push(await this.doAdvancedGacha({poolId,useTkt,itemId:""}));
    }
    await this._trigger.emit("items:use", [costs]);
    return res;
  }

  /**
   * 执行实际抽卡逻辑
   * 
   * 根据抽卡池规则类型执行不同的抽卡策略，计算稀有度，获取随机角色。
   * @param args - 抽卡参数
   * @param args.poolId - 抽卡池ID
   * @param args.useTkt - 使用的抽卡类型
   * @param args.itemId - 使用的物品ID
   * @returns 抽卡结果和保底计数信息
   */
  async doAdvancedGacha(args: {
    poolId: string;
    useTkt: number;
    itemId: string | null;
  }): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    const { poolId } = args;
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

    // 修复：池不在 gachaPoolClient 时回退 NORMAL（不 500）
    const poolConfig = excel.GachaTable.gachaPoolClient.find(
      (g) => g.gachaPoolId === poolId,
    );
    const ruleType = poolConfig?.gachaRuleType ?? "NORMAL";
    const extras: { [key: string]: object | string; from: string } = {
      from: ruleType,
    };
    const detail = this._poolDetail(poolId);
    let beforeNonHitCnt = await accountManager.getBeforeNonHitCnt(
      this.uid,
      ruleType,
    );
    const rank: number = 0;

    const funcs: { [key: string]: () => Promise<string> } = {
      NORMAL: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      // DOUBLE/CLASSIC_DOUBLE/BACKFLOW/SPECIAL：双 up/回归/特殊池——UP 干员由详情
      // upCharInfo 处理，走通用 _handleGacha 即可（修复：原 funcs 缺这些键 → 500）
      DOUBLE: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC_DOUBLE: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      BACKFLOW: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      SPECIAL: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      LIMITED: async () => {
        extras.extraItem = {
          id: poolConfig?.LMTGSID ?? "",
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

    // 防御：ruleType 仍不在 funcs 映射（未来新池类型）时回退 NORMAL，不 500
    const gachaFn = funcs[ruleType] ?? funcs.NORMAL;
    const charId = await gachaFn();
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

  /**
   * 处理抽卡逻辑
   * 
   * 根据保底计数和确保角色，计算稀有度并获取随机角色。
   * @param poolId - 抽卡池ID
   * @param args - 参数
   * @param args.beforeNonHitCnt - 保底计数
   * @param args.ensure - 确保获取的角色ID（可选）
   * @returns 角色ID
   */
  async _handleGacha(
    poolId: string,
    args: { beforeNonHitCnt: number; ensure?: string },
  ): Promise<string> {
    const rank = await this._getRarityRank(poolId, args);
    return this._getRandomChar(poolId, rank, args);
  }

  /**
   * 获取随机角色
   * 
   * 根据稀有度从抽卡池中随机选择一个角色，考虑UP角色概率。
   * @param poolId - 抽卡池ID
   * @param rank - 稀有度等级
   * @param args - 参数
   * @param args.ensure - 确保获取的角色ID（可选）
   * @returns 角色ID
   */
  async _getRandomChar(
    poolId: string,
    rank: number,
    args: { ensure?: string },
  ): Promise<string> {
    let charId: string;
    const detail = this._poolDetail(poolId);
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

  /**
   * 获取稀有度等级
   * 
   * 根据抽卡池配置和保底机制计算本次抽卡的稀有度。
   * 五星概率随保底计数递增，10连必出四星及以上。
   * @param poolId - 抽卡池ID
   * @param args - 参数
   * @param args.beforeNonHitCnt - 保底计数
   * @returns 稀有度等级
   */
  async _getRarityRank(
    poolId: string,
    args: { beforeNonHitCnt: number },
  ): Promise<number> {
    const detail = this._poolDetail(poolId);
    const perAvailList = detail.availCharInfo.perAvailList;
    // 防御：详情缺失/为空时回退固定概率（2% 六星，否则四星），不 500
    if (!perAvailList?.length) {
      const fallbackRank = Math.random() <= 0.02 ? 5 : 4;
      await this._player.update(async (draft) => {
        draft.gacha.normal[poolId].cnt += 1;
        if (draft.gacha.normal[poolId].avail && fallbackRank >= 4) {
          draft.gacha.normal[poolId].avail = false;
        }
      });
      return fallbackRank;
    }
    let per6 = perAvailList.find((c) => c.rarityRank === 5)?.totalPercent ?? 2;
    let rank: number;
    per6 += args.beforeNonHitCnt < 50 ? 0 : (args.beforeNonHitCnt - 50) * 0.02;
    if (Math.random() <= per6) {
      rank = 5;
    } else {
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

  /**
   * 获取抽卡池详情
   * @param args - 参数
   * @param args.poolId - 抽卡池ID
   * @returns 抽卡池详情数据
   */
  async getPoolDetail(args: { poolId: string }): Promise<GachaDetailData> {
    return this._poolDetail(args.poolId);
  }
}