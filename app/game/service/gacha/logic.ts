/**
 * 抽卡管理器类
 * 
 * 负责处理抽卡相关的核心业务逻辑，包括单抽、十连抽、保底机制、稀有度概率计算等。
 * 使用抽卡数据表配置和玩家数据管理器协同工作。
 */

import { PlayerGacha } from "@game/domain/playerdata";
import { GachaResult, GachaType, GACHA_RULE_TYPE, resolveGachaRank } from "@game/domain/gacha";
import {
  GachaDetailData,
  GachaDetailTable,
  GachaPerChar,
} from "@excel/gacha_detail_table";
import { GachaPoolClientData } from "@excel/excel-types";
import excel from "@excel/excel";
import { accountManager } from "@game/service/manager/AccountManager";
import { ItemBundle } from "@excel/character_table";
import { randomChoice } from "@utils/random";
import { domainLogger } from "@utils/logger";
import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/service/manager/events";

/** 寻访域日志（域标签固定为 GachaManager，Dashboard 可按域过滤） */
const log = domainLogger("GachaManager");

export class GachaManager {
  /** 抽卡详情数据表 */
  _table: GachaDetailTable;
  /** 玩家数据管理器 */
  _player: PlayerDataManager;
  /** 事件触发器 */
  _trigger: TypedEventEmitter;
  /** 缺详情卡池的回退详情（首个结构完整的卡池，去掉 UP 干员走通用池） */
  private _fallbackDetail: GachaDetailData | null = null;
  /**
   * gachaPoolClient 的 O(1) 索引（poolId → 池配置），懒构建。
   * 优化：439 个卡池的线性 find 在每抽/十连逐抽都会执行，改 Map 后查找 O(1)。
   */
  private _poolMap: Map<string, GachaPoolClientData> | null = null;

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
   * O(1) 获取卡池客户端配置（懒构建 poolId → config 索引，替代逐抽线性 find）
   * @param poolId - 抽卡池ID
   * @returns 卡池配置（未收录时 undefined，调用方回退 NORMAL）
   */
  private _getPoolConfig(poolId: string): GachaPoolClientData | undefined {
    if (!this._poolMap) {
      this._poolMap = new Map(
        excel.GachaTable.gachaPoolClient.map((g) => [g.gachaPoolId, g]),
      );
    }
    return this._poolMap.get(poolId);
  }

  /**
   * 池规则类型归一化：gachaRuleType 缺省（undefined/null/0/空串）视为 NORMAL。
   * 旧数据与测试池常以 0 表示「无规则类型」，直接透传给策略表会误判为未知类型；
   * 归一化后未知的字符串类型仍由策略表显式报错（建议 5）。
   * @param poolId - 抽卡池ID
   * @returns 归一化后的规则类型（策略表键）
   */
  private _ruleTypeOf(poolId: string): string {
    const raw = this._getPoolConfig(poolId)?.gachaRuleType;
    // 类型声明为 string，但旧数据/测试池运行时可能为数字 0 → String() 归一化后再判定
    return !raw || String(raw) === "0" ? "NORMAL" : String(raw);
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
    let d = this._table.details[poolId];
    if (!d) {
      if (!this._fallbackDetail) {
        const first = Object.values(this._table.details).find(
          (x) => x?.availCharInfo?.perAvailList?.length,
        );
        this._fallbackDetail = first
          ? ({
              ...first,
              upCharInfo: { perCharList: [] },
              // 修复：回退详情不携带首个池的限定/加权干员（内容属于别的池，展示会错）
              limitedChar: [],
              weightUpCharInfoList: [],
              gachaObjGroups: null,
            } as GachaDetailData)
          : ({
              upCharInfo: { perCharList: [] },
              availCharInfo: { perAvailList: [] },
              gachaObjGroups: null,
            } as unknown as GachaDetailData);
      }
      log.warn(
        `卡池 ${poolId} 无详情数据（gacha_detail_table 缺失），回退通用池`,
      );
      d = this._fallbackDetail;
    }
    // 格式归一：CS GachaDetailData.gachaObjGroups 为客户端解析必需字段——
    // 缺失（旧格式详情/回退详情）时客户端报"疑似格式错误"，统一补 null
    if (d && !("gachaObjGroups" in d)) {
      (d as any).gachaObjGroups = null;
    }
    return d;
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
  /**
   * 校验抽卡消耗是否足够（修复：原实现无余额校验——扣费直接减、可扣成负数，
   * 未知/空 itemId 还会被 _useItem 静默跳过 → 免费抽；不足或不可校验时拒绝）
   */
  private _verifyCost(costs: ItemBundle[]): boolean {
    const p = this._player._playerdata;
    for (const c of costs) {
      const type =
        c.type || excel.ItemTable?.items?.[c.id]?.itemType;
      switch (type) {
        case "DIAMOND_SHD":
          // 合成玉（4003）→ status.diamondShard。修复：原实现把 DIAMOND_SHD 与 DIAMOND
          //（至纯源石 4002）合并在一个 case 里校验 androidDiamond → 合成玉抽卡时按源石余额判
          // 档（源石够但合成玉不够也会放行、再扣成负），且混用十连（合成玉+凭证）会出现
          // "只耗合成玉/余额错判" 的异常。
          if (p.status.diamondShard < c.count) return false;
          break;
        case "DIAMOND":
          // 至纯源石（4002）→ androidDiamond
          if (p.status.androidDiamond < c.count) return false;
          break;
        case "LGG_SHD":
          if (p.status.lggShard < c.count) return false;
          break;
        case "HGG_SHD":
          if (p.status.hggShard < c.count) return false;
          break;
        case "CLASSIC_SHD":
          if (p.status.classicShard < c.count) return false;
          break;
        case "TKT_GACHA":
          if (p.status.gachaTicket < c.count) return false;
          break;
        case "TKT_GACHA_10":
          if (p.status.tenGachaTicket < c.count) return false;
          break;
        case "CLASSIC_TKT_GACHA":
          if (p.status.classicGachaTicket < c.count) return false;
          break;
        case "CLASSIC_TKT_GACHA_10":
          if (p.status.classicTenGachaTicket < c.count) return false;
          break;
        case "LIMITED_FREE_GACHA":
          break; // 免费抽，无消耗
        default:
          if (c.instId != null) {
            const entry = p.consumable?.[c.id]?.[c.instId];
            if (!entry || entry.count < c.count) return false;
          } else if (type) {
            if ((p.inventory?.[c.id] ?? 0) < c.count) return false;
          } else {
            // 无 type 且不在 ItemTable（如空 itemId）→ 无法扣费，拒绝防免费抽
            return false;
          }
      }
    }
    return true;
  }

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
    // 修复：先校验余额再抽（原实现先扣费且可扣成负数）
    if (!this._verifyCost(costs)) {
      throw new Error("资源不足，无法抽卡");
    }
    // 统一物品管道：单抽消耗（等价 items:use 直发，见建议 4）
    for (const c of costs) this._player.gainItem.add(c);
    await this._player.gainItem.use();
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
    // 修复：先校验余额再抽（原实现十连先发干员后扣费且可扣成负数）
    if (!this._verifyCost(costs)) {
      throw new Error("资源不足，无法抽卡");
    }
    const res: (GachaResult & { logInfo: { beforeNonHitCnt: number } })[] = [];
    // 优化：保底计数只在十连结束统一落盘一次（原每抽 saveBeforeNonHitCnt →
    // emit("save") → users 表全量重写，十连 = 10 次 SQLite 写盘；现读一次、循环内存
    // 累积、最后写一次 = 1 次写盘）
    const ruleType = this._ruleTypeOf(poolId);
    let beforeNonHitCnt = await accountManager.getBeforeNonHitCnt(
      this.uid,
      ruleType,
    );
    for (let i = 0; i < 10; i++) {
      const { charId, beforeNonHitCnt: next, extras } = await this._pullOnce({
        poolId,
        beforeNonHitCnt,
      });
      beforeNonHitCnt = next;
      res.push(await this._resolveGachaResult(charId, extras, beforeNonHitCnt));
    }
    await accountManager.saveBeforeNonHitCnt(this.uid, ruleType, beforeNonHitCnt);
    // 统一物品管道：十连消耗（等价 items:use 直发，见建议 4）
    for (const c of costs) this._player.gainItem.add(c);
    await this._player.gainItem.use();
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
    const ruleType = this._ruleTypeOf(poolId);
    const beforeNonHitCnt = await accountManager.getBeforeNonHitCnt(
      this.uid,
      ruleType,
    );
    const { charId, beforeNonHitCnt: next, extras } = await this._pullOnce({
      poolId,
      beforeNonHitCnt,
    });
    await accountManager.saveBeforeNonHitCnt(this.uid, ruleType, next);
    return this._resolveGachaResult(charId, extras, next);
  }

  /**
   * 单抽核心（不持久化保底计数——单抽由 doAdvancedGacha 落盘，十连由
   * tenAdvancedGacha 统一累积后落盘一次，避免每抽一次 users 表全量重写）
   *
   * 按抽卡池规则类型执行不同的抽卡策略，计算稀有度，获取随机角色，
   * 并返回更新后的保底计数。
   * @param args - 抽卡参数
   * @param args.poolId - 抽卡池ID
   * @param args.beforeNonHitCnt - 抽前保底计数
   * @returns 角色ID、更新后保底计数、char:get 事件参数（from/extraItem）
   */
  private async _pullOnce(args: {
    poolId: string;
    beforeNonHitCnt: number;
  }): Promise<{
    charId: string;
    beforeNonHitCnt: number;
    extras: { from: string; extraItem?: ItemBundle };
  }> {
    const { poolId, beforeNonHitCnt } = args;
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
    const poolConfig = this._getPoolConfig(poolId);
    const ruleType = this._ruleTypeOf(poolId);
    const extras: { from: string; extraItem?: ItemBundle } = { from: ruleType };
    const detail = this._poolDetail(poolId);

    const funcs: { [key: string]: () => Promise<{ charId: string; rank: number }> } = {
      NORMAL: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      // DOUBLE/CLASSIC_DOUBLE/BACKFLOW/SPECIAL：双 up/回归/特殊池——UP 干员由详情
      // upCharInfo 处理，走通用 _handleGacha 即可（修复：原 funcs 缺这些键 → 500）
      DOUBLE: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      CLASSIC_DOUBLE: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      BACKFLOW: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      SPECIAL: async () => this._handleGacha(poolId, { beforeNonHitCnt }),
      LIMITED: async () => {
        // 修复：extraItem 补 type=LMTGS_COIN（消费型入账 consumable）+ id 读
        // lMTGSID（JSON 实际键，生成器按 JSON 键对照修正；缺配置回退通用
        // "LMTGS_COIN"——旧实现读 CS 名 LMTGSID 恒 undefined → 空 id 警告跳过）
        extras.extraItem = {
          id: poolConfig?.lMTGSID || "LMTGS_COIN",
          count: 1,
          type: "LMTGS_COIN",
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

    // 防御：ruleType 不在策略表（未来新池类型）时显式报错，不再静默按 NORMAL 回退——
    // 新池类型应显式适配（参考 OBS GachaController match 分发），静默回退会掩盖配置缺失
    const gachaFn = funcs[ruleType];
    if (!gachaFn) {
      log.error(
        `未知寻访规则类型 gachaRuleType=${ruleType}（池 ${poolId}）：请显式适配策略表`,
      );
      throw new Error(`unknown gachaRuleType: ${ruleType}`);
    }
    const { charId, rank } = await gachaFn();
    // 修复：原 `const rank = 0` 恒等判断 → 保底计数六星命中后从未重置（无限增长，
    // 超 100 抽后六星概率溢出 >100%）；改为真实稀有度（5 = 六星）命中即清零
    const nextNonHitCnt = rank !== 5 ? beforeNonHitCnt + 1 : 0;
    return { charId, beforeNonHitCnt: nextNonHitCnt, extras };
  }

  /**
   * 通过 char:get 事件入账干员并解析抽卡结果
   *
   * 修复：原 emit 固定传 { from: "NORMAL" } 导致 extras 成为死代码——CLASSIC 池
   * classicCount/经典票、LIMITED 池 LMTGSID 凭证从未生效；改为透传 ruleType/extraItem。
   * @param charId - 抽中角色ID
   * @param extras - char:get 事件参数（from + 可选 extraItem）
   * @param beforeNonHitCnt - 抽后保底计数
   * @returns 抽卡结果与保底计数日志
   */
  private async _resolveGachaResult(
    charId: string,
    extras: { from: string; extraItem?: ItemBundle },
    beforeNonHitCnt: number,
  ): Promise<GachaResult & { logInfo: { beforeNonHitCnt: number } }> {
    let result!: GachaResult;
    await this._trigger.emit("char:get", [
      charId,
      extras,
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
   * @returns 角色ID与稀有度（5 = 六星，供保底计数重置）
   */
  async _handleGacha(
    poolId: string,
    args: { beforeNonHitCnt: number; ensure?: string },
  ): Promise<{ charId: string; rank: number }> {
    const rank = await this._getRarityRank(poolId, args);
    const charId = await this._getRandomChar(poolId, rank, args);
    return { charId, rank };
  }

  /**
   * 获取玩家在该自选卡池、指定稀有度下已选中的 UP 干员列表
   *
   * 中坚甄选/回归/特殊等自选池通过 choosePoolUp（或管理后台 setPlayerPoolUp）
   * 把玩家选择写入 gacha[gachaType][poolId].upChar。upChar 的三种形态在此统一兼容：
   * - 字典 { rank: string[] }（客户端 choosePoolUp 协议 Dictionary<Int32, List<String>>）
   * - 干员数组 string[]（管理后台写入）
   * - 单一字符串（旧测试/容错，视为 1 个干员）
   * 未作选择或无匹配稀有度时返回空数组，调用方走详情表静态 UP 逻辑。
   * @param poolId - 抽卡池ID
   * @param rank - 稀有度下标（5=六星）
   * @returns 玩家该稀有度已选中 UP 干员 ID 列表（可为空）
   */
  private _selfSelectedUpForRank(poolId: string, rank: number): string[] {
    const poolConfig = this._getPoolConfig(poolId);
    const ruleType = this._ruleTypeOf(poolId);
    const gachaType = GACHA_RULE_TYPE[ruleType] ?? "single";
    const poolData: any = (this.gacha as any)?.[gachaType]?.[poolId];
    const upChar = poolData?.upChar;
    if (!upChar) return [];
    // 字典形态：按稀有度取（兼容字符串键）
    if (typeof upChar === "object" && !Array.isArray(upChar)) {
      const list = upChar[String(rank)] ?? upChar[rank];
      return Array.isArray(list) ? list.filter(Boolean) : [];
    }
    // 数组/字符串形态：无法按稀有度区分，仅保留确实在该稀有度候选中的干员
    const raw: string[] = Array.isArray(upChar) ? upChar : [String(upChar)];
    const rankedSet = new Set(
      this._poolDetail(poolId).availCharInfo.perAvailList
        .find((c) => c.rarityRank === rank)?.charIdList ?? [],
    );
    return raw.filter((id) => rankedSet.has(id));
  }

  /**
   * 获取随机角色
   * 
   * 根据稀有度从抽卡池中随机选择一个角色，考虑UP角色概率。
   * 自选卡池：若玩家已为该稀有度自选 UP，则用自选列表替换详情表静态 UP
   * （同一概率档位，无静态 UP 时按 35% 默认档替），未自选时维持原逻辑。
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
    const staticPerChar = detail.upCharInfo!.perCharList.find(
      (c) => c.rarityRank === rank,
    ) as GachaPerChar | undefined;
    // 自选覆盖：玩家选中该稀有度 UP 时，用它替换静态 UP
    const selfUps = this._selfSelectedUpForRank(poolId, rank);
    const perChar: GachaPerChar | undefined = selfUps.length
      ? {
          rarityRank: rank,
          charIdList: selfUps,
          // 沿用静态 UP 的整体出率档位（percent*count）；无静态时按 35% 默认档
          percent: staticPerChar
            ? staticPerChar.percent * staticPerChar.count
            : 0.35,
          count: 1,
        }
      : staticPerChar;
    const rr = Math.random();
    if (perChar) {
      if (rr < perChar.percent * perChar.count) {
        charId = randomChoice(perChar.charIdList);
      } else {
        // 修复：weightUp 扩权不再原地修改共享 perAvailList.charIdList
        //（原实现每抽 append 4 份到详情表共享数组 → 概率被污染 + 数组无限膨胀拖慢随机）
        const avail = detail.availCharInfo.perAvailList.find(
          (c) => c.rarityRank === rank,
        )!;
        let charList = avail.charIdList;
        detail.weightUpCharInfoList?.forEach((c) => {
          if (c.rarityRank === rank) {
            charList = [...charList, ...new Array(4).fill(c.charId)];
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
    // 概率/保底计算收敛到 domain/gacha.ts 的纯函数 resolveGachaRank（可注入随机源、可单测）
    const gachaSt = this.gacha.normal?.[poolId] ?? { cnt: 0, maxCnt: 10 };
    const nextCnt = (gachaSt.cnt ?? 0) + 1;
    const rank = resolveGachaRank({
      per6Base: perAvailList.find((c) => c.rarityRank === 5)?.totalPercent ?? 2,
      beforeNonHitCnt: args.beforeNonHitCnt,
      nextCnt,
      maxCnt: gachaSt.maxCnt ?? 10,
      ranks: perAvailList.map((c) => c.rarityRank),
      weights: perAvailList.map((r) => r.totalPercent),
    });
    await this._player.update(async (draft) => {
      const st = draft.gacha.normal?.[poolId];
      if (!st) return;
      // 只增不减，禁止窗口回绕（一次性事件，触发后 cnt 继续增长不再命中保底点）
      st.cnt = nextCnt;
      // 修复：抽到五星及以上（rank>=4，对齐回退分支）后关闭 avail——
      // 客户端据此隐藏"保底剩余次数"提示；原实现仅回退分支处理，正常路径
      // avail 恒为 true，抽到五星后保底提示仍残留。
      if (st.avail && rank >= 4) {
        st.avail = false;
      }
    });

    return rank;
  }

  /**
   * 读取玩家在当前自选卡池（如 FESCLASSIC）已选的 UP 字典
   *
   * 读取 gacha[gachaType][poolId].upChar，仅当其为字典形态
   *（客户端 choosePoolUp 协议 Dictionary<Int32, List<String>>，如 {4:[...],5:[...]}）
   * 时返回；数组/字符串形态由 _selfSelectedUpForRank 另行兼容。无选择返回 null。
   * @param poolId - 抽卡池ID
   * @returns 玩家已选 UP 字典（{稀有度: 干员列表}），无则 null
   */
  private _selfSelectedUpDict(poolId: string): Record<string, string[]> | null {
    const cfg = this._getPoolConfig(poolId);
    const gachaType = GACHA_RULE_TYPE[cfg?.gachaRuleType ?? ""] ?? "single";
    const upChar: unknown = (this.gacha as any)?.[gachaType]?.[poolId]?.upChar;
    if (upChar && typeof upChar === "object" && !Array.isArray(upChar)) {
      return upChar as Record<string, string[]>;
    }
    return null;
  }

  /**
   * 当前卡的生效 UP 干员列表（静态池 UP 与玩家自选叠加）
   *
   * 自选卡池（中坚甄选 FESCLASSIC 等）：玩家 choosePoolUp 选择的 UP 需反映到
   * getPoolDetail 的 detailInfo 与商店干员区，否则客户端无法生成所选卡池、商店也
   * 不显示选择。此方法以静态 upCharInfo.perCharList 为基座，按稀有度用玩家自选
   * charIdList 覆盖（无自选时原样返回静态，行为不变）。返回一份克隆，不改动共享详情。
   * @param poolId - 抽卡池ID
   * @returns 合并玩家自选后的 perCharList（克隆）
   */
  effectiveUpPerCharList(poolId: string): GachaPerChar[] {
    return resolveEffectiveUpPerCharList(
      this._table,
      excel.GachaTable.gachaPoolClient,
      this.gacha,
      poolId,
    );
  }

  /**
   * 获取抽卡池详情
   *
   * 格式化补全 gachaObjGroups（客户端解析必需）外，对自选卡池把玩家已选 UP 合并进
   * upCharInfo.perCharList——fix：此前直接返回静态详情，客户端无法感知玩家选择，
   * 抽卡界面上"没有生成所选卡池"。
   * @param args - 参数
   * @param args.poolId - 抽卡池ID
   * @returns 抽卡池详情数据（自选池已含玩家 UP）
   */
  async getPoolDetail(args: { poolId: string }): Promise<GachaDetailData> {
    const detail = this._poolDetail(args.poolId);
    if (!detail || !detail.upCharInfo) return detail;
    return {
      ...detail,
      upCharInfo: {
        perCharList: this.effectiveUpPerCharList(args.poolId),
      },
    };
  }
}

/**
 * 生效 UP 干员列表（纯函数版，供 ShopManager 等跨模块直接调用）
 *
 * 内联 GachaManager.effectiveUpPerCharList/_selfSelectedUpDict 的实现：
 * 静态 upCharInfo.perCharList 为基座，按稀有度用玩家自选 charIdList 覆盖。
 * 详情缺失时回退首个结构完整卡池（upCharInfo 置空走通用池）。返回克隆，不改共享详情。
 *
 * @param table - 抽卡详情表（excel.GachaDetailTable）
 * @param poolConfigs - 卡池客户端配置列表（excel.GachaTable.gachaPoolClient）
 * @param gacha - 玩家抽卡数据（含自选 UP 字典）
 * @param poolId - 抽卡池ID
 * @returns 合并玩家自选后的 perCharList（克隆）
 */
export function resolveEffectiveUpPerCharList(
  table: GachaDetailTable,
  poolConfigs: GachaPoolClientData[],
  gacha: PlayerGacha | undefined,
  poolId: string,
): GachaPerChar[] {
  // _poolDetail 内联：缺详情回退首个结构完整卡池（无缓存，每次重建）
  let d = table.details[poolId];
  if (!d) {
    const first = Object.values(table.details).find(
      (x) => x?.availCharInfo?.perAvailList?.length,
    );
    d = first
      ? ({
          ...first,
          upCharInfo: { perCharList: [] },
          limitedChar: [],
          weightUpCharInfoList: [],
          gachaObjGroups: null,
        } as GachaDetailData)
      : ({
          upCharInfo: { perCharList: [] },
          availCharInfo: { perAvailList: [] },
          gachaObjGroups: null,
        } as unknown as GachaDetailData);
  }
  if (d && !("gachaObjGroups" in d)) {
    (d as any).gachaObjGroups = null;
  }
  const base: GachaPerChar[] = (d.upCharInfo?.perCharList ?? []).map(
    (c) => ({ ...c, charIdList: [...c.charIdList] }),
  );
  // _selfSelectedUpDict 内联：字典形态（{稀有度: 干员列表}）才合并
  const cfg = poolConfigs.find((g) => g.gachaPoolId === poolId);
  const gachaType = GACHA_RULE_TYPE[cfg?.gachaRuleType ?? ""] ?? "single";
  const upChar: unknown = (gacha as any)?.[gachaType]?.[poolId]?.upChar;
  if (!upChar || typeof upChar !== "object" || Array.isArray(upChar)) {
    return base;
  }
  const result = base.map((c) => ({ ...c, charIdList: [...c.charIdList] }));
  for (const [rankKey, charIds] of Object.entries(upChar)) {
    const rank = Number(rankKey);
    if (!Number.isInteger(rank) || !Array.isArray(charIds) || !charIds.length) {
      continue;
    }
    const ex = result.find((c) => c.rarityRank === rank);
    if (ex) {
      ex.charIdList = [...charIds];
      ex.count = 1;
    } else {
      result.push({
        rarityRank: rank,
        charIdList: [...charIds],
        percent: 0.35,
        count: 1,
      });
    }
  }
  return result;
}