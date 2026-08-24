/**
 * 商店控制器类
 *
 * 负责处理商店购买相关的核心业务逻辑，包括低级商店、高级商店、皮肤商店、
 * 家具商店等多种类型商店的购买操作和刷新逻辑。
 */

import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { readJsonSync } from "@utils/file";
import {
  ChooseGPItem,
  ClassicGoodList,
  GPGoodList,
  HighGoodList,
  LevelGPItem,
  LMTGSGood,
  MonthlySubItem,
  NormalGPItem,
  PeriodicityGroup,
  PeriodicityGPItem,
  QCObject,
  REPGoodList,
  SocialGoodList,
  SocialShopData,
} from "@excel/shop";
import excel from "@excel/excel";
import { GachaPerChar } from "@excel/gacha_detail_table";
import { now } from "@utils/time";
import { logger } from "@utils/logger";
import { TypedEventEmitter } from "@game/model/events";

/**
 * 商店业务错误（余额不足/超限购/已拥有）
 *
 * 路由层捕获后返回 result:1 业务错误而非 500；购买流程在抛出前必须未产生任何副作用
 *（不扣费、不发放、不写记录）。
 */
export class ShopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShopError";
  }
}

/**
 * 信用交易所物资条目（PRTS 采购中心「信用交易所」物资表的单个物资）
 *
 * 对应候选池中的一种可选物资：item 入账所需 id/count/type，
 * originPrice 为原价（信用），allow95/allow99 标记该物资是否可刷出 -95%/-99% 特价
 *（仅「龙门币×1800/基础作战记录」可 -95%，「龙门币×3600/初级作战记录」可 -99%）。
 */
interface CreditShopMaterial {
  /** 物品 id（ItemTable itemId） */
  id: string;
  /** 单次购买数量 */
  count: number;
  /** 入账类型（ItemTable itemType） */
  type: string;
  /** 客户端展示名称 */
  name: string;
  /** 原价（信用） */
  originPrice: number;
  /** 是否可刷 -95% 特价 */
  allow95?: boolean;
  /** 是否可刷 -99% 特价 */
  allow99?: boolean;
}

/**
 * 信用交易所候选池（7 行「并列随机抽取项」）
 *
 * PRTS：信用交易所物资每日只刷 10 个；候选物资按"同一行四个物品为并列随机抽取项"——
 * 每次从一行中随机取其一作为当日可能出现的一个物资。行内各物资原价（信用）见文档。
 */
const CREDIT_SHOP_ROWS: CreditShopMaterial[][] = [
  // 行1：-95% 特价候选（龙门币×1800 / 基础作战记录×9）
  [
    { id: "4001", count: 1800, type: "GOLD", name: "龙门币", originPrice: 100, allow95: true },
    { id: "2001", count: 9, type: "CARD_EXP", name: "基础作战记录", originPrice: 100, allow95: true },
    { id: "30011", count: 2, type: "MATERIAL", name: "源岩", originPrice: 80 },
    { id: "30012", count: 3, type: "MATERIAL", name: "固源岩", originPrice: 200 },
  ],
  // 行2：-99% 特价候选（龙门币×3600 / 初级作战记录×9）
  [
    { id: "4001", count: 3600, type: "GOLD", name: "龙门币", originPrice: 200, allow99: true },
    { id: "2002", count: 9, type: "CARD_EXP", name: "初级作战记录", originPrice: 200, allow99: true },
    { id: "30021", count: 2, type: "MATERIAL", name: "代糖", originPrice: 100 },
    { id: "30022", count: 2, type: "MATERIAL", name: "糖", originPrice: 200 },
  ],
  // 行3
  [
    { id: "3401", count: 20, type: "MATERIAL", name: "家具零件", originPrice: 160 },
    { id: "3301", count: 5, type: "MATERIAL", name: "技巧概要·卷1", originPrice: 160 },
    { id: "30031", count: 2, type: "MATERIAL", name: "酯原料", originPrice: 100 },
    { id: "30032", count: 2, type: "MATERIAL", name: "聚酸酯", originPrice: 200 },
  ],
  // 行4
  [
    { id: "3401", count: 25, type: "MATERIAL", name: "家具零件", originPrice: 200 },
    { id: "3302", count: 3, type: "MATERIAL", name: "技巧概要·卷2", originPrice: 200 },
    { id: "30041", count: 2, type: "MATERIAL", name: "异铁碎片", originPrice: 120 },
    { id: "30042", count: 2, type: "MATERIAL", name: "异铁", originPrice: 240 },
  ],
  // 行5
  [
    { id: "7001", count: 1, type: "TKT_RECRUIT", name: "招聘许可", originPrice: 160 },
    { id: "3112", count: 5, type: "MATERIAL", name: "碳", originPrice: 160 },
    { id: "30051", count: 2, type: "MATERIAL", name: "双酮", originPrice: 120 },
    { id: "30052", count: 2, type: "MATERIAL", name: "酮凝集", originPrice: 240 },
  ],
  // 行6
  [
    { id: "7002", count: 1, type: "TKT_INST_FIN", name: "加急许可", originPrice: 160 },
    { id: "3113", count: 3, type: "MATERIAL", name: "碳素", originPrice: 200 },
    { id: "30061", count: 2, type: "MATERIAL", name: "破损装置", originPrice: 160 },
    { id: "30062", count: 1, type: "MATERIAL", name: "装置", originPrice: 160 },
  ],
  // 行7：仅赤金
  [{ id: "3003", count: 6, type: "MATERIAL", name: "赤金", originPrice: 160 }],
];

export class ShopController {
  /** 社交商店商品列表 */
  socialGoodList!: SocialGoodList;
  /** 玩家数据管理器 */
  _player: PlayerDataManager;
  /** 事件触发器 */
  _trigger: TypedEventEmitter;

  /**
   * 构造函数
   * @param player - 玩家数据管理器
   * @param _trigger - 事件触发器
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    // 信用商店商品基座（静态配置；buildSocialGoodList 按当天日期重新生成）。
    // 修复：同步读取——原异步 readJson 与首次 getSocialGoodList 请求竞态，
    // 启动后首请求拿到空基座 → 信用商店缺常规商品
    try {
      this.socialGoodList = readJsonSync<SocialGoodList>(
        "./data/shop/SocialGoodList.json",
      );
    } catch {
      this.socialGoodList = { goodList: [], charPurchase: {} };
    }
  }

  /**
   * 校验购买数量为正整数
   *
   * 修复：原各 buy* 方法对 count 无任何校验——负数 count 使价格/发放数量取反，
   * items:use 经 _useItem 取反后反向入账（免费刷信用/凭证/钻石等货币）
   * @param count - 购买数量
   */
  private _assertBuyCount(count: number): void {
    if (typeof count !== "number" || !Number.isInteger(count) || count <= 0) {
      throw new Error(`非法购买数量: ${count}`);
    }
  }

  /**
   * 读取物品当前持有量（货币/凭证统一入口，余额校验用）
   *
   * 4001 龙门币 / 4002 源石 / 4003 合成玉 / 4004 高级凭证 / 4005 资质凭证 /
   * socialPoint 信用 在 status；其余（4006/3401/EPGS_COIN/REP_COIN/LMTGS_COIN_*）在 inventory。
   * @param itemId - 物品 ID（socialPoint 表示信用）
   * @returns 当前持有量（未持有为 0）
   */
  private _held(itemId: string): number {
    const st = this._player._playerdata.status as any;
    switch (itemId) {
      case "4001":
        return st.gold ?? 0;
      case "4002":
        return st.androidDiamond ?? 0;
      case "4003":
        return st.diamondShard ?? 0;
      case "4004":
        return st.hggShard ?? 0;
      case "4005":
        return st.lggShard ?? 0;
      case "socialPoint":
        return st.socialPoint ?? 0;
      default:
        return this._player._playerdata.inventory?.[itemId] ?? 0;
    }
  }

  /**
   * 余额校验：不足抛 ShopError（路由层转 result:1，不扣费不发放）
   *
   * 修复：原各 buy* 方法直接 emit items:use 扣费——余额不足时 gainItem 把余额扣成
   * 负数但商品照常发放，等于免费刷货币；此处先校验、不足即拒绝且无副作用。
   * @param itemId - 货币物品 ID
   * @param count - 本次需扣总量
   */
  private _assertAffordable(itemId: string, count: number): void {
    if (count <= 0) return;
    const have = this._held(itemId);
    if (have < count) {
      throw new ShopError(`货币不足: 需要 ${itemId}×${count}，持有 ${have}`);
    }
  }

  /**
   * 读取 shop.<key>.info 中某商品已购数量
   * @param shopKey - 商店类型键（LS/HS/ES/...）
   * @param goodId - 商品 ID
   * @returns 已购数量
   */
  private _boughtCount(shopKey: string, goodId: string): number {
    const shop = (this._player._playerdata.shop as any)?.[shopKey];
    const rec = (shop?.info ?? []).find((i: any) => i.id === goodId);
    return rec?.count ?? 0;
  }

  /**
   * 限购校验：已购 + 本次 > availCount 时抛 ShopError
   *
   * 修复：原各 buy* 方法从不检查 availCount——每日/总量限购商品可无限购买。
   * 官服 availCount 用 -1 表示无限（本实现 <=0 视为不限）。
   * @param shopKey - 商店类型键
   * @param goodId - 商品 ID
   * @param count - 本次购买数量
   * @param availCount - 限购数量（<=0 不限）
   */
  private _assertAvail(
    shopKey: string,
    goodId: string,
    count: number,
    availCount?: number,
  ): void {
    if (!availCount || availCount <= 0) return;
    const bought = this._boughtCount(shopKey, goodId);
    if (bought + count > availCount) {
      throw new ShopError(`商品 ${goodId} 已达限购（${availCount}）`);
    }
  }

  /** 读取/初始化 shop.<key> 基础结构（官服迁移数据缺字段时不 500） */
  /**
   * 商店状态兜底（draft 内创建/补全商店对象）
   *
   * 修复：原实现 `draft.shop[key] ?? 默认值` 只对"商店不存在"生效——玩家数据里商店
   * 已存在但字段缺失（如官服迁移的 SKIN 无 info）时返回原对象，info 为 undefined →
   * `.info.find` 500。此处对已存在对象也逐字段补全（info/progressInfo 等保证类型）。
   */
  private _shopDraft(draft: any, key: string): any {
    draft.shop = draft.shop ?? {};
    const st = (draft.shop[key] = draft.shop[key] ?? {});
    st.curShopId = st.curShopId ?? "";
    st.info = Array.isArray(st.info) ? st.info : [];
    st.progressInfo = st.progressInfo ?? {};
    st.charPurchase = st.charPurchase ?? {};
    st.groupInfo = st.groupInfo ?? {};
    return st;
  }

  /**
   * 每日刷新处理：重置低级商店每日限购记录
   */
  async dailyRefresh() {
    await this._player.update(async (draft) => {
      // 修复：兜底 shop.LS 缺失（官服迁移数据 shop 可能为空对象 → 原直接访问 .info 500）
      const ls = this._shopDraft(draft, "LS");
      ls.info = [];
      // 信用商店按当天日期重置（curShopId 对齐 buildSocialGoodList 的 goodId 前缀）
      if (draft.shop.SOCIAL) {
        draft.shop.SOCIAL.curShopId = this.todaySocialShopId();
        draft.shop.SOCIAL.info = [];
      }
    });
  }

  /** 当天信用商店 ID（SOCIAL<YYYYMMDD>，与 buildSocialGoodList 的 goodId 前缀一致） */
  todaySocialShopId(): string {
    const t = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    return `SOCIAL${t.getFullYear()}${p(t.getMonth() + 1)}${p(t.getDate())}`;
  }

  /**
   * 自动生成当天信用商店商品（信用商店 = 社交商店，客户端 /shop/getSocialGoodList）
   *
   * 修复：socialGoodList 构造期置空从未加载 → 信用商店空列表。基座数据在构造期异步
   * 载入 data/shop/SocialGoodList.json，此处把 goodId 日期前缀重定为当天
   * （SOCIAL<YYYYMMDD>_T<N>_<type>_<M>_<slot>，与玩家 shop.SOCIAL.info 记录对齐）。
   *
   * @returns 当天信用商店商品列表
   */
  /**
   * 干员合同价格（信用交易所干员合同无折扣，按累计信用消费档位定价，PRTS 数据）
   * @param unlockNum - 解锁所需累计消费
   * @returns 合同价格
   */
  private _creditContractPrice(unlockNum: number): number {
    const tiers: [number, number][] = [
      [0, 100],
      [200, 120],
      [500, 140],
      [1000, 160],
      [1500, 160],
      [2000, 180],
      [3000, 200],
      [4000, 200],
      [5000, 240],
      [6000, 240],
      [7000, 240],
      [8500, 240],
      [10000, 300],
    ];
    let price = 300;
    for (const [num, p] of tiers) {
      if (unlockNum >= num) price = p;
    }
    return price;
  }

  /**
   * 生成当天信用商店商品（信用交易所）
   *
   * 官服规则（PRTS）：每日 10 个商品；干员合同解锁后占第 1 栏位（1 干员 + 9 随机商品），
   * 干员信物换满（6 个）后不再占位（10 个随机商品）。
   * 修复：
   * - 干员合同只生成 1 个"当前干员"（creditUnlockGroup 顺序上第一个未满 6 信物的干员；
   *   全部满潜 → 无干员合同 → 10 个常规商品）——原实现把全部已购干员都生成合同（3 个），
   *   客户端干员区渲染异常/点击无效
   * - 干员购买上限固定 6（availCount = 6 - 已购，不依赖配置档位数）
   * - 常规商品：有干员时按当天日期种子随机取 9 个，无干员时 10 个
   * - creditGroup：玩家已购干员所在组（有 creditGroup2 干员 → creditGroup2）
   * - costSocialPoint：累计信用消费（玩家存档动态字段优先，否则按已购信物档位推导）
   * - charPurchase：玩家实际购买记录（与静态基座合并，玩家优先）
   *
   * @returns 信用商店商品列表 + 干员解锁进度数据
   */
  buildSocialGoodList(): SocialGoodList & {
    costSocialPoint: number;
    creditGroup: string;
  } {
    const base = this.socialGoodList;
    const prefix = this.todaySocialShopId();
    // 干员合同：玩家已购信物（静态基座合并 + 玩家实际，玩家优先）
    const playerSocial = this._player._playerdata.shop?.SOCIAL;
    const charPurchase: { [k: string]: number } = {
      ...(base?.charPurchase ?? {}),
      ...(playerSocial?.charPurchase ?? {}),
    };
    // 信用干员解锁配置（客户端 shop_client_table creditUnlockGroup）
    const unlockGroups = (excel.ShopClientTable as any)?.creditUnlockGroup ?? {};
    let creditGroup = "creditGroup1";
    let costSocialPoint = 0;
    // 按已购信物推导累计消费与所在组
    for (const [groupId, g] of Object.entries(unlockGroups)) {
      const entries: any[] = (g as any)?.charDict ?? [];
      for (const e of entries) {
        const bought = charPurchase[e.charId] ?? 0;
        if (!bought) continue;
        if (groupId === "creditGroup2") creditGroup = "creditGroup2";
        const my = entries.filter((x: any) => x.charId === e.charId);
        const tier = my[Math.min(bought, my.length) - 1];
        if (tier?.unlockNum) {
          costSocialPoint = Math.max(costSocialPoint, tier.unlockNum);
        }
      }
    }
    // 当前干员 = 组顺序上第一个未满 6 信的干员（上限固定 6；全满 → null）
    let currentChar: { charId: string; bought: number; unlockNum: number } | null = null;
    for (const [groupId, g] of Object.entries(unlockGroups)) {
      const entries: any[] = (g as any)?.charDict ?? [];
      const seen = new Set<string>();
      for (const e of entries) {
        if (seen.has(e.charId)) continue;
        seen.add(e.charId);
        const bought = charPurchase[e.charId] ?? 0;
        if (bought < 6) {
          const my = entries.filter((x: any) => x.charId === e.charId);
          const tier = my[Math.min(bought, my.length) - 1];
          currentChar = { charId: e.charId, bought, unlockNum: tier?.unlockNum ?? 0 };
          break;
        }
      }
      if (currentChar) break;
    }
    // 常规物资（每日从候选池按当天种子生成 count 个带折扣商品；跨日轮换、同日稳定）
    const goodList: SocialShopData[] = [];
    // 干员合同存在时占第 1 栏位 → 剩余 9 个随机物资；干员换完后 10 个随机物资
    const normal = this._buildSocialNormalGoods(currentChar ? 9 : 10, prefix);
    if (currentChar) {
      const price = this._creditContractPrice(currentChar.unlockNum);
      const contract: SocialShopData = {
        goodId: `${prefix}_T1_${currentChar.charId}`,
        displayName: this._charName(currentChar.charId),
        item: { id: currentChar.charId, count: 1, type: "CHAR" },
        price,
        availCount: Math.max(0, 6 - currentChar.bought),
        slotItem: {
          price,
          displayName: this._charName(currentChar.charId),
          item: { id: currentChar.charId, count: 1, type: "CHAR" },
        },
        discount: 0,
        originPrice: price,
      };
      goodList.push(contract); // 干员合同占第 1 栏位
      goodList.push(...normal);
    } else {
      goodList.push(...normal); // 干员已换完 → 10 个常规物资
    }
    // 玩家存档累计消费优先（buySocialGood 实时累计，动态字段）
    const savedCost = (playerSocial as any)?.costSocialPoint;
    if (typeof savedCost === "number" && savedCost > 0) {
      costSocialPoint = Math.max(costSocialPoint, savedCost);
    }
    return { goodList, charPurchase, costSocialPoint, creditGroup };
  }

  /**
   * 基于种子串的确定性伪随机数生成器（线性同余，同日稳定 / 跨日轮换）
   *
   * 信用交易所物资抽选/折扣需要"同一天多次请求返回一致、次日自然变化"的随机源，
   * 不能直接用 Math.random。以当天的日期前缀（SOCIAL<YYYYMMDD>）作种子。
   * @param seed - 随机种子串（当天日期前缀）
   * @returns 每次调用返回 [0,1) 的确定性随机函数
   */
  private _seededRng(seed: string): () => number {
    let s = 0;
    for (let i = 0; i < seed.length; i++) {
      s = (s * 31 + seed.charCodeAt(i)) >>> 0;
    }
    return () => {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 4294967296;
    };
  }

  /**
   * 决定单个信用交易所物资的折扣力度（对应 PRTS 折扣规则）
   *
   * 主档为 -50%/-75%；低概率（约 10%）出现 -95%/-99% 特价，且仅限允许特价的物资
   *（-95% 仅龙门币×1800/基础作战记录，-99% 仅龙门币×3600/初级作战记录）。
   * @param rand - 确定性随机函数
   * @param m - 候选物资
   * @returns 折扣力度（0 表示无折扣；0.5/0.75 普通档，0.95/0.99 特价档）
   */
  private _creditDiscount(rand: () => number, m: CreditShopMaterial): number {
    const r = rand();
    if (m.allow99 && r < 0.03) return 0.99;
    if (m.allow95 && r < 0.06) return 0.95;
    if (r < 0.45) return 0.5;
    return 0.75;
  }

  /**
   * 生成当天信用交易所随机物资商品（对应 PRTS 信用交易所机制）
   *
   * 候选池为 7 行「并列随机抽取项」，每日生成 count 个：每次从随机一行内随机取一个物资
   *（同一天内可命中同一行不同物资）。其中前 3~7 个（不超过 count）为打折商品——折扣高的
   * 排列在前，同档次（-75% 及以上）之间顺序不定。同日用当天日期种子稳定，次日自然轮换。
   * @param count - 需生成的物资数量（有干员合同 9，否则 10）
   * @param prefix - 当天日期前缀（SOCIAL<YYYYMMDD>）
   * @returns 按折扣从高到低排列的物资商品
   */
  private _buildSocialNormalGoods(
    count: number,
    prefix: string,
  ): SocialShopData[] {
    const rand = this._seededRng(prefix);
    // 1) 抽 count 个物资：每行随机取一个代表（有放回，允许命中同一行不同物资）
    const picked: { m: CreditShopMaterial; discount: number }[] = [];
    for (let i = 0; i < count; i++) {
      const row = CREDIT_SHOP_ROWS[Math.floor(rand() * CREDIT_SHOP_ROWS.length)];
      picked.push({
        m: row[Math.floor(rand() * row.length)],
        discount: 0,
      });
    }
    // 2) 决定打折商品数（3~7，不超过 count）并为其分配折扣
    const kDisc = Math.min(count, 3 + Math.floor(rand() * 5));
    const indices = Array.from({ length: count }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    const discounted = new Set(indices.slice(0, kDisc));
    // 特价（-95%/-99%）多于 1 个时，仅保留 1 个，其余降为普通档（PRTS：多特价倾向减少打折数）
    let special = 0;
    for (const idx of discounted) {
      const d = this._creditDiscount(rand, picked[idx].m);
      picked[idx].discount = d >= 0.9 ? (special++ === 0 ? d : 0.75) : d;
    }
    // 3) 转成协议商品，折扣高优先排前（同折扣保持生成序）
    return picked
      .map((p, idx): [SocialShopData, number, number] => [
        {
          goodId: `${prefix}_T2_goods_${idx + 1}_${idx + 1}`,
          displayName: p.m.name,
          originPrice: p.m.originPrice,
          price: Math.round(p.m.originPrice * (1 - p.discount)),
          discount: p.discount,
          availCount: -1, // 每日刷新，不限购
          item: { id: p.m.id, count: p.m.count, type: p.m.type },
        } as SocialShopData,
        p.discount,
        idx,
      ])
      .sort((a, b) => b[1] - a[1] || a[2] - b[2])
      .map(([g]) => g);
  }

  /**
   * 购买信用商店商品（信用 = status.socialPoint）
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buySocialGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 信用币反向入账（免费刷信用）；正整数校验
    this._assertBuyCount(count);
    const good = this.buildSocialGoodList().goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    const price = (good.price ?? 0) * count;
    // 修复：余额不足拒绝（原直接 socialPoint -= price → 信用扣成负数仍发货）
    this._assertAffordable("socialPoint", price);
    // 修复：信用商店商品每日限购（availCount）
    this._assertAvail("SOCIAL", goodId, count, good.availCount);
    await this._player.update(async (draft) => {
      // 扣信用（socialPoint）
      draft.status.socialPoint = (draft.status.socialPoint ?? 0) - price;
      // 记录购买（对齐官服 shop.SOCIAL.info [{id, count}]）
      if (!draft.shop.SOCIAL) {
        draft.shop.SOCIAL = {
          curShopId: "",
          info: [],
          charPurchase: {},
        };
      }
      const social = draft.shop.SOCIAL;
      social.curShopId = this.todaySocialShopId();
      // 修复：累计信用消费（响应 costSocialPoint 数据源——干员解锁进度按累计消费判断）
      (social as any).costSocialPoint =
        ((social as any).costSocialPoint ?? 0) + price;      // 修复：干员合同购买 → 更新 charPurchase（信物计数，客户端干员进度）
      if (good.item.type === "CHAR") {
        social.charPurchase = social.charPurchase ?? {};
        social.charPurchase[good.item.id] =
          (social.charPurchase[good.item.id] ?? 0) + count;
      }
      const info = social.info ?? [];
      const existing = info.find((i) => i.id === goodId);
      if (existing) {
        existing.count += count;
      } else {
        info.push({ id: goodId, count });
      }
    });
    // 带 type 发放（干员合同 CHAR → char:get 入账并返回 instId；其余 TKT/材料走 items:get）
    const item: ItemBundle = {
      id: good.item.id,
      count: good.item.count * count,
      type: good.item.type,
    };
    const granted = await this._issueCharItem(item);
    return [granted];
  }

  /**
   * 每月刷新处理
   *
   * 更新月度商店的ID和分组信息，重置购买记录。
   */
  async monthlyRefresh() {
    await this._player.update(async (draft) => {
      // 修复：兜底 shop.LS 缺失（同 dailyRefresh）
      const ls = this._shopDraft(draft, "LS");
      ls.curShopId = this.todayLowShopId();
      ls.curGroupId = `${this.todayLowShopId()}_Group_1`;
      ls.info = [];
    });
  }

  /**
   * 当前低级商店 ID（资质凭证区，按月刷新）
   *
   * 官服公式（参考 DoctoratePy shopGetLowGoodList）：ShopNumber = (年-2019)*12 + (月-5) + 1，
   * month 为 1-based。2026-08 → 88。修复：原公式 getMonth()(0-based)-5+(年-2019)*12 少 2，
   * 与官服/玩家存档（如 69=2025-01）不一致 → 客户端按 curShopId 计算刷新时间会偏差
   */
  todayLowShopId(): string {
    const t = new Date();
    const monthNum =
      (t.getFullYear() - 2019) * 12 + (t.getMonth() + 1 - 5) + 1;
    return `lggShdShopnumber${monthNum}`;
  }

  /**
   * 当前额外商店 ID（采购凭证区，按年刷新）
   *
   * 官服公式（参考 DoctoratePy shopGetExtraGoodList）：ShopId = xShdShopnumber<年-2021>。
   * 2026 → xShdShopnumber5；玩家旧数据 xShdShopnumber2（2023）→ 客户端刷新倒计时为负
   */
  todayExtraShopId(): string {
    return `xShdShopnumber${new Date().getFullYear() - 2021}`;
  }

  /**
   * 手动刷新额外商店（跨年更新 curShopId 并清空旧周期购买记录）
   */
  async refreshExtraShop(): Promise<void> {
    await this._player.update(async (draft) => {
      const es = this._shopDraft(draft, "ES");
      es.curShopId = this.todayExtraShopId();
      es.info = [];
    });
  }

  /**
   * 购买低级商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyLowGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 价格/发放取反 → 免费刷货币；正整数校验
    this._assertBuyCount(count);
    const good = excel.ShopTable.lowGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500（原 find! 断言 → undefined.item 崩溃）
    if (!good) return [];
    // 修复：余额不足拒绝（资质凭证 4005）
    this._assertAffordable("4005", good.price * count);
    // 修复：每日限购检查
    this._assertAvail("LS", goodId, count, good.availCount);
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const ls = this._shopDraft(draft, "LS");
      const existingItem = ls.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        ls.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4005", count: good.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    // 修复：BuyShopItem 任务事件从未 emit → 商店购买任务永不推进
    await this._trigger.emit("BuyShopItem", [{ type: "LS", socialPoint: 0 }]);
    return [item];
  }

  /**
   * 购买高级商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyHighGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷高级凭证；正整数校验
    this._assertBuyCount(count);
    const good =
      excel.ShopTable.highGoodList.goodList.find((g) => g.goodId === goodId) ??
      // 动态商品（根据当前标准池自动生成的干员区）
      this.buildHighCharGoods().find((g) => g.goodId === goodId) ??
      // 中坚甄选券（CLASSIC_FES_PICK_TIER_*/5，随中坚甄选池）
      this.buildFesPickGoods("HS").find((g) => g.goodId === goodId);
    // 防御：未知商品不 500
    if (!good) return [];
    let price = good.price;
    let item!: ItemBundle;
    if (!good?.progressGoodId) {
      // 修复：余额不足拒绝（高级凭证 4004）
      this._assertAffordable("4004", good.price * count);
      // 修复：限购检查
      this._assertAvail("HS", good.goodId, count, good.availCount);
    } else {
      // 进度商品：按档位定价，一次购买推进一档（count 按 1 档处理，费率一致）
      const progressGood =
        excel.ShopTable.highGoodList.progressGoodList[good.progressGoodId];
      const order =
        (this._player._playerdata.shop as any)?.HS?.progressInfo?.[
          good.progressGoodId
        ]?.order ?? 1;
      this._assertAffordable("4004", progressGood[order - 1]?.price ?? 0);
    }
    await this._player.update(async (draft) => {
      const hs = this._shopDraft(draft, "HS");
      if (!good?.progressGoodId) {
        item = { id: good.item.id, count: good.item.count * count, type: good.item.type };
        const existingItem = hs.info.find((i: any) => i.id === good.goodId);
        if (existingItem) {
          existingItem.count += count;
        } else {
          hs.info.push({ id: good.goodId, count: count });
        }
      } else {
        const progressGood =
          excel.ShopTable.highGoodList.progressGoodList[good.progressGoodId];
        let progressInfo = hs.progressInfo[good.progressGoodId];
        if (!progressInfo) {
          progressInfo = {
            order: 1,
            count: 0,
          };
        }
        price = progressGood[progressInfo.order - 1].price;
        item = progressGood[progressInfo.order - 1].item;
        // 修复：档位数取配置长度（原硬编码 5，进度档数变化时错乱）
        if (progressInfo.order < progressGood.length) {
          progressInfo.order += 1;
        } else {
          progressInfo.count += 1;
        }
        hs.progressInfo[good.progressGoodId] = progressInfo;
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4004", count: price * count }],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回带 instId（获得干员效果）；其余走 items:get
    const granted = await this._issueCharItem(item);
    // 修复：BuyShopItem 任务事件从未 emit → 商店购买任务永不推进
    await this._trigger.emit("BuyShopItem", [{ type: "HS", socialPoint: 0 }]);
    return [granted];
  }

  /**
   * 购买额外商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyExtraGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷黄票；正整数校验
    this._assertBuyCount(count);
    const good = excel.ShopTable.extraGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：余额不足拒绝（采购凭证 4006）
    this._assertAffordable("4006", good.price * count);
    // 修复：限购检查
    this._assertAvail("ES", goodId, count, good.availCount);
    const item = { id: good.item.id, count: good.item.count * count, type: good.item.type };
    await this._player.update(async (draft) => {
      const es = this._shopDraft(draft, "ES");
      const existingItem = es.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        es.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4006", count: good!.price * count }],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回带 instId 的效果，避免客户端显示"未知物品"
    const granted = await this._issueCharItem(item);
    // 修复：BuyShopItem 任务事件从未 emit → 商店购买任务永不推进
    await this._trigger.emit("BuyShopItem", [{ type: "ES", socialPoint: 0 }]);
    return [granted];
  }

  /**
   * 皮肤是否存在（皮肤表存在性防御）
   *
   * 修复：SkinGoodList.json 数据错位（如 char_254_vodfox_witch#2 漏写品牌分隔符 @）
   * 会下发皮肤表不存在的 skinId → 客户端预览图加载失败。购买/列表均按
   * excel.SkinTable.charSkins 校验，无效皮肤拒绝/过滤。
   * @param skinId - 皮肤 ID
   * @returns 皮肤表存在返回 true
   */
  private _skinExists(skinId: string): boolean {
    return Boolean((excel.SkinTable as any)?.charSkins?.[skinId]);
  }

  /**
   * 购买皮肤商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   */
  async buySkinGood(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
    const good = excel.ShopTable.skinGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500（原 find! 断言 → undefined.skinId 崩溃）
    if (!good) return;
    // 修复：皮肤表不存在（数据错位）拒绝——避免写入无效 characterSkins 条目导致预览图错误
    if (!this._skinExists(good.skinId)) {
      throw new ShopError(`皮肤 ${good.skinId} 不存在（数据错位）`);
    }
    // 修复：已拥有拒绝——皮肤经 CHAR_SKIN 入 characterSkins，重复购买应被服务端拒绝
    if (this._player._playerdata.skin?.characterSkins?.[good.skinId]) {
      throw new ShopError(`皮肤 ${good.skinId} 已拥有`);
    }
    // 修复：余额不足拒绝（至纯源石 4002）
    this._assertAffordable("4002", good.price);
    const item = { id: good.skinId, count: 1, type: "CHAR_SKIN" };
    // 修复：记录购买（原不写 SKIN.info → 客户端购买状态永远可买）
    await this._player.update(async (draft) => {
      const skin = this._shopDraft(draft, "SKIN");
      const existing = skin.info.find((i: any) => i.id === good.goodId);
      if (existing) {
        existing.count += 1;
      } else {
        skin.info.push({ id: good.goodId, count: 1 });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4002", type: "DIAMOND", count: good.price }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
  }

  /**
   * 购买现金商店商品
   *
   * 现金商店以钻石(androidDiamond/iosDiamond)作为货币，购买后记录购买次数。
   * 参考实现中现金商店为外部支付通道，此处简化为直接发放钻石并记录购买次数。
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @returns 获取的物品列表
   */
  async buyCashGood(args: { goodId: string }): Promise<ItemBundle[]> {
    const { goodId } = args;
    // 修复：兼容 AllProductList 基础 id（CS_1）与 CashGoodList 版本化 id（CS_1_r1/r2/r3）——
    // 客户端 createOrder 传 product_id（可为基础或版本化），按前缀匹配避免发货落空
    const good =
      excel.ShopTable.cashGoodList.goodList.find((g) => g.goodId === goodId) ??
      excel.ShopTable.cashGoodList.goodList.find((g) =>
        g.goodId.startsWith(goodId + "_"),
      );
    // 防御：未知商品不 500
    if (!good) return [];
    // 现金商店物品为钻石充值，发放钻石，并依据 doubleCount 判断是否为首充翻倍
    const isDouble = await this._player.update(async (draft) => {
      const cash = this._shopDraft(draft, "CASH");
      const existingItem = cash.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += 1;
        return 0;
      } else {
        cash.info.push({ id: goodId, count: 1 });
        return good.doubleCount > 0 ? 1 : 0;
      }
    });
    const diamondCount = isDouble
      ? good.diamondNum * 2 + good.plusNum
      : good.diamondNum + good.plusNum;
    const item: ItemBundle = {
      id: "4002",
      type: "DIAMOND",
      count: diamondCount,
    };
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  /**
   * 购买联合行动商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyEPGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷 EPGS 币；正整数校验
    this._assertBuyCount(count);
    const good = excel.ShopTable.EPGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：余额不足拒绝（寻访参数模型 EPGS_COIN）
    this._assertAffordable("EPGS_COIN", good.price * count);
    // 修复：限购检查
    this._assertAvail("EPGS", goodId, count, good.availCount);
    const item = { id: good.item.id, count: good.item.count * count, type: good.item.type };
    await this._player.update(async (draft) => {
      const epgs = this._shopDraft(draft, "EPGS");
      const existingItem = epgs.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        epgs.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "EPGS_COIN", count: good!.price * count }],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回 instId；其余走 items:get
    const granted = await this._issueCharItem(item);
    return [granted];
  }

  /**
   * 购买声望商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyREPGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷声望币；正整数校验
    this._assertBuyCount(count);
    const good = excel.ShopTable.REPGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：余额不足拒绝（情报凭证 REP_COIN）
    this._assertAffordable("REP_COIN", good.price * count);
    // 修复：限购检查
    this._assertAvail("REP", goodId, count, good.availCount);
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const rep = this._shopDraft(draft, "REP");
      const existingItem = rep.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        rep.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "REP_COIN", count: good.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  /**
   * 购买经典商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyClassicGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷经典票/凭证；正整数校验
    this._assertBuyCount(count);
    const good =
      excel.ShopTable.classicGoodList.goodList.find((g) => g.goodId === goodId) ??
      // 动态商品（根据当前中坚池自动生成的干员区）
      this.buildClassicCharGoods().find((g) => g.goodId === goodId) ??
      // 中坚甄选券（CLASSIC_FES_PICK_TIER_*/5，随中坚甄选池）
      this.buildFesPickGoods("KS").find((g) => g.goodId === goodId);
    // 防御：未知商品不 500
    if (!good) return [];
    let item!: ItemBundle;
    let price = good.price;
    if (!good?.progressGoodId) {
      // 修复：余额不足拒绝（高级凭证 4004）
      this._assertAffordable("4004", good.price * count);
      // 修复：限购检查
      this._assertAvail("CLASSIC", good.goodId, count, good.availCount);
    } else {
      // 进度商品：按档位定价，一次购买推进一档（count 按 1 档处理）
      const progressGood =
        excel.ShopTable.classicGoodList.progressGoodList[good.progressGoodId];
      const order =
        (this._player._playerdata.shop as any)?.CLASSIC?.progressInfo?.[
          good.progressGoodId
        ]?.order ?? 1;
      this._assertAffordable("4004", progressGood[order - 1]?.price ?? 0);
    }
    await this._player.update(async (draft) => {
      const classic = this._shopDraft(draft, "CLASSIC");
      if (!good?.progressGoodId) {
        item = { id: good.item.id, count: good.item.count * count, type: good.item.type };
        const existingItem = classic.info.find(
          (i: any) => i.id === good.goodId,
        );
        if (existingItem) {
          existingItem.count += count;
        } else {
          classic.info.push({ id: good.goodId, count: count });
        }
      } else {
        const { progressGoodId } = good;
        const progressGood =
          excel.ShopTable.classicGoodList.progressGoodList[progressGoodId];
        // 修复：先判空再解引用——原实现先取 progressInfo.order 后判空，
        // 首次购买（progressInfo 为 undefined）直接 TypeError 500
        let progressInfo = classic.progressInfo[progressGoodId];
        if (!progressInfo) {
          progressInfo = {
            order: 1,
            count: 0,
          };
          classic.progressInfo[progressGoodId] = progressInfo;
        }
        price = progressGood[progressInfo.order - 1].price;
        item = progressGood[progressInfo.order - 1].item;
        // 修复：档位数取配置长度（原硬编码 5）
        if (progressInfo.order < progressGood.length) {
          progressInfo.order += 1;
        } else {
          progressInfo.count += 1;
        }
      }
    });

    await this._trigger.emit("items:use", [
      [{ id: "4004", count: price * count }],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回带 instId（获得干员效果）；其余走 items:get
    const granted = await this._issueCharItem(item);
    await this._trigger.emit("BuyShopItem", [{ type: "CLASSIC", socialPoint: 0 }]);
    return [granted];
  }

  /**
   * 购买限定商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
  async buyLMTGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：查找范围含自动生成商品（当前池商品不在静态 LMTGSGoodList.json）
    const good =
      excel.ShopTable.LMTGSGoodList?.goodList.find(
        (g) => g.goodId === goodId,
      ) ?? this.buildLMTGSGoodList().find((g) => g.goodId === goodId);
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：扣对应池的寻访数据契约（price.id = LMTGS_COIN_<poolId>；原硬编码
    // "LMTGS_COIN" 通用 id 扣不到玩家手里的具体凭证）——先校验余额，不足拒绝
    this._assertAffordable(good.price.id, good.price.count * count);
    // 修复：限购检查（静态表 availCount；自动生成商品为 -1 不限）
    this._assertAvail("LMTGS", goodId, count, good.availCount);
    // 修复：记录购买（原不写任何记录 → 客户端 getGoodPurchaseState 永远可买）
    await this._player.update(async (draft) => {
      const shop = draft.shop as any;
      shop.LMTGS = shop.LMTGS ?? { info: [] };
      const existing = shop.LMTGS.info.find((i: any) => i.id === goodId);
      if (existing) {
        existing.count += count;
      } else {
        shop.LMTGS.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: good.price.id, count: good.price.count * count, type: good.price.type }],
    ]);
    // 带 type 发放（CHAR → char:get 入账干员并返回 instId，客户端"获得干员"效果）
    const item: ItemBundle = {
      id: good.item.id,
      count: good.item.count * count,
      type: good.item.type,
    };
    const granted = await this._issueCharItem(item);
    return [granted];
  }

  /** 自动生成的限定商店商品（懒构建，一次生成缓存） */
  private _autoLMTGSGoods: LMTGSGood[] | null = null;
  /** 自动生成的高级商店（HS 高级凭证区）干员商品（懒构建，随当前标准池） */
  private _autoHighGoods: QCObject[] | null = null;
  /** 自动生成的经典商店（CLASSIC 通用凭证区）干员商品（懒构建，随当前中坚池） */
  private _autoClassicGoods: QCObject[] | null = null;
  /** 自动生成的中坚甄选券商品（懒构建，随当前中坚甄选池；HS/KS 各一份） */
  private _autoFesPickGoods: { HS: QCObject[]; KS: QCObject[] } | null = null;

  /**
   * 当前限定池（LMTGS 商店按当期池代币过滤）
   *
   * 优先当前活跃 LIMITED 池（openTime<=now<=endTime），无活跃池回退最近一期
   *（数据版本落后/卡池空窗期商店仍有内容）。客户端限定商店只展示当期池商品，
   * 商品代币 = 当期池 lMTGSID（LMTGS_COIN_<poolId>）。
   * @returns 当前限定池，无则 null
   */
  currentLimitedPool(): (typeof excel.GachaTable.gachaPoolClient)[number] | null {
    const ts = now();
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => p.gachaRuleType === "LIMITED")
      .sort((a, b) => b.openTime - a.openTime);
    if (!pools.length) return null;
    return (
      pools.find((p) => p.openTime <= ts && ts <= p.endTime) ??
      pools[0]
    );
  }

  /**
   * 自动生成限定商店商品（运行时——新限定池无需手动补 LMTGSGoodList.json）
   *
   * 修复：按当期卡池过滤——只生成当前限定池（currentLimitedPool）商品，
   * 商品代币为当期池 lMTGSID；不再跨池返回全部 LIMITED 池商品（原实现客户端需按
   * LMTGSID 自行过滤，且非当期池商品用旧池代币无法购买）。
   * 每池生成：本池 UP 六星（300 凭证）+ 本池新五星（75 凭证）+
   * 历史限定六星（300 凭证，最多 4 个，排除本池已含）。goodId = `${poolId}_${seq}`
   * 稳定（客户端按 getLMTGSGoodList 拿到的 goodId 回传 buyLMTGSGood）。
   * 与静态 LMTGSGoodList.json 合并（静态保留当期池特殊商品，按 goodId 去重、自动优先）。
   *
   * @returns 自动生成的当期限定商品（客户端按当前池 LMTGSID 过滤）
   */
  buildLMTGSGoodList(): LMTGSGood[] {
    if (this._autoLMTGSGoods) return this._autoLMTGSGoods;
    const pool = this.currentLimitedPool();
    const goods: LMTGSGood[] = [];
    if (pool) {
      // 历史限定六星：全部 LIMITED 池的 UP 六星（去重、按池序收集），供当期池"历史限定"区
      const historical: string[] = [];
      const allPools = excel.GachaTable.gachaPoolClient
        .filter((p) => p.gachaRuleType === "LIMITED")
        .sort((a, b) => a.openTime - b.openTime);
      for (const p of allPools) {
        const detail = excel.GachaDetailTable.details[p.gachaPoolId];
        const up6 =
          (detail?.upCharInfo?.perCharList ?? []).filter(
            (c: GachaPerChar) => c.rarityRank === 5,
          );
        for (const c of up6) {
          for (const id of c.charIdList) {
            if (!historical.includes(id)) historical.push(id);
          }
        }
      }
      const detail = excel.GachaDetailTable.details[pool.gachaPoolId];
      const up = detail?.upCharInfo?.perCharList ?? [];
      const up6 = up.filter((c: GachaPerChar) => c.rarityRank === 5);
      const up4 = up.find((c: GachaPerChar) => c.rarityRank === 4);
      // 寻访数据契约按池（JSON 键 lMTGSID，如 LMTGS_COIN_7601）
      const token = (pool as any).lMTGSID || "LMTGS_COIN";
      let seq = 0;
      const push = (
        item: ItemBundle,
        price: number,
      ): void => {
        goods.push({
          goodId: `${pool.gachaPoolId}_${++seq}`,
          startTime: pool.openTime,
          endTime: pool.endTime,
          availCount: -1,
          item,
          price: { id: token, count: price, type: "LMTGS_COIN" },
          sortId: seq,
        });
      };
      // 本池 UP 六星（含限定干员）→ 300 凭证
      for (const c of up6) {
        for (const id of c.charIdList) push({ id, count: 1, type: "CHAR" }, 300);
      }
      // 本池新五星 → 75 凭证
      if (up4) {
        for (const id of up4.charIdList) push({ id, count: 1, type: "CHAR" }, 75);
      }
      // 历史限定六星（最多 4 个，排除本池已含）→ 300 凭证
      let added = 0;
      for (const id of historical) {
        if (added >= 4) break;
        if (up6.some((c: GachaPerChar) => c.charIdList.includes(id))) continue;
        push({ id, count: 1, type: "CHAR" }, 300);
        added++;
      }
    }
    this._autoLMTGSGoods = goods;
    return goods;
  }

  /**
   * 当前标准寻访池（高级凭证区干员来源）
   *
   * 标准池 gachaRuleType === 0（JSON 数字 0）。优先当前活跃池（openTime<=now<=endTime），
   * 无活跃池时取最近结束的一期（数据版本落后时商店仍有内容）。
   * @returns 标准池配置，无则 null
   */
  private _currentStandardPool(): (typeof excel.GachaTable.gachaPoolClient)[number] | null {
    const ts = now();
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => Number(p.gachaRuleType) === 0)
      .sort((a, b) => b.openTime - a.openTime);
    if (!pools.length) return null;
    return (
      pools.find((p) => p.openTime <= ts && ts <= p.endTime) ??
      pools[0]
    );
  }

  /**
   * 当前中坚池（CLASSIC 通用凭证区干员来源）
   *
   * 中坚规则：CLASSIC / CLASSIC_DOUBLE / CLASSIC_ATTAIN / FESCLASSIC / FESCLASSIC 变体。
   * @returns 中坚池配置，无则 null
   */
  private _currentClassicPool(): (typeof excel.GachaTable.gachaPoolClient)[number] | null {
    const ts = now();
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => /^(CLASSIC|FESCLASSIC)/.test(String(p.gachaRuleType)))
      .sort((a, b) => b.openTime - a.openTime);
    if (!pools.length) return null;
    return (
      pools.find((p) => p.openTime <= ts && ts <= p.endTime) ??
      pools[0]
    );
  }

  /**
   * 当前中坚甄选池（FESCLASSIC 二次元自选卡池；甄选券商品关联的池）
   *
   * 不混入 CLASSIC 常规中坚池：甄选券只对应 FESCLASSIC（中坚甄选）池。优先当前活跃
   *（openTime<=now<=endTime），无活跃池时回退最近开启的一期（数据版本落后时仍有内容）。
   * @returns 中坚甄选池配置，无则 null
   */
  private _currentFesClassicPool(): (typeof excel.GachaTable.gachaPoolClient)[number] | null {
    const ts = now();
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => String(p.gachaRuleType) === "FESCLASSIC")
      .sort((a, b) => b.openTime - a.openTime);
    if (!pools.length) return null;
    return pools.find((p) => p.openTime <= ts && ts <= p.endTime) ?? pools[0];
  }

  /**
   * 归一化自动生成商品的可见时间窗口（goodStartTime/goodEndTime）
   *
   * 修复：数据版本处于卡池空窗期（已无活跃池）时，_currentStandardPool/_currentClassicPool
   * 会回退到最近一期已结束的池，其 endTime 已过期。若直接把 pool.endTime 作为商品
   * goodEndTime，客户端会按它判定商品过期而下架/禁用该商品。
   * 此处当池已结束时，把 goodEndTime 顺延为"持续开放"（脚本化未来 +90 天），保证商店在
   * 空窗期仍可正常购买；池活跃时原样返回。
   * @param pool - 关联卡池
   * @returns 商品可见时间窗口
   */
  private _autoGoodsTime(pool: {
    openTime: number;
    endTime: number;
  }): { goodStartTime: number; goodEndTime: number } {
    const goodStartTime = pool.openTime;
    let goodEndTime = pool.endTime;
    // 池已结束（卡池空窗期）：商品持续开放，避免客户端按 goodEndTime 判过期
    if (pool.endTime < now()) {
      goodEndTime = now() + 90 * 86400;
    }
    return { goodStartTime, goodEndTime };
  }

  /** 干员展示名（CHAR 表缺失时回退 charId） */
  private _charName(charId: string): string {
    return (excel.CharacterTable as any)?.[charId]?.name ?? charId;
  }

  /**
   * 发放单件商品并返回供客户端展示（"获得干员"效果）
   *
   * 干员（CHAR）走 char:get 管线入账（获得 charInstId/潜能/凭证），并返回携带 instId
   *（干员实例 id）的 CHAR 条目——客户端据此弹出"获得干员"弹窗；其余类型走 items:get。
   * 修复：原实现一律 items:get [[item]]，CHAR 商品有些丢失 type（干员不入账），且返回不含
   * instId → 客户端购买干员无获得效果。
   * @param item - 待发放的商品（ID/数量/类型）
   * @returns 返回客户端的条目（CHAR 附带 instId）
   */
  private async _issueCharItem(item: ItemBundle): Promise<ItemBundle> {
    if (item.type === "CHAR" && item.id) {
      let charInstId = 0;
      await this._trigger.emit("char:get", [
        item.id,
        { from: "SHOP" },
        (res: any) => {
          charInstId = res?.charInstId ?? 0;
        },
      ]);
      return { ...item, instId: charInstId };
    }
    await this._trigger.emit("items:get", [[item]]);
    return item;
  }

  /**
   * 根据当前标准池自动生成高级凭证区（HS）干员商品
   *
   * 官服规则：高级凭证区干员随轮换卡池刷新——当期标准池 6★ 180 黄票 / 5★ 45 黄票
   *（萌娘百科：指定六星干员凭证 180、指定五星干员凭证 45）。
   * 标准池无结构化 upCharInfo，取 availCharInfo.perAvailList 中 6★(rarityRank 5)/5★(rarityRank 4)
   * 全部干员（当期标准池可获得的 6★/5★），goodId = `HS_${poolId}_${seq}` 稳定。
   * 与静态 HighGoodList.json 合并（静态保留材料区/progress 商品，按 goodId 去重、自动优先）。
   * @returns 自动生成的 HS 干员商品
   */
  buildHighCharGoods(): QCObject[] {
    if (this._autoHighGoods) return this._autoHighGoods;
    const pool = this._currentStandardPool();
    const goods: QCObject[] = [];
    if (pool) {
      const { goodStartTime, goodEndTime } = this._autoGoodsTime(pool);
      const detail = excel.GachaDetailTable.details[pool.gachaPoolId];
      let seq = 0;
      for (const avail of detail?.availCharInfo?.perAvailList ?? []) {
        const price =
          avail.rarityRank === 5 ? 180 : avail.rarityRank === 4 ? 45 : 0;
        if (!price) continue;
        for (const charId of avail.charIdList) {
          goods.push({
            goodId: `HS_${pool.gachaPoolId}_${++seq}`,
            displayName: this._charName(charId),
            priority: 1,
            number: seq,
            goodType: "NORMAL",
            item: { id: charId, count: 1, type: "CHAR" },
            progressGoodId: "",
            price,
            originPrice: price,
            discount: 0,
            availCount: 1,
            slotId: 0,
            groupId: "",
            goodStartTime,
            goodEndTime,
          } as QCObject);
        }
      }
    }
    this._autoHighGoods = goods;
    return goods;
  }

  /**
   * 根据当前中坚池自动生成通用凭证区（CLASSIC）干员商品
   *
   * 官服规则：通用凭证区干员随中坚卡池刷新——中坚池 UP 6★ 2000 / 5★ 500（蓝票；
   * 2025-05 起 1800/450，此处沿用静态数据 2000/500 与 buyClassicGood 扣费一致）。
   * 中坚池有结构化 upCharInfo.perCharList，直接取 UP 干员。
   * @returns 自动生成的 CLASSIC 干员商品
   */
  buildClassicCharGoods(): QCObject[] {
    if (this._autoClassicGoods) return this._autoClassicGoods;
    const pool = this._currentClassicPool();
    const goods: QCObject[] = [];
    if (pool) {
      const { goodStartTime, goodEndTime } = this._autoGoodsTime(pool);
      const detail = excel.GachaDetailTable.details[pool.gachaPoolId];
      let seq = 0;
      // 自选卡池（FESCLASSIC 中坚甄选）：干员区反映玩家 choosePoolUp 自选 UP，
      // 未自选/常规 CLASSIC 池时 effectiveUpPerCharList 原样返回静态 upCharInfo，
      // 行为不变（详见 GachaController.effectiveUpPerCharList）。
      const perCharList =
        this._player.gacha?.effectiveUpPerCharList(pool.gachaPoolId) ??
        detail?.upCharInfo?.perCharList ??
        [];
      for (const c of perCharList) {
        const price = c.rarityRank === 5 ? 2000 : c.rarityRank === 4 ? 500 : 0;
        if (!price) continue;
        for (const charId of c.charIdList) {
          goods.push({
            goodId: `KS_${pool.gachaPoolId}_${++seq}`,
            displayName: this._charName(charId),
            priority: 1,
            number: seq,
            goodType: "NORMAL",
            item: { id: charId, count: 1, type: "CHAR" },
            progressGoodId: "",
            price,
            originPrice: price,
            discount: 0,
            availCount: 1,
            slotId: 0,
            groupId: "",
            goodStartTime,
            goodEndTime,
          } as QCObject);
        }
      }
    }
    this._autoClassicGoods = goods;
    return goods;
  }

  /**
   * 解析中坚甄选券的物品 id
   *
   * 官服规则：券 id = `classic_fes_pick_tier_{稀有度}_{池序号}01`（如池 FESCLASSIC_76_0_2
   * → classic_fes_pick_tier_6_7601）。当前 excel 数据的 item_table 可能未收录当期池的券（版本
   * 落后），此时回退到已收录的同稀有度券 id（取后缀最大者），保证物品可被客户端正常解析；
   * 全无收录时仍按官服规则生成 id 并记 WARN 供补数据。
   * @param tier - 稀有度档（6=六星 / 5=五星）
   * @param poolId - 中坚甄选池 id（形如 FESCLASSIC_76_0_2）
   * @returns 可发放的券物品 id
   */
  private _pickTicketId(tier: number, poolId: string): string {
    // 池序号：取池 id 中版本号首段（FESCLASSIC_76_0_2 → 76）
    const seqMatch = /^FESCLASSIC_(\d+)/.exec(poolId);
    const seq = seqMatch ? seqMatch[1] : "00";
    const byRule = `classic_fes_pick_tier_${tier}_${seq}01`;
    const items: Record<string, unknown> = (excel.ItemTable as any)?.items ?? {};
    if (items[byRule]) return byRule;
    // 回退：取已收录同稀有度券中后缀最大者（越接近当期数据越新）
    const existing = Object.keys(items).filter((k) =>
      k.startsWith(`classic_fes_pick_tier_${tier}_`),
    );
    if (existing.length) {
      return existing.sort((a, b) =>
        Number(b.split("_").pop() ?? 0) - Number(a.split("_").pop() ?? 0),
      )[0];
    }
    logger.warn("shop", `中坚甄选券 ${byRule} 未收录于 item_table，按规则生成`);
    return byRule;
  }

  /**
   * 按当期中坚甄选（FESCLASSIC）池生成"中坚甄选 6/5★ 干员"甄选券商品
   *
   * 参考官方抓包 /shop/getClassicGoodList、/shop/getHighGoodList：两处都售卖两张甄选券
   *（CLASSIC_FES_PICK_TIER_6 / CLASSIC_FES_PICK_TIER_5），玩家购买后可在 FESCLASSIC 池
   * 通过 /gacha/choosePoolUp 自选 UP 干员并抽取（复用既有 gacha 自选抽卡逻辑）。
   * 价格对齐抓包——高级凭证区（HS）6★180/5★45，通用凭证区（KS）6★1800/5★450。
   * 无 FESCLASSIC 池时返回空数组（商店不展现甄选券）。
   * @param prefix - 商店前缀（HS=高级凭证区 / KS=通用凭证区），决定 goodId 与价格档位
   * @returns 甄选券商品列表（NORMAL；可空）
   */
  buildFesPickGoods(prefix: "HS" | "KS"): QCObject[] {
    if (this._autoFesPickGoods) return this._autoFesPickGoods[prefix];
    let resolved: { HS: QCObject[]; KS: QCObject[] } = { HS: [], KS: [] };
    const pool = this._currentFesClassicPool();
    if (pool) {
      // 两商店售卖的券物品一致（同一 FESCLASSIC 池、同一券），仅 goodId/价格档位不同
      const tier6 = this._pickTicketId(6, pool.gachaPoolId);
      const tier5 = this._pickTicketId(5, pool.gachaPoolId);
      resolved = {
        HS: [
          this._buildFesPickGood("HS", "6", tier6, pool, 180, "CLASSIC_FES_PICK_TIER_6"),
          this._buildFesPickGood("HS", "5", tier5, pool, 45, "CLASSIC_FES_PICK_TIER_5"),
        ].filter(Boolean) as QCObject[],
        KS: [
          this._buildFesPickGood("KS", "6", tier6, pool, 1800, "CLASSIC_FES_PICK_TIER_6"),
          this._buildFesPickGood("KS", "5", tier5, pool, 450, "CLASSIC_FES_PICK_TIER_5"),
        ].filter(Boolean) as QCObject[],
      };
    }
    this._autoFesPickGoods = resolved;
    return resolved[prefix];
  }

  /**
   * 构造单张甄选券商品（NORMAL）
   *
   * @param prefix - 商店前缀（HS/KS，用于 goodId 前缀与排序号）
   * @param tier - 稀有度档位标签（"6"/"5"）
   * @param ticketId - 甄选券物品 id
   * @param pool - 关联的 FESCLASSIC 池（提供时间窗）
   * @param price - 价格（按商店币种档位传入）
   * @param itemType - 物品类型（CLASSIC_FES_PICK_TIER_6 / _5）
   * @returns 单条甄选券商品
   */
  private _buildFesPickGood(
    prefix: "HS" | "KS",
    tier: string,
    ticketId: string,
    pool: (typeof excel.GachaTable.gachaPoolClient)[number],
    price: number,
    itemType: string,
  ): QCObject {
    const goodId = `${prefix}_FESPICK${tier}_${pool.gachaPoolId}`;
    return {
      goodId,
      displayName: tier === "6" ? "中坚甄选6星干员" : "中坚甄选5星干员",
      priority: 1,
      number: tier === "6" ? 1 : 2,
      goodType: "NORMAL",
      item: { id: ticketId, count: 1, type: itemType },
      progressGoodId: "",
      price,
      originPrice: price,
      discount: 0,
      availCount: 1,
      slotId: 0,
      groupId: "",
      goodStartTime: pool.openTime,
      goodEndTime: pool.endTime,
    };
  }

  /**
   * 高级凭证区完整商品列表（动态干员 + 静态材料区合并）
   * @returns 合并后的 HighGoodList
   */
  buildHighGoodList(): HighGoodList {
    const staticList = excel.ShopTable.highGoodList;
    const auto = this.buildHighCharGoods();
    const fesPick = this.buildFesPickGoods("HS");
    const autoIds = new Set([...auto, ...fesPick].map((g) => g.goodId));
    return {
      ...staticList,
      goodList: [
        ...auto,
        ...fesPick,
        ...staticList.goodList.filter((g) => !autoIds.has(g.goodId)),
      ],
    };
  }

  /**
   * 通用凭证区完整商品列表（动态干员 + 静态 progress 商品合并）
   * @returns 合并后的 ClassicGoodList
   */
  buildClassicGoodList(): ClassicGoodList {
    const staticList = excel.ShopTable.classicGoodList;
    const auto = this.buildClassicCharGoods();
    const fesPick = this.buildFesPickGoods("KS");
    const autoIds = new Set([...auto, ...fesPick].map((g) => g.goodId));
    return {
      ...staticList,
      goodList: [
        ...auto,
        ...fesPick,
        ...staticList.goodList.filter((g) => !autoIds.has(g.goodId)),
      ],
    };
  }

  /**
   * 声望商店（REP）商品列表
   *
   * 修复：剩余数量显示为负——客户端 RemainCount = availCount - 已购 count
   *（QCShopREPGood.RemainCount），限购修复前可无限购买的老存档 count 已超过静态
   * availCount → 显示负数。此处对每个商品按已购数量抬升 availCount 至 max(静态, 已购)，
   * 保证剩余 ≥ 0；已购达上限的商品显示售罄（isSoldOut），且 buyREPGood 的限购检查
   *（静态 availCount）继续拦截新购买，语义一致。
   * @returns 修正后的 REP 商品列表
   */
  buildREPGoodList(): REPGoodList {
    const staticList = excel.ShopTable.REPGoodList;
    return {
      ...staticList,
      goodList: staticList.goodList.map((g) => ({
        ...g,
        availCount: Math.max(g.availCount, this._boughtCount("REP", g.goodId)),
      })),
    };
  }

  /**
   * 手动刷新信用交易所（服务器指令入口）
   *
   * 自动刷新已由 dailyRefresh（每天 04:00 refresh:daily 事件）承担；此方法供管理端
   * 指令手动触发同一逻辑——重置低级商店/信用商店当日购买记录并更新信用商店 shopId。
   */
  async refreshSocialShop(): Promise<void> {
    await this.dailyRefresh();
  }

  /**
   * 购买家具商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.buyCount - 购买数量
   * @param args.costType - 消耗类型（COIN_FURN或DIAMOND）
   * @returns 获取的物品列表
   */
  async buyFurniGood(args: {
    goodId: string;
    buyCount: number;
    costType: string;
  }): Promise<ItemBundle[]> {
    const { goodId, buyCount, costType } = args;
    const good = excel.ShopTable.furniGoodList.goods.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500（数据版本错位）
    if (!good) return [];
    // 修复：负数 buyCount → 价格取反经 items:use 反向入账（免费刷家具/钻石）；正整数校验
    this._assertBuyCount(buyCount);
    // 修复：费用币种解析不再依赖 costType 严格等于 "COIN_FURN"。
    // 当前 FurniGoodList 数据 priceDia 全为 0（无源石价），非 "COIN_FURN" 的 costType
    // （如客户端传数值枚举）会被旧实现误判为源石分支 → 扣 priceDia(=0) → 家具免费、
    // 与客户端显示的家具币消耗不符。改为：有源石价且非家具币时才走源石，否则一律家具币。
    const isCoin = costType === "COIN_FURN" || !(good.priceDia > 0);
    const pay = isCoin ? good.priceCoin : good.priceDia;
    this._assertAffordable(isCoin ? "3401" : "4002", pay * buyCount);
    // 修复：限购检查（FurniGood.count 总可购数）
    this._assertAvail("FURNI", goodId, buyCount, good.count);
    if (isCoin) {
      await this._trigger.emit("items:use", [
        [{ id: "3401", count: good.priceCoin * buyCount }],
      ]);
    } else {
      // 修复：DIAMOND 分支 id 补全（原 id 为空串，仅靠 type 分支扣减）
      await this._trigger.emit("items:use", [
        [{ id: "4002", type: "DIAMOND", count: good.priceDia * buyCount }],
      ]);
    }
    await this._player.update(async (draft) => {
      const furni = this._shopDraft(draft, "FURNI");
      const existingItem = furni.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += buyCount;
      } else {
        furni.info.push({ id: goodId, count: buyCount });
      }
    });
    const item = { id: good.furniId, type: "FURN", count: buyCount };
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  /**
   * 购买家具组（客户端 body: { groupId, goods: [{id, count}] }——整组购买）
   *
   * 修复：原 buyFurniGroup 路由把组请求体透传给 buyFurniGood（单商品逻辑）→
   * goodId 解构不到 → 500。此处逐个结算组内家具：扣家具币 priceCoin、发放 FURN、
   * 记录 shop.FURNI.info；未知商品（数据版本错位）跳过不 500。
   * @param args - 购买参数
   * @returns 发放的家具物品列表
   */
  async buyFurniGroup(args: {
    groupId?: string;
    goods?: { id: string; count: number }[];
  }): Promise<ItemBundle[]> {
    const items: ItemBundle[] = [];
    for (const g of args.goods ?? []) {
      const good = excel.ShopTable.furniGoodList.goods.find(
        (x) => x.goodId === g.id,
      );
      if (!good) continue; // 未知家具（数据版本错位）跳过
      const count = g.count ?? 1;
      // 修复：负数 count → 价格取反 → 免费刷家具币；正整数校验
      this._assertBuyCount(count);
      // 修复：余额不足的家具跳过（不扣不发，不影响组内其余结算）
      if (this._held("3401") < (good.priceCoin ?? 0) * count) continue;
      // 修复：限购检查
      this._assertAvail("FURNI", g.id, count, good.count);
      await this._trigger.emit("items:use", [
        [{ id: "3401", count: (good.priceCoin ?? 0) * count }],
      ]);
      await this._player.update(async (draft) => {
        const furni = this._shopDraft(draft, "FURNI");
        const existing = furni.info.find((i: any) => i.id === g.id);
        if (existing) {
          existing.count += count;
        } else {
          furni.info.push({ id: g.id, count });
        }
      });
      items.push({ id: good.furniId, type: "FURN", count });
    }
    await this._trigger.emit("items:get", [items]);
    return items;
  }

  /**
   * 使用凭证购买礼包商店商品
   *
   * 对应参考实现中的 buyShopGoodWithTicket，根据 goodId 解析礼包分类，
   * 找到对应礼包配置后发放其中的所有物品。
   * goodId 格式约定为 `GP_<goodType>_<序列>`，例如 `GP_Once_xxx`、`GP_NpOne_xxx`、`GP_gM_xxx`。
   * - goodType=gM：月度礼包，位于 GPGoodList.monthlyGroup.packages
   * - goodType=Once：一次性礼包，位于 GPGoodList.oneTimeGP
   * - goodType=NpOne：选择礼包，位于 GPGoodList.chooseGroup
   * 凭证(ticket)的扣减由调用方在路由层之上处理，本方法只负责发放物品。
   * @param args - 购买参数
   * @param args.ticketId - 凭证ID
   * @param args.goodId - 商品ID
   * @returns 获取的物品列表
   */
  async buyGoodWithTicket(args: {
    ticketId: string;
    goodId: string;
  }): Promise<ItemBundle[]> {
    const { goodId } = args;
    const parts = goodId.split("_");
    // 解析 goodId 中的 goodType 部分，格式为 `GP_<goodType>_<序列>`
    const goodType = parts[1];
    const gpList: GPGoodList = excel.ShopTable.GPGoodList;
    let configItems: ItemBundle[] = [];
    let availCount = 0;

    if (goodType === "gM") {
      // 月度礼包：monthlyGroup.packages 是字典，直接按 goodId 取
      const group: PeriodicityGroup = gpList.monthlyGroup;
      const pkg: PeriodicityGPItem | undefined = group?.packages?.[goodId];
      if (pkg) {
        configItems = pkg.items;
        availCount = pkg.availCount;
      }
    } else if (goodType === "Once") {
      // 一次性礼包：oneTimeGP 是数组，需遍历查找
      // 修复：数据字段可能为 null → 防御不 500
      const found = (gpList.oneTimeGP ?? []).find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as NormalGPItem).items;
        availCount = found.availCount;
      }
    } else if (goodType === "NpOne") {
      // 选择礼包：chooseGroup 是数组，需遍历查找
      const found = (gpList.chooseGroup ?? []).find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as ChooseGPItem).items;
        availCount = found.availCount;
      }
    } else if (goodType === "Lv") {
      // 等级礼包：levelGP 是数组
      const found = (gpList.levelGP ?? []).find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as LevelGPItem).items;
        availCount = found.availCount;
      }
    } else if (goodType === "gW") {
      // 周度礼包：weeklyGroup.packages 是字典
      // 修复：数据 goodId = GP_gW_*（原匹配 "Wk" 永不命中 → 周礼包不发放）
      const group: PeriodicityGroup = gpList.weeklyGroup;
      const pkg: PeriodicityGPItem | undefined = group?.packages?.[goodId];
      if (pkg) {
        configItems = pkg.items;
        availCount = pkg.availCount;
      }
    } else if (goodType === "Ms") {
      // 月卡礼包：monthlySub 是数组
      const found = (gpList.monthlySub ?? []).find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as MonthlySubItem).items;
        availCount = found.availCount;
      }
    }

    // 发放礼包内的所有物品
    if (configItems.length > 0) {
      // 修复：限购检查（一次性/月卡等礼包 shop.GP.<type>.info 记录）
      if (availCount > 0) {
        const gpInfo =
          (this._player._playerdata.shop as any)?.GP?.[
            goodType === "Once"
              ? "oneTime"
              : goodType === "Lv"
                ? "level"
                : goodType === "gW"
                  ? "weekly"
                  : goodType === "gM"
                    ? "monthly"
                    : goodType === "NpOne"
                      ? "choose"
                      : "monthlySub"
          ]?.info ?? [];
        const bought = (gpInfo.find((i: any) => i.id === goodId)?.count ?? 0);
        if (bought + 1 > availCount) {
          throw new ShopError(`礼包 ${goodId} 已达限购（${availCount}）`);
        }
        await this._player.update(async (draft) => {
          const shop = draft.shop as any;
          shop.GP = shop.GP ?? {};
          const sub =
            goodType === "Once"
              ? "oneTime"
              : goodType === "Lv"
                ? "level"
                : goodType === "gW"
                  ? "weekly"
                  : goodType === "gM"
                    ? "monthly"
                    : goodType === "NpOne"
                      ? "choose"
                      : "monthlySub";
          shop.GP[sub] = shop.GP[sub] ?? { info: [], valid: [], curGroupId: "" };
          const rec = shop.GP[sub].info.find((i: any) => i.id === goodId);
          if (rec) {
            rec.count += 1;
          } else {
            shop.GP[sub].info.push({ id: goodId, count: 1 });
          }
        });
      }
      // 修复：逐件发放——干员（CHAR）走 char:get 入账并带 instId（客户端"获得干员"效果），
      // 其余走 items:get。原实现一次性 items:get [configItems]，CHAR 无 instId → pay/其他
      // 发放干员的礼包客户端无获得效果（甚至解析异常）。
      const granted: ItemBundle[] = [];
      for (const ci of configItems) {
        granted.push(await this._issueCharItem(ci));
      }
      return granted;
    }
    return configItems;
  }

  /**
   * 获取现金商品购买结果
   *
   * 参考实现中此接口为占位（返回 202），用于外部支付通道回调后的查询。
   * 此处简化实现：返回玩家当前 shop.CASH 的购买记录作为结果。
   * @returns 购买记录信息
   */
  async getCashGoodPurchaseResult(): Promise<{
    info: { id: string; count: number }[];
  }> {
    return {
      // 修复：兜底 CASH 缺失（官服迁移数据 shop 可能为空对象 → 原直接访问 .info 500）
      info: this._player._playerdata.shop.CASH?.info ?? [],
    };
  }

  /**
   * 获取凭证皮肤商品列表
   *
   * 凭证皮肤指通过特殊凭证兑换的皮肤，列表来源于 SkinTable 中的相关配置。
   * 参考实现中此接口为占位（返回 202）。此处基于皮肤商店列表筛选可用项返回。
   * @returns 凭证皮肤商品列表
   */
  getVoucherSkinGoodList(): { goodList: unknown[] } {
    // 简化实现：返回皮肤商店中标记为可兑换(isRedeem)的皮肤
    // 修复：过滤皮肤表不存在的条目（数据错位 → 客户端预览图加载失败）
    const voucherGoods = excel.ShopTable.skinGoodList.goodList.filter(
      (g) => g.isRedeem && this._skinExists(g.skinId),
    );
    return { goodList: voucherGoods };
  }

  /**
   * 使用凭证兑换皮肤
   *
   * 参考实现中此接口为占位（返回 202）。此处实现：扣减凭证物品并发放对应皮肤。
   * @param args - 兑换参数
   * @param args.goodId - 商品ID（对应 skinGoodList 中的 goodId）
   */
  async useVoucherSkin(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
    const good = excel.ShopTable.skinGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    if (!good) {
      return;
    }
    // 修复：皮肤表不存在（数据错位）拒绝——避免写入无效 characterSkins 条目
    if (!this._skinExists(good.skinId)) {
      return;
    }
    // 修复：凭证核销——凭证皮肤商品 currencyUnit 即凭证物品 id（DIAMOND 除外；
    // 当前 SkinGoodList.json 无 isRedeem 商品，此路径有配置时不再无限免费兑换）
    if (good.isRedeem && good.currencyUnit && good.currencyUnit !== "DIAMOND") {
      await this._trigger.emit("items:use", [
        [{ id: good.currencyUnit, count: 1 }],
      ]);
    }
    // 发放皮肤物品
    const item: ItemBundle = {
      id: good.skinId,
      count: 1,
      type: "CHAR_SKIN",
    };
    await this._player.update(async (draft) => {
      // 修复：兑换记录写入 SKIN 商店而非信用商店（原写 SOCIAL.info 污染信用记录）
      const skin = this._shopDraft(draft, "SKIN");
      const existingItem = skin.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += 1;
      } else {
        skin.info.push({ id: goodId, count: 1 });
      }
    });
    await this._trigger.emit("items:get", [[item]]);
  }

  /**
   * 检查商店禁止状态
   *
   * 参考实现中此接口为占位（返回 202）。此处简化实现：永远返回未禁止状态。
   * 用于客户端校验玩家是否被限制购买，正常游戏状态下应始终为允许。
   * @returns 禁止状态信息
   */
  checkForbidden(): { forbidden: boolean; reason: string } {
    return {
      forbidden: false,
      reason: "",
    };
  }
}

export default ShopController;
