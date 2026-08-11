/**
 * 商店控制器类
 *
 * 负责处理商店购买相关的核心业务逻辑，包括低级商店、高级商店、皮肤商店、
 * 家具商店等多种类型商店的购买操作和刷新逻辑。
 */

import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { readJson } from "@utils/file";
import {
  ChooseGPItem,
  GPGoodList,
  LevelGPItem,
  LMTGSGood,
  MonthlySubItem,
  NormalGPItem,
  PeriodicityGroup,
  PeriodicityGPItem,
  SocialGoodList,
} from "@excel/shop";
import excel from "@excel/excel";
import { GachaPerChar } from "@excel/gacha_detail_table";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";

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
    this.socialGoodList = {
      goodList: [],
      charPurchase: {},
    };
    // 信用商店商品基座（静态配置；buildSocialGoodList 按当天日期重新生成）
    void readJson<SocialGoodList>("./data/shop/SocialGoodList.json")
      .then((d) => {
        this.socialGoodList = d;
      })
      .catch(() => {});
  }

  /**
   * 每日刷新处理：重置低级商店每日限购记录
   */
  async dailyRefresh() {
    await this._player.update(async (draft) => {
      draft.shop.LS.info = [];
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
  buildSocialGoodList(): SocialGoodList {
    const base = this.socialGoodList;
    if (!base?.goodList?.length) return { goodList: [], charPurchase: {} };
    const prefix = this.todaySocialShopId();
    const goodList = base.goodList.map((g) =>
      g.goodId.startsWith(prefix)
        ? g
        : { ...g, goodId: g.goodId.replace(/^SOCIAL\d+/, prefix) },
    );
    return { goodList, charPurchase: base.charPurchase ?? {} };
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
    const good = this.buildSocialGoodList().goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    const price = (good.price ?? 0) * count;
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
      draft.shop.SOCIAL.curShopId = this.todaySocialShopId();
      const info = draft.shop.SOCIAL.info ?? [];
      const existing = info.find((i) => i.id === goodId);
      if (existing) {
        existing.count += count;
      } else {
        info.push({ id: goodId, count });
      }
    });
    // 带 type 发放（TKT_RECRUIT/MATERIAL/CARD_EXP 等走 items:get）
    const item: ItemBundle = {
      id: good.item.id,
      count: good.item.count * count,
      type: good.item.type,
    };
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  /**
   * 每月刷新处理
   *
   * 更新月度商店的ID和分组信息，重置购买记录。
   */
  async monthlyRefresh() {
    const ts = new Date();
    const monthNum = ts.getMonth() - 5 + (ts.getFullYear() - 2019) * 12;
    await this._player.update(async (draft) => {
      draft.shop.LS.curShopId = `lggShdShopnumber${monthNum}`;
      draft.shop.LS.curGroupId = `lggShdGroupnumber${monthNum}_Group_1`;
      draft.shop.LS.info = [];
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
    const good = excel.ShopTable.lowGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.LS.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.LS.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4005", count: good.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
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
    const good = excel.ShopTable.highGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    let price = good.price;
    let item!: ItemBundle;
    await this._player.update(async (draft) => {
      if (!good?.progressGoodId) {
        item = { id: good.item.id, count: good.item.count * count };
        const existingItem = draft.shop.HS.info.find(
          (i) => i.id === good.goodId,
        );
        if (existingItem) {
          existingItem.count += count;
        } else {
          draft.shop.HS.info.push({ id: good.goodId, count: count });
        }
      } else {
        const progressGood =
          excel.ShopTable.highGoodList.progressGoodList[good.progressGoodId];
        let progressInfo = draft.shop.HS.progressInfo[good.progressGoodId];
        if (!progressInfo) {
          progressInfo = {
            order: 1,
            count: 0,
          };
        }
        price = progressGood[progressInfo.order - 1].price;
        item = progressGood[progressInfo.order - 1].item;
        if (progressInfo.order < 5) {
          progressInfo.order += 1;
        } else {
          progressInfo.count += 1;
        }
        draft.shop.HS.progressInfo[good.progressGoodId] = progressInfo;
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4004", count: price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
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
    const good = excel.ShopTable.extraGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.ES.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.ES.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4006", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
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
    )!;
    const item = { id: good.skinId, count: 1, type: "CHAR_SKIN" };
    await this._trigger.emit("items:use", [
      [{ id: "4002", count: good.price }],
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
    const good = excel.ShopTable.cashGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    // 现金商店物品为钻石充值，发放钻石，并依据 doubleCount 判断是否为首充翻倍
    const isDouble = await this._player.update(async (draft) => {
      const existingItem = draft.shop.CASH.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += 1;
        return 0;
      } else {
        draft.shop.CASH.info.push({ id: goodId, count: 1 });
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
    const good = excel.ShopTable.EPGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.EPGS.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.EPGS.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "EPGS_COIN", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
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
    const good = excel.ShopTable.REPGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    const item = { id: good.item.id, count: good.item.count * count };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.REP.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.REP.info.push({ id: goodId, count });
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
    const good = excel.ShopTable.classicGoodList.goodList.find(
      (g) => g.goodId === goodId,
    )!;
    let item!: ItemBundle;
    let price = good.price;
    await this._player.update(async (draft) => {
      if (!good?.progressGoodId) {
        item = { id: good.item.id, count: good.item.count * count };
        const existingItem = draft.shop.CLASSIC.info.find(
          (i) => i.id === good.goodId,
        );
        if (existingItem) {
          existingItem.count += count;
        } else {
          draft.shop.CLASSIC.info.push({ id: good.goodId, count: count });
        }
      } else {
        const { progressGoodId } = good;
        const progressGood =
          excel.ShopTable.classicGoodList.progressGoodList[progressGoodId];
        let progressInfo = draft.shop.CLASSIC.progressInfo[progressGoodId];
        price = progressGood[progressInfo.order - 1].price;
        item = progressGood[progressInfo.order - 1].item;
        if (!progressInfo) {
          progressInfo = {
            order: 1,
            count: 0,
          };
        }

        if (progressInfo.order < 5) {
          progressInfo.order += 1;
        } else {
          progressInfo.count += 1;
        }
        draft.shop.CLASSIC.progressInfo[progressGoodId] = progressInfo;
      }
    });

    await this._trigger.emit("items:use", [
      [{ id: "4004", count: price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
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
    // "LMTGS_COIN" 通用 id 扣不到玩家手里的具体凭证）
    await this._trigger.emit("items:use", [
      [{ id: good.price.id, count: good.price.count * count, type: good.price.type }],
    ]);
    // 带 type 发放（CHAR → char:get 入账干员；原缺 type → gainItem 查不到 ItemTable 跳过）
    const item: ItemBundle = {
      id: good.item.id,
      count: good.item.count * count,
      type: good.item.type,
    };
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  /** 自动生成的限定商店商品（懒构建，一次生成缓存） */
  private _autoLMTGSGoods: LMTGSGood[] | null = null;

  /**
   * 自动生成限定商店商品（运行时——新限定池无需手动补 LMTGSGoodList.json）
   *
   * 每个 LIMITED 池生成：本池 UP 六星（300 凭证）+ 本池新五星（75 凭证）+
   * 历史限定六星（300 凭证，最多 4 个，排除本池已含）。goodId = `${poolId}_${seq}`
   * 稳定（客户端按 getLMTGSGoodList 拿到的 goodId 回传 buyLMTGSGood）。
   * 与静态 LMTGSGoodList.json 合并（静态保留特殊商品，按 goodId 去重、自动优先）。
   *
   * @returns 自动生成的全部限定商品（跨池，客户端按当前池 LMTGSID 过滤）
   */
  buildLMTGSGoodList(): LMTGSGood[] {
    if (this._autoLMTGSGoods) return this._autoLMTGSGoods;
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => p.gachaRuleType === "LIMITED")
      .sort((a, b) => a.gachaIndex - b.gachaIndex);
    // 历史限定六星：全部 LIMITED 池的 UP 六星（去重、按池序收集）
    const historical: string[] = [];
    for (const p of pools) {
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
    const goods: LMTGSGood[] = [];
    for (const p of pools) {
      const detail = excel.GachaDetailTable.details[p.gachaPoolId];
      const up = detail?.upCharInfo?.perCharList ?? [];
      const up6 = up.filter((c: GachaPerChar) => c.rarityRank === 5);
      const up4 = up.find((c: GachaPerChar) => c.rarityRank === 4);
      const token = p.LMTGSID || "LMTGS_COIN";
      const start = p.openTime;
      const end = p.endTime;
      let seq = 0;
      const push = (
        item: ItemBundle,
        price: number,
      ): void => {
        goods.push({
          goodId: `${p.gachaPoolId}_${++seq}`,
          startTime: start,
          endTime: end,
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
    if (costType === "COIN_FURN") {
      await this._trigger.emit("items:use", [
        [{ id: "3401", count: good.priceCoin * buyCount }],
      ]);
    } else {
      await this._trigger.emit("items:use", [
        [{ id: "", type: "DIAMOND", count: good.priceDia * buyCount }],
      ]);
    }
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.FURNI.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += buyCount;
      } else {
        draft.shop.FURNI.info.push({ id: goodId, count: buyCount });
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
      await this._trigger.emit("items:use", [
        [{ id: "3401", count: (good.priceCoin ?? 0) * count }],
      ]);
      await this._player.update(async (draft) => {
        if (!draft.shop.FURNI) {
          draft.shop.FURNI = { info: [], groupInfo: {} };
        }
        const existing = draft.shop.FURNI.info.find((i) => i.id === g.id);
        if (existing) {
          existing.count += count;
        } else {
          draft.shop.FURNI.info.push({ id: g.id, count });
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

    if (goodType === "gM") {
      // 月度礼包：monthlyGroup.packages 是字典，直接按 goodId 取
      const group: PeriodicityGroup = gpList.monthlyGroup;
      const pkg: PeriodicityGPItem | undefined = group.packages[goodId];
      if (pkg) {
        configItems = pkg.items;
      }
    } else if (goodType === "Once") {
      // 一次性礼包：oneTimeGP 是数组，需遍历查找
      const found = gpList.oneTimeGP.find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as NormalGPItem).items;
      }
    } else if (goodType === "NpOne") {
      // 选择礼包：chooseGroup 是数组，需遍历查找
      const found = gpList.chooseGroup.find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as ChooseGPItem).items;
      }
    } else if (goodType === "Lv") {
      // 等级礼包：levelGP 是数组
      const found = gpList.levelGP.find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as LevelGPItem).items;
      }
    } else if (goodType === "Wk") {
      // 周度礼包：weeklyGroup.packages 是字典
      const group: PeriodicityGroup = gpList.weeklyGroup;
      const pkg: PeriodicityGPItem | undefined = group.packages[goodId];
      if (pkg) {
        configItems = pkg.items;
      }
    } else if (goodType === "Ms") {
      // 月卡礼包：monthlySub 是数组
      const found = gpList.monthlySub.find((g) => g.goodId === goodId);
      if (found) {
        configItems = (found as MonthlySubItem).items;
      }
    }

    // 发放礼包内的所有物品
    if (configItems.length > 0) {
      await this._trigger.emit("items:get", [configItems]);
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
      info: this._player._playerdata.shop.CASH.info,
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
    const voucherGoods = excel.ShopTable.skinGoodList.goodList.filter(
      (g) => g.isRedeem,
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
    // 发放皮肤物品
    const item: ItemBundle = {
      id: good.skinId,
      count: 1,
      type: "CHAR_SKIN",
    };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.SOCIAL.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += 1;
      } else {
        draft.shop.SOCIAL.info.push({ id: goodId, count: 1 });
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
