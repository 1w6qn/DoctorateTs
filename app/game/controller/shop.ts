/**
 * 商店控制器类
 *
 * 负责处理商店购买相关的核心业务逻辑，包括低级商店、高级商店、皮肤商店、
 * 家具商店等多种类型商店的购买操作和刷新逻辑。
 */

import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import {
  ChooseGPItem,
  GPGoodList,
  LevelGPItem,
  MonthlySubItem,
  NormalGPItem,
  PeriodicityGroup,
  PeriodicityGPItem,
  SocialGoodList,
} from "@excel/shop";
import excel from "@excel/excel";
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
  }

  /** 每日刷新处理（预留） */
  async dailyRefresh() {}

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
    const good = excel.ShopTable.LMTGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._trigger.emit("items:use", [
      [{ id: "LMTGS_COIN", count: good!.price.count * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
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
    )!;
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
