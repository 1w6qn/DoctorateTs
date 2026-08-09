/**
 * 模板商店路由模块（奇象巡展/方舟枢纽商店）
 *
 * 处理模板商店相关的 HTTP 请求，包括商品列表查询和购买操作。
 * 商品配置来自 data/shop/templateShop.json（参考 ODPY 数据源，33 家商店含
 * sandbox_1/2、shop_act53side 等）；请求/响应类型见
 * @game/model/protocol/templateShop（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { readJsonSync } from "@utils/file";
import { ItemBundle } from "@excel/character_table";
import {
  TemplateBuyGoodRequest,
  TemplateBuyGoodResponse,
  TemplateGetGoodListRequest,
  TemplateGetGoodListResponse,
} from "../model/protocol/templateShop";

const router = Router();

/** 模板商店配置（启动时读一次） */
const templateShopData = readJsonSync<{
  [shopId: string]: {
    shopId: string;
    price: { id: string; count: number; type: string };
    shopGroup: { [groupId: string]: { shopGood: { [goodId: string]: any } } };
  };
}>("./data/shop/templateShop.json");

/**
 * 获取商品列表
 * @route POST /templateShop/getGoodList
 * @param req.body.shopId - 商店ID
 * @returns 商品数据、下次同步时间和玩家增量数据
 *
 * 修复：原实现返回空 data（商店打不开）；现按 ODPY 读取
 * templateShop.json[shopId] 返回完整商店配置
 */
router.post("/getGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { shopId } = req.body as TemplateGetGoodListRequest;
  const data = templateShopData?.[shopId];
  res.send({
    data: data ?? {},
    nextSyncTime: -1,
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  } satisfies TemplateGetGoodListResponse);
});

/**
 * 购买商品
 * @route POST /templateShop/buyGood
 * @param req.body - CS: TemplateBuyGoodRequest { shopId, goodId, count }
 * @returns 购买结果 itemList 和玩家增量数据
 *
 * 修复：原实现原样回显请求体（客户端拿不到 itemList/增量）；
 * 现按商店配置校验并发放商品（扣货币 → 发物品 → 记录购买次数）
 */
router.post("/buyGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as TemplateBuyGoodRequest;
  const { shopId, goodId, count = 1 } = body;
  const shop = templateShopData?.[shopId];

  // 在全部 shopGroup 中查找商品
  let good: any;
  if (shop) {
    for (const group of Object.values(shop.shopGroup ?? {})) {
      if (group?.shopGood?.[goodId]) {
        good = group.shopGood[goodId];
        break;
      }
    }
  }

  const items: ItemBundle[] = [];
  if (good) {
    await player.update(async (draft) => {
      // 购买记录（模板商店无独立字段，用 (draft as any).templateShop 记录）
      let tshop = (draft as any).templateShop as any;
      if (!tshop) {
        (draft as any).templateShop = {};
        tshop = (draft as any).templateShop;
      }
      if (!tshop[shopId]) tshop[shopId] = {};
      // 限购检查（availCount）
      const bought = tshop[shopId][goodId] ?? 0;
      if (good.availCount && bought + count > good.availCount) {
        return;
      }
      // 扣货币（商店 price 指定货币；不足则不发放）
      const price = good.price ?? shop.price?.count ?? 0;
      const currencyId = shop?.price?.id;
      const currencyType = shop?.price?.type;
      if (currencyId && price > 0) {
        const have =
          currencyType === "GOLD"
            ? draft.status.gold
            : draft.inventory[currencyId] ?? 0;
        if (have < price * count) return;
        if (currencyType === "GOLD") {
          draft.status.gold -= price * count;
        } else {
          draft.inventory[currencyId] = have - price * count;
        }
      }
      tshop[shopId][goodId] = bought + count;
      // 发放商品
      const item = good.item ?? {};
      items.push({
        id: item.id ?? goodId,
        type: item.type ?? "MATERIAL",
        count: (item.count ?? 1) * count,
      });
    });
  }

  // 物品经 items:get 发放（干员走 char 入账，其余走 inventory）
  if (items.length > 0) {
    await player._trigger.emit("items:get", [items]);
  }
  res.send({
    itemList: items,
    ...player.delta,
  } satisfies TemplateBuyGoodResponse);
});

export default router;
