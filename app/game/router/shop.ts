/**
 * 商店路由模块
 *
 * 处理商店相关的 HTTP 请求，包括商品列表查询和各类商店的购买操作。
 * 路由层保持轻薄，业务逻辑委托给 ShopController / TroopManager 等 Manager 层处理。
 * 请求/响应类型见 @game/model/protocol/shop（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import excel from "@excel/excel";
import {
  BuyCashGoodRequest,
  BuyCashGoodResponse,
  BuyClassicGoodRequest,
  BuyClassicGoodResponse,
  BuyEPGSGoodRequest,
  BuyEPGSGoodResponse,
  BuyExtraGoodRequest,
  BuyExtraGoodResponse,
  BuyFurniGoodRequest,
  BuyFurniGoodResponse,
  BuyFurniGroupRequest,
  BuyGoodWithTicketRequest,
  BuyGoodWithTicketResponse,
  BuyHighGoodRequest,
  BuyHighGoodResponse,
  BuyLMTGSGoodRequest,
  BuyLMTGSGoodResponse,
  BuyLowGoodRequest,
  BuyLowGoodResponse,
  BuyREPGoodRequest,
  BuyREPGoodResponse,
  BuySkinGoodRequest,
  BuySkinGoodResponse,
  BuySocialGoodRequest,
  BuySocialGoodResponse,
  CheckForbiddenRequest,
  CheckForbiddenResponse,
  DecomposeClassicPotentialItemRequest,
  DecomposeClassicPotentialItemResponse,
  DecomposePotentialItemRequest,
  DecomposePotentialItemResponse,
  GetCashGoodListRequest,
  GetCashGoodListResponse,
  GetCashGoodPurchaseResultRequest,
  GetCashGoodPurchaseResultResponse,
  GetClassicGoodListRequest,
  GetClassicGoodListResponse,
  GetEPGSGoodListRequest,
  GetEPGSGoodListResponse,
  GetExtraGoodListRequest,
  GetExtraGoodListResponse,
  GetFurniGoodListRequest,
  GetFurniGoodListResponse,
  GetGoodPurchaseStateRequest,
  GetGoodPurchaseStateResponse,
  GetGPGoodListRequest,
  GetGPGoodListResponse,
  GetHighGoodListRequest,
  GetHighGoodListResponse,
  GetLMTGSGoodListRequest,
  GetLMTGSGoodListResponse,
  GetLowGoodListRequest,
  GetLowGoodListResponse,
  GetREPGoodListRequest,
  GetREPGoodListResponse,
  GetSkinGoodListRequest,
  GetSkinGoodListResponse,
  GetSocialGoodListRequest,
  GetSocialGoodListResponse,
  GetVoucherSkinGoodListRequest,
  GetVoucherSkinGoodListResponse,
  UseVoucherSkinRequest,
  UseVoucherSkinResponse,
} from "../model/protocol/shop";

const router = Router();

/**
 * 校验请求体必填字段是否缺失
 * @param body - 请求体
 * @param required - 必填字段名列表
 * @returns 缺失的字段名列表（空数组表示全部存在）
 */
function missingRequiredFields(
  body: unknown,
  required: string[],
): string[] {
  const b = (body ?? {}) as Record<string, unknown>;
  return required.filter((f) => b[f] === undefined);
}

/**
 * 分解潜能物品
 * @route POST /shop/decomposePotentialItem
 * @param req.body - 分解参数
 * @returns 分解获得的物品和玩家增量数据
 */
router.post("/decomposePotentialItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as DecomposePotentialItemRequest;
  // 缺参校验：charInstIdList 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["charInstIdList"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    items: await player.troop.decomposePotentialItem(body),
    ...player.delta,
  } satisfies DecomposePotentialItemResponse);
});

/**
 * 分解经典潜能物品
 * @route POST /shop/decomposeClassicPotentialItem
 * @param req.body - 分解参数
 * @returns 分解获得的物品和玩家增量数据
 */
router.post("/decomposeClassicPotentialItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as DecomposeClassicPotentialItemRequest;
  // 缺参校验：charInstIdList 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["charInstIdList"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    items: await player.troop.decomposeClassicPotentialItem(body),
    ...player.delta,
  } satisfies DecomposeClassicPotentialItemResponse);
});

/**
 * 获取商品购买状态
 *
 * 返回玩家在各商店的购买记录，客户端据此判断商品是否已购买、限购次数等。
 * 参考实现中此接口返回空对象，此处返回玩家 shop 状态中的所有购买记录。
 * @route POST /shop/getGoodPurchaseState
 * @returns 购买状态和玩家增量数据
 */
router.post("/getGoodPurchaseState", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetGoodPurchaseStateRequest;
  // 修复：按客户端 goodIdMap 返回扁平 {goodId: 1|-1}（1=可购买/-1=已购买/限购），
  // 对齐 CS GetGoodPurchaseStateResponse { result: Dictionary<string, int> } 与抓包形状；
  // 原实现直接返回各商店原始 info 数组（41KB 且形状不符）
  const goodIdMap = body.goodIdMap ?? {};
  const shopState = player._playerdata.shop as any;
  const result: { [goodId: string]: number } = {};
  for (const [shopType, goodIds] of Object.entries(goodIdMap)) {
    if (!Array.isArray(goodIds) || goodIds.length === 0) continue;
    const purchased = new Set<string>();
    const shopData: any = shopState?.[shopType];
    if (shopData) {
      if (Array.isArray(shopData.info)) {
        // 常规商店：{ info: [{id, count}] }
        for (const item of shopData.info) purchased.add(item.id);
      } else {
        // GP 等嵌套商店：{ subType: { info: [...] } }
        for (const sub of Object.values(shopData)) {
          if (sub && Array.isArray((sub as any).info)) {
            for (const item of (sub as any).info) purchased.add(item.id);
          }
        }
      }
    }
    for (const goodId of goodIds) {
      result[goodId] = purchased.has(goodId) ? -1 : 1;
    }
  }
  res.send({
    result,
    ...player.delta,
  } satisfies GetGoodPurchaseStateResponse);
});

/**
 * 获取低级商店商品列表
 * @route POST /shop/getLowGoodList
 * @returns 低级商店商品列表和玩家增量数据
 */
router.post("/getLowGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetLowGoodListRequest;
  res.send({
    ...excel.ShopTable.lowGoodList,
    ...player.delta,
  } satisfies GetLowGoodListResponse);
});

/**
 * 获取高级商店商品列表
 * @route POST /shop/getHighGoodList
 * @returns 高级商店商品列表和玩家增量数据
 */
router.post("/getHighGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetHighGoodListRequest;
  res.send({
    ...excel.ShopTable.highGoodList,
    ...player.delta,
  } satisfies GetHighGoodListResponse);
});

/**
 * 获取经典商店商品列表
 * @route POST /shop/getClassicGoodList
 * @returns 经典商店商品列表和玩家增量数据
 */
router.post("/getClassicGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetClassicGoodListRequest;
  res.send({
    ...excel.ShopTable.classicGoodList,
    ...player.delta,
  } satisfies GetClassicGoodListResponse);
});

/**
 * 获取联合行动商店商品列表
 * @route POST /shop/getEPGSGoodList
 * @returns 联合行动商店商品列表和玩家增量数据
 */
router.post("/getEPGSGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetEPGSGoodListRequest;
  res.send({
    ...excel.ShopTable.EPGSGoodList,
    ...player.delta,
  } satisfies GetEPGSGoodListResponse);
});

/**
 * 获取限定商店商品列表
 * @route POST /shop/getLMTGSGoodList
 * @returns 限定商店商品列表和玩家增量数据
 */
router.post("/getLMTGSGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetLMTGSGoodListRequest;
  // 自动生成 + 静态合并：新限定池无需手动补 LMTGSGoodList.json
  const auto = player.shop.buildLMTGSGoodList();
  const staticList = excel.ShopTable.LMTGSGoodList;
  const autoIds = new Set(auto.map((g) => g.goodId));
  const goodList = [
    ...auto,
    ...staticList.goodList.filter((g) => !autoIds.has(g.goodId)),
  ];
  res.send({
    goodList,
    newFlag: [],
    ...player.delta,
  } satisfies GetLMTGSGoodListResponse);
});

/**
 * 获取额外商店商品列表
 * @route POST /shop/getExtraGoodList
 * @returns 额外商店商品列表和玩家增量数据
 */
router.post("/getExtraGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetExtraGoodListRequest;
  res.send({
    ...excel.ShopTable.extraGoodList,
    ...player.delta,
  } satisfies GetExtraGoodListResponse);
});

/**
 * 获取声望商店商品列表
 * @route POST /shop/getREPGoodList
 * @returns 声望商店商品列表和玩家增量数据
 */
router.post("/getREPGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetREPGoodListRequest;
  res.send({
    ...excel.ShopTable.REPGoodList,
    ...player.delta,
  } satisfies GetREPGoodListResponse);
});

/**
 * 获取皮肤商店商品列表
 * @route POST /shop/getSkinGoodList
 * @returns 皮肤商店商品列表和玩家增量数据
 */
router.post("/getSkinGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetSkinGoodListRequest;
  res.send({
    ...excel.ShopTable.skinGoodList,
    ...player.delta,
  } satisfies GetSkinGoodListResponse);
});

/**
 * 获取现金商店商品列表
 * @route POST /shop/getCashGoodList
 * @returns 现金商店商品列表和玩家增量数据
 */
router.post("/getCashGoodList", (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetCashGoodListRequest;
  res.send({
    ...excel.ShopTable.cashGoodList,
    ...player.delta,
  } satisfies GetCashGoodListResponse);
});

/**
 * 获取信用商店商品列表
 * @route POST /shop/getGPGoodList
 * @returns 信用商店商品列表和玩家增量数据
 */
router.post("/getGPGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetGPGoodListRequest;
  res.send({
    ...excel.ShopTable.GPGoodList,
    ...player.delta,
  } satisfies GetGPGoodListResponse);
});

/**
 * 获取社交商店商品列表
 * @route POST /shop/getSocialGoodList
 * @returns 社交商店商品列表和玩家增量数据
 */
router.post("/getSocialGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetSocialGoodListRequest;
  // 信用商店：按当天日期自动生成（goodId = SOCIAL<YYYYMMDD>_...）
  res.send({
    ...player.shop.buildSocialGoodList(),
    ...player.delta,
  } satisfies GetSocialGoodListResponse);
});

/** 购买信用商店商品（信用 = status.socialPoint） */
router.post("/buySocialGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuySocialGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buySocialGood(body),
    ...player.delta,
  } satisfies BuySocialGoodResponse);
});

/**
 * 获取家具商店商品列表
 * @route POST /shop/getFurniGoodList
 * @returns 家具商店商品列表和玩家增量数据
 */
router.post("/getFurniGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetFurniGoodListRequest;
  res.send({
    ...excel.ShopTable.furniGoodList,
    ...player.delta,
  } satisfies GetFurniGoodListResponse);
});

/**
 * 购买低级商店商品
 * @route POST /shop/buyLowGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyLowGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyLowGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyLowGood(body),
    ...player.delta,
  } satisfies BuyLowGoodResponse);
});

/**
 * 购买高级商店商品
 * @route POST /shop/buyHighGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyHighGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyHighGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyHighGood(body),
    ...player.delta,
  } satisfies BuyHighGoodResponse);
});

/**
 * 购买额外商店商品
 * @route POST /shop/buyExtraGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyExtraGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyExtraGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyExtraGood(body),
    ...player.delta,
  } satisfies BuyExtraGoodResponse);
});

/**
 * 购买现金商店商品
 *
 * 现金商店以钻石为货币，购买后记录次数并支持首充翻倍。
 * @route POST /shop/buyCashGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyCashGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyCashGoodRequest;
  // 缺参校验：goodId 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyCashGood(body),
    ...player.delta,
  } satisfies BuyCashGoodResponse);
});

/**
 * 购买联合行动商店商品
 * @route POST /shop/buyEPGSGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyEPGSGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(body),
    ...player.delta,
  } satisfies BuyEPGSGoodResponse);
});

/**
 * 购买声望商店商品
 * @route POST /shop/buyREPGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyREPGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyREPGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyREPGood(body),
    ...player.delta,
  } satisfies BuyREPGoodResponse);
});
/** 购买声望商店商品（门票版；客户端路由 /shop/buyREPGoodWithTicket，复用 buyREPGood 逻辑） */
router.post("/buyREPGoodWithTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyREPGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyREPGood(body),
    ...player.delta,
  } satisfies BuyREPGoodResponse);
});

/**
 * 购买经典商店商品
 * @route POST /shop/buyClassicGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyClassicGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyClassicGoodRequest;
  // 缺参校验：goodId/count 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "count"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyClassicGood(body),
    ...player.delta,
  } satisfies BuyClassicGoodResponse);
});

/**
 * 购买限定商店商品
 * @route POST /shop/buyLMTGSGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyLMTGSGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyLMTGSGoodRequest;
  res.send({
    result: 0,
    items: await player.shop.buyLMTGSGood(body),
    ...player.delta,
  } satisfies BuyLMTGSGoodResponse);
});

/**
 * 购买家具商店商品
 * @route POST /shop/buyFurniGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
/** 购买家具组（客户端 body: {groupId, goods: [{id,count}]}——整组购买） */
router.post("/buyFurniGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyFurniGroupRequest;
  res.send({
    result: 0,
    items: await player.shop.buyFurniGroup(body),
    ...player.delta,
  } satisfies BuyFurniGoodResponse);
});

router.post("/buyFurniGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyFurniGoodRequest;
  res.send({
    result: 0,
    items: await player.shop.buyFurniGood(body),
    ...player.delta,
  } satisfies BuyFurniGoodResponse);
});

/**
 * 购买皮肤商店商品
 * @route POST /shop/buySkinGood
 * @param req.body - 购买参数
 * @returns 玩家增量数据
 */
router.post("/buySkinGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuySkinGoodRequest;
  // 缺参校验：goodId 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  await player.shop.buySkinGood(body);
  res.send({ ...player.delta } satisfies BuySkinGoodResponse);
});

/**
 * 使用凭证购买礼包商店商品
 *
 * 对应参考实现中的 buyShopGoodWithTicket，使用凭证兑换礼包。
 * goodId 格式约定为 `GP_<goodType>_<序列>`，详见 ShopController.buyGoodWithTicket。
 * @route POST /shop/buyGoodWithTicket
 * @param req.body.ticketId - 凭证ID
 * @param req.body.goodId - 商品ID
 * @returns 购买结果（含获得的物品列表）和玩家增量数据
 */
router.post("/buyGoodWithTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyGoodWithTicketRequest;
  // 缺参校验：goodId/ticketId 缺失时返回业务错误而非 500
  if (missingRequiredFields(body, ["goodId", "ticketId"]).length) {
    res.send({ result: 1, ...player.delta });
    return;
  }
  res.send({
    result: 0,
    items: await player.shop.buyGoodWithTicket(body),
    ...player.delta,
  } satisfies BuyGoodWithTicketResponse);
});

/**
 * 获取现金商品购买结果
 *
 * 用于外部支付通道回调后的查询。参考实现中为占位（返回 202）。
 * 此处返回玩家当前 shop.CASH 的购买记录。
 * @route POST /shop/getCashGoodPurchaseResult
 * @returns 购买结果和玩家增量数据
 */
router.post("/getCashGoodPurchaseResult", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetCashGoodPurchaseResultRequest;
  res.send({
    result: await player.shop.getCashGoodPurchaseResult(),
    ...player.delta,
  } satisfies GetCashGoodPurchaseResultResponse);
});

/**
 * 获取凭证皮肤商品列表
 *
 * 凭证皮肤指通过特殊凭证兑换的皮肤。参考实现中为占位（返回 202）。
 * 此处基于皮肤商店列表筛选可兑换项返回。
 * @route POST /shop/getVoucherSkinGoodList
 * @returns 凭证皮肤商品列表和玩家增量数据
 */
router.post("/getVoucherSkinGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetVoucherSkinGoodListRequest;
  res.send({
    ...player.shop.getVoucherSkinGoodList(),
    ...player.delta,
  } satisfies GetVoucherSkinGoodListResponse);
});

/**
 * 使用凭证兑换皮肤
 *
 * 参考实现中为占位（返回 202）。此处实现：发放对应皮肤并记录购买。
 * @route POST /shop/useVoucherSkin
 * @param req.body.goodId - 商品ID
 * @returns 玩家增量数据
 */
router.post("/useVoucherSkin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UseVoucherSkinRequest;
  await player.shop.useVoucherSkin(body);
  res.send({ ...player.delta } satisfies UseVoucherSkinResponse);
});

/**
 * 检查商店禁止状态
 *
 * 用于客户端校验玩家是否被限制购买。参考实现中为占位（返回 202）。
 * 此处简化实现：永远返回未禁止状态。
 * @route POST /shop/checkForbidden
 * @returns 禁止状态和玩家增量数据
 */
router.post("/checkForbidden", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as CheckForbiddenRequest;
  res.send({
    ...player.shop.checkForbidden(),
    ...player.delta,
  } satisfies CheckForbiddenResponse);
});

/**
 * 用票券购买 GP 商品（CS: ShopDetailGPState——/shop/buyGPGoodWithTicket）
 * 私服返回空增量（GP 票券购买暂不核销）
 */
router.post("/buyGPGoodWithTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as { goodsId?: string };
  res.send(player.delta);
});

export default router;
