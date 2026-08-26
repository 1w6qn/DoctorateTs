/**
 * 模板商店（TemplateShop）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.UI.TemplateShop.TemplateGetGoodListRequest / TemplateBuyGoodRequest 等
 * Request/Response 类；服务端当前为 stub 实现（商品列表返回空 data、购买回显请求体），
 * 响应字段以服务端输出为准。
 */
import { PlayerDeltaResponse } from "../contracts/common";

/** 获取模板商店商品列表请求（CS: UI.TemplateShop.TemplateGetGoodListRequest） */
export interface TemplateGetGoodListRequest {
  shopId: string;
}

/**
 * 获取模板商店商品列表响应
 * CS: UI.TemplateShop.TemplateGetGoodListResponse { data: TemplateShopData, nextSyncTime }，
 * CS 响应不继承 PlayerDeltaResponse，服务端额外返回增量；
 * 服务端固定返回空 data，此处以服务端输出为准
 */
export interface TemplateGetGoodListResponse extends PlayerDeltaResponse {
  data: Record<string, unknown>;
  nextSyncTime: number;
}

/** 购买模板商店商品请求（CS: UI.TemplateShop.TemplateBuyGoodRequest） */
export interface TemplateBuyGoodRequest {
  shopId: string;
  goodId: string;
  count: number;
}

/**
 * 购买模板商店商品响应
 * CS: UI.TemplateShop.TemplateBuyGoodResponse : PlayerDeltaResponse { itemList: List<RewardItemModel> }，
 * 服务端为 stub 实现（原样回显请求体），未返回 itemList/playerDataDelta，协议字段标为可选；
 * 服务端额外返回 result（0 成功 / 1 业务错误：缺参、未知商品、限购、货币不足）
 */
export interface TemplateBuyGoodResponse extends PlayerDeltaResponse {
  itemList?: unknown[];
  result?: number;
}

/** 模板商店数据（CS: UI.TemplateShop.TemplateShopData；供参考，服务端暂未返回完整结构） */
export interface TemplateShopData {
  shopId: string;
  shopName: string;
  /** CS: TShopType 枚举（NORMAL/SHOP_RARITY_GROUP/SHOP_PERIOD_UNLOCK） */
  type: string;
  price: { id: string; count: number; type: string };
  shopGroup: { [key: string]: unknown };
  iconColorCodes: string;
  buttonColorCodes: string;
  startTime: number;
  endTime: number;
  groupExtraData: { inTimeText: string; allEndText: string };
}
