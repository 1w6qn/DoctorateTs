/**
 * 商店协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * Get\*GoodList、Buy\*Good、Decompose\*、ShopCashGoodPurchase 系列类；
 * 商品列表结构直接复用 @excel/shop 中的表格类型。
 */
import { ItemBundle } from "@excel/character_table";
import {
  CashGoodList,
  ClassicGoodList,
  EPGSGoodList,
  ExtraGoodList,
  FurniGoodList,
  GPGoodList,
  HighGoodList,
  LowGoodList,
  LMTGSGoodList,
  REPGoodList,
  SkinGoodList,
  SocialGoodList,
  SocialShopData,
} from "@excel/shop";
import { PlayerDeltaResponse } from "./common";

/* ===== 请求类型 ===== */

/** 分解潜能物品请求（CS: DecomposePotentialItemRequest） */
export interface DecomposePotentialItemRequest {
  charInstIdList: string[];
}

/** 分解经典潜能物品请求（CS: DecomposeClassicPotentialItemRequest） */
export interface DecomposeClassicPotentialItemRequest {
  charInstIdList: string[];
}

/**
 * 获取商品购买状态请求（CS: GetGoodPurchaseStateRequest { goodIdMap: ShopPurchaseState }）
 * goodIdMap：商店类型（LS/HS/ES/CASH/GP/SOCIAL/CLASSIC）→ 待查询 goodId 列表
 */
export interface GetGoodPurchaseStateRequest {
  goodIdMap?: { [shopType: string]: string[] };
}

/** 获取低级商店商品列表请求（CS: GetLowGoodListRequest，无字段） */
export interface GetLowGoodListRequest {}

/** 获取高级商店商品列表请求（CS: GetHighGoodListRequest，无字段） */
export interface GetHighGoodListRequest {}

/** 获取经典商店商品列表请求（CS: GetClassicGoodListRequest，无字段） */
export interface GetClassicGoodListRequest {}

/** 获取联合行动商店商品列表请求（CS: GetEPGSGoodListRequest，无字段） */
export interface GetEPGSGoodListRequest {}

/** 获取限定商店商品列表请求（CS: GetLMTGSGoodListRequest，无字段） */
export interface GetLMTGSGoodListRequest {}

/** 获取额外商店商品列表请求（CS: GetExtraGoodListRequest，无字段） */
export interface GetExtraGoodListRequest {}

/** 获取声望商店商品列表请求（CS: GetREPGoodListRequest，无字段） */
export interface GetREPGoodListRequest {}

/** 获取皮肤商店商品列表请求（CS: GetSkinGoodListRequest，无字段） */
export interface GetSkinGoodListRequest {}

/** 获取现金商店商品列表请求（CS: GetCashGoodListRequest，无字段） */
export interface GetCashGoodListRequest {}

/** 获取信用商店商品列表请求（CS: GetGPGoodListRequest，无字段） */
export interface GetGPGoodListRequest {}

/** 获取社交商店商品列表请求（CS: GetSocialGoodListRequest，无字段） */
export interface GetSocialGoodListRequest {}

/** 获取家具商店商品列表请求（CS: BuildingGetFurnitureGoodListRequest，无字段） */
export interface GetFurniGoodListRequest {}

/** 购买低级商店商品请求（CS: BuyLowGoodRequest） */
export interface BuyLowGoodRequest {
  goodId: string;
  count: number;
}

/** 购买高级商店商品请求（CS: BuyHighGoodRequest） */
export interface BuyHighGoodRequest {
  goodId: string;
  count: number;
}

/** 购买额外商店商品请求（CS: BuyExtraGoodRequest） */
export interface BuyExtraGoodRequest {
  goodId: string;
  count: number;
}

/** 购买现金商店商品请求（CS: BuyCashGoodRequest） */
export interface BuyCashGoodRequest {
  goodId: string;
}

/** 购买联合行动商店商品请求（CS: BuyEPGSGoodRequest） */
export interface BuyEPGSGoodRequest {
  goodId: string;
  count: number;
}

/** 购买声望商店商品请求（CS: BuyREPGoodRequest） */
export interface BuyREPGoodRequest {
  goodId: string;
  count: number;
}

/** 购买经典商店商品请求（CS: BuyClassicGoodRequest） */
export interface BuyClassicGoodRequest {
  goodId: string;
  count: number;
}

/** 购买限定商店商品请求（CS: BuyLMTGSGoodRequest） */
export interface BuyLMTGSGoodRequest {
  goodId: string;
  count: number;
}

/** 购买家具商店商品请求（CS: BuildingBuyFurnitureGoodRequest；服务端额外读取 costType） */
export interface BuyFurniGoodRequest {
  goodId: string;
  buyCount: number;
  costType: string;
}

/** 购买家具组请求（客户端整组购买：{ groupId, goods: [{id, count}] }） */
export interface BuyFurniGroupRequest {
  groupId?: string;
  goods?: { id: string; count: number }[];
}

/** 购买皮肤商店商品请求（CS: BuySkinGoodRequest；服务端仅读取 goodId） */
export interface BuySkinGoodRequest {
  goodId: string;
  isSpecial: number;
  enterTs: number;
}

/** 使用凭证购买礼包请求（CS: BuyGpGoodWithTicketRequest） */
export interface BuyGoodWithTicketRequest {
  goodId: string;
  ticketId: string;
}

/** 获取现金商品购买结果请求（CS: ShopCashGoodPurchaseRequest，无字段） */
export interface GetCashGoodPurchaseResultRequest {}

/** 获取凭证皮肤商品列表请求（服务端自定义，无 CS 对应类） */
export interface GetVoucherSkinGoodListRequest {}

/** 使用凭证兑换皮肤请求（服务端自定义，无 CS 对应类） */
export interface UseVoucherSkinRequest {
  goodId: string;
}

/** 检查商店禁止状态请求（服务端自定义，无 CS 对应类） */
export interface CheckForbiddenRequest {}

/* ===== 响应类型 ===== */

/** 分解潜能物品响应（CS: DecomposePotentialItemResponse） */
export interface DecomposePotentialItemResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 分解经典潜能物品响应（CS: DecomposeClassicPotentialItemResponse） */
export interface DecomposeClassicPotentialItemResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/**
 * 获取商品购买状态响应（CS: GetGoodPurchaseStateResponse { result: Dictionary<string, int> }）
 * result：goodId → 1（可购买）/ -1（已购买/限购）
 */
export interface GetGoodPurchaseStateResponse extends PlayerDeltaResponse {
  result: { [goodId: string]: number };
}

/** 获取低级商店商品列表响应（CS: GetLowGoodListResponse） */
export type GetLowGoodListResponse = LowGoodList & PlayerDeltaResponse;

/** 获取高级商店商品列表响应（CS: GetHighGoodListResponse） */
export type GetHighGoodListResponse = HighGoodList & PlayerDeltaResponse;

/** 获取经典商店商品列表响应（CS: GetClassicGoodListResponse） */
export type GetClassicGoodListResponse = ClassicGoodList & PlayerDeltaResponse;

/** 获取联合行动商店商品列表响应（CS: GetEPGSGoodListResponse） */
export type GetEPGSGoodListResponse = EPGSGoodList & PlayerDeltaResponse;

/** 获取限定商店商品列表响应（CS: GetLMTGSGoodListResponse） */
export type GetLMTGSGoodListResponse = LMTGSGoodList & PlayerDeltaResponse;

/** 获取额外商店商品列表响应（CS: GetExtraGoodListResponse） */
export type GetExtraGoodListResponse = ExtraGoodList & PlayerDeltaResponse;

/** 获取声望商店商品列表响应（CS: GetREPGoodListResponse） */
export type GetREPGoodListResponse = REPGoodList & PlayerDeltaResponse;

/** 获取皮肤商店商品列表响应（CS: GetSkinGoodListResponse） */
export type GetSkinGoodListResponse = SkinGoodList & PlayerDeltaResponse;

/** 获取现金商店商品列表响应（CS: GetCashGoodListResponse） */
export type GetCashGoodListResponse = CashGoodList & PlayerDeltaResponse;

/** 获取信用商店商品列表响应（CS: GetGPGoodListResponse） */
export type GetGPGoodListResponse = GPGoodList & PlayerDeltaResponse;

/**
 * 获取社交商店商品列表响应（CS: GetSocialGoodListResponse）
 * 服务端补全 costSocialPoint（累计信用消费）/ creditGroup（干员解锁组）——
 * 客户端点击干员进度依赖此二字段，缺失导致干员解锁弹窗卡死
 */
export interface GetSocialGoodListResponse extends PlayerDeltaResponse {
  goodList: SocialShopData[];
  charPurchase: { [key: string]: number };
  costSocialPoint: number;
  creditGroup: string;
}

/** 购买信用商店商品请求（CS: BuySocialGoodRequest；goodId + count） */
export interface BuySocialGoodRequest {
  goodId: string;
  count: number;
}

/** 购买信用商店商品响应（CS: BuySocialGoodResponse { items }） */
export interface BuySocialGoodResponse extends PlayerDeltaResponse {
  result: number;
  items: ItemBundle[];
}

/** 获取家具商店商品列表响应（CS: BuildingGetFurnitureGoodListResponse） */
export type GetFurniGoodListResponse = FurniGoodList & PlayerDeltaResponse;

/** 购买低级商店商品响应（CS: BuyLowGoodResponse；服务端额外返回 result） */
export interface BuyLowGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买高级商店商品响应（CS: BuyHighGoodResponse；服务端额外返回 result） */
export interface BuyHighGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买额外商店商品响应（CS: BuyExtraGoodResponse；服务端额外返回 result） */
export interface BuyExtraGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买现金商店商品响应（CS: BuyCashGoodResponse；服务端额外返回 result） */
export interface BuyCashGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买联合行动商店商品响应（CS: BuyEPGSGoodResponse；服务端额外返回 result） */
export interface BuyEPGSGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买声望商店商品响应（CS: BuyREPGoodResponse；服务端额外返回 result） */
export interface BuyREPGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买经典商店商品响应（CS: BuyClassicGoodResponse；服务端额外返回 result） */
export interface BuyClassicGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买限定商店商品响应（CS: BuyLMTGSGoodResponse；服务端额外返回 result） */
export interface BuyLMTGSGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买家具商店商品响应（CS: BuildingBuyFurnitureGoodResponse；服务端额外返回 result） */
export interface BuyFurniGoodResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 购买皮肤商店商品响应（CS: BuySkinGoodRepsonse，CS 拼写 Repsonse；仅增量；服务端额外返回 result） */
export interface BuySkinGoodResponse extends PlayerDeltaResponse {
  result?: number;
}

/** 使用凭证购买礼包响应（CS: BuyGpGoodWithTicketResponse；服务端额外返回 result） */
export interface BuyGoodWithTicketResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
  result?: number;
}

/** 获取现金商品购买结果响应（CS: ShopCashGoodPurchaseResponse；服务端返回购买记录） */
export interface GetCashGoodPurchaseResultResponse extends PlayerDeltaResponse {
  result: unknown;
}

/** 获取凭证皮肤商品列表响应（服务端自定义） */
export interface GetVoucherSkinGoodListResponse extends PlayerDeltaResponse {
  goodList: unknown[];
}

/** 使用凭证兑换皮肤响应（服务端自定义；仅增量；服务端额外返回 result） */
export interface UseVoucherSkinResponse extends PlayerDeltaResponse {
  result?: number;
}

/** 检查商店禁止状态响应（服务端自定义） */
export interface CheckForbiddenResponse extends PlayerDeltaResponse {
  forbidden: boolean;
  reason: string;
}
