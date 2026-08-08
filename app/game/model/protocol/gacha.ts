/**
 * 抽卡/招募协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * CancelNormalGachaRequest 等 Request/Response 类；字段以 CS 类为准，
 * 服务端未返回的协议字段（如部分 result/items）标为可选。
 */
import { ItemBundle } from "@excel/character_table";
import { GachaDetailData } from "@excel/gacha_detail_table";
import { GachaResult, GachaType } from "../gacha";
import { PlayerDeltaResponse } from "./common";

/** 同步普通招募状态请求（CS: SyncNormalGachaRequest，无字段） */
export interface SyncNormalGachaRequest {}

/** 同步普通招募状态响应（CS: SyncNormalGachaResponse） */
export type SyncNormalGachaResponse = PlayerDeltaResponse;

/** 完成普通招募请求（CS: FinishNormalGachaRequest） */
export interface FinishNormalGachaRequest {
  slotId: number;
}

/** 完成普通招募响应（CS: FinishNormalGachaResponse；服务端省略 result） */
export interface FinishNormalGachaResponse extends PlayerDeltaResponse {
  result?: number;
  charGet: GachaResult;
}

/** 执行普通招募请求（CS: NormalGachaRequest） */
export interface NormalGachaRequest {
  slotId: number;
  tagList: number[];
  specialTagId: number;
  duration: number;
}

/** 执行普通招募响应（CS: NormalGachaResponse，无额外字段） */
export type NormalGachaResponse = PlayerDeltaResponse;

/** 加速普通招募请求（CS: BoostNormalGachaRequest） */
export interface BoostNormalGachaRequest {
  slotId: number;
  buy: number;
}

/** 加速普通招募响应（CS: BoostNormalGachaResponse） */
export interface BoostNormalGachaResponse extends PlayerDeltaResponse {
  result: number;
}

/** 取消普通招募请求（CS: CancelNormalGachaRequest） */
export interface CancelNormalGachaRequest {
  slotId: number;
}

/** 取消普通招募响应（CS: CancelNormalGachaResponse；服务端省略 result） */
export interface CancelNormalGachaResponse extends PlayerDeltaResponse {
  result?: number;
}

/** 购买招募槽位请求（CS: BuyRecruitSlotRequest） */
export interface BuyRecruitSlotRequest {
  slotId: number;
}

/** 购买招募槽位响应（CS: BuyRecruitSlotResponse） */
export type BuyRecruitSlotResponse = PlayerDeltaResponse;

/** 刷新招募标签请求（CS: RefreshTagsGachaRequest） */
export interface RefreshTagsGachaRequest {
  slotId: number;
}

/** 刷新招募标签响应（CS: RefreshTagsGachaResponse） */
export type RefreshTagsGachaResponse = PlayerDeltaResponse;

/**
 * 获取卡池详情请求（CS: GetDetailGachaRequest）
 * gachaObjGroupType 对应 CS GachaDetailData.GachaObjGroupType（枚举数值）
 */
export interface GetDetailGachaRequest {
  poolId: string;
  gachaObjGroupType?: number;
}

/** 获取卡池详情响应（CS: GetDetailGachaResponse；服务端省略 hasRateUp） */
export interface GetDetailGachaResponse extends PlayerDeltaResponse {
  detailInfo: GachaDetailData;
  gachaObjGroupType: number;
  hasRateUp?: boolean;
}

/** 高级抽卡（单抽）请求（CS: AdvancedGachaRequest） */
export interface AdvancedGachaRequest {
  poolId: string;
  useTkt: GachaType;
  itemId: string | null;
}

/** 高级抽卡（单抽）响应（CS: AdvancedGachaResponse） */
export interface AdvancedGachaResponse extends PlayerDeltaResponse {
  result: number;
  charGet: GachaResult;
}

/** 十连抽合并道具（CS: CombineGachaItem） */
export interface CombineGachaItem {
  id: string;
  count: number;
}

/** 高级抽卡（十连）请求（CS: TenAdvancedGachaRequest） */
export interface TenAdvancedGachaRequest {
  poolId: string;
  useTkt: GachaType;
  itemList: CombineGachaItem[];
}

/** 高级抽卡（十连）响应（CS: TenAdvancedGachaResponse） */
export interface TenAdvancedGachaResponse extends PlayerDeltaResponse {
  result: number;
  gachaResultList: GachaResult[];
}

/** 选择 UP 角色请求（CS: ChoosePoolUpRequest） */
export interface ChoosePoolUpRequest {
  poolId: string;
  /** 稀有度 → 候选干员列表（CS: Dictionary<Int32, List<String>>） */
  chooseChar: { [key: string]: string[] };
}

/** 选择 UP 角色响应（CS: ChoosePoolUpResponse） */
export interface ChoosePoolUpResponse extends PlayerDeltaResponse {
  result: number;
}

/** 获取免费干员请求（CS: GetFreeCharRequest） */
export interface GetFreeCharRequest {
  poolId: string;
}

/**
 * 获取免费干员响应（CS: GetFreeCharResponse）
 * 服务端不返回 items（私服实现为空操作），协议字段标为可选
 */
export interface GetFreeCharResponse extends PlayerDeltaResponse {
  result: number;
  items?: ItemBundle[];
}
