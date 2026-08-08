/**
 * 首页（home）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * SetHomeThemeRequest / SetHomeBackgroundRequest / SetLowPowerRequest /
 * FinishStoryRequest / UI.Firework.FireworkChangeAnimalRequest /
 * UI.TemplateTrap.SetTemplateTrapRequest 等 Request/Response 类；
 * 字段以 CS 类为准，服务端未返回的协议字段标为可选。
 * 部分接口（事件上报/战车确认/特殊干员置顶等）无 CS 类对应，标注为服务端自定义。
 */
import { ItemBundle } from "@excel/character_table";
import { Cart } from "../playerdata";
import { PlayerDeltaResponse } from "./common";

/* ===== 主题与背景 ===== */

/** 更换首页主题请求（CS: SetHomeThemeRequest） */
export interface SetHomeThemeRequest {
  themeId: string;
}

/** 更换首页主题响应（CS: SetHomeThemeResponse） */
export type SetHomeThemeResponse = PlayerDeltaResponse;

/** 设置首页背景请求（CS: SetHomeBackgroundRequest） */
export interface SetBackgroundRequest {
  bgID: string;
}

/** 设置首页背景响应（CS: SetHomeBackgroundResponse） */
export type SetBackgroundResponse = PlayerDeltaResponse;

/* ===== 干员标记 ===== */

/**
 * 修改干员星级标记请求（CS: ChangeStarMarkCharRequest）
 * CS 的 chrIdDict 为 ListDict<String,Int32>，映射为 { [key: string]: number }
 */
export interface ChangeMarkStarRequest {
  chrIdDict: { [key: string]: number };
}

/** 修改干员星级标记响应（CS: ChangeStarMarkCharResponse） */
export type ChangeMarkStarResponse = PlayerDeltaResponse;

/* ===== 设置 ===== */

/** 设置低电量模式请求（CS: SetLowPowerRequest） */
export interface SetLowPowerRequest {
  newValue: number;
}

/** 设置低电量模式响应（CS: SetLowPowerResponse） */
export type SetLowPowerResponse = PlayerDeltaResponse;

/**
 * 切换 NPC 语音请求（CS: ChangeRogueNpcVoiceLanRequest）
 * CS 的 voiceLan 为 VoiceLangType 枚举，服务端以字符串读取
 */
export interface NpcAudioChangeLanRequest {
  id: string;
  voiceLan: string;
}

/** 切换 NPC 语音响应（CS: ChangeRogueNpcVoiceLanResponse） */
export type NpcAudioChangeLanResponse = PlayerDeltaResponse;

/* ===== 剧情 ===== */

/** 完成剧情请求（CS: FinishStoryRequest） */
export interface FinishStoryRequest {
  storyId: string;
}

/** 完成剧情响应（CS: FinishStoryResponse；服务端返回空 items） */
export interface FinishStoryResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/* ===== 事件上报 ===== */

/** 客户端事件批量上报请求（服务端自定义；统计/BI 类接口，请求体无业务字段） */
export interface BatchEventRequest {}

/** 客户端事件批量上报响应（服务端自定义；返回空对象） */
export interface BatchEventResponse {}

/* ===== 信物与烟火 ===== */

/** 设置信物小队请求（CS: Activity.Act12side.UI.CharmSetSquadRequest） */
export interface CharmSetSquadRequest {
  squad: string[];
}

/** 设置信物小队响应（CS: Activity.Act12side.UI.CharmSetSquadResponse） */
export type CharmSetSquadResponse = PlayerDeltaResponse;

/** 烟花棋盘槽位（CS: FireworkData.PlateSlotData） */
export interface PlateSlotData {
  id: string;
  idx: number;
}

/**
 * 保存烟花棋盘槽位请求（CS: UI.Firework.FireworkSavePlateSlotRequest）
 * CS 另有 groupId 字段，服务端未读取
 */
export interface FireworkSavePlateSlotsRequest {
  groupId?: string;
  slots: PlateSlotData[];
}

/** 保存烟花棋盘槽位响应（CS: UI.Firework.FireworkSavePlateSlotResponse） */
export type FireworkSavePlateSlotsResponse = PlayerDeltaResponse;

/**
 * 更换烟花动物请求（CS: UI.Firework.FireworkChangeAnimalRequest）
 * CS 另有 groupId 字段，服务端未读取
 */
export interface FireworkChangeAnimalRequest {
  animal: string;
  groupId?: string;
}

/** 更换烟花动物响应（CS: UI.Firework.FireworkChangeAnimalResponse） */
export interface FireworkChangeAnimalResponse extends PlayerDeltaResponse {
  animal: string;
}

/* ===== 战车与陷阱队 ===== */

/** 确认出战战车请求（服务端自定义，无 CS 对应类；car 结构见 PlayerCartInfo.battleCar） */
export interface ConfirmBattleCarRequest {
  car: Cart;
}

/** 确认出战战车响应（服务端自定义；仅增量） */
export type ConfirmBattleCarResponse = PlayerDeltaResponse;

/**
 * 设置陷阱队请求（CS: UI.TemplateTrap.SetTemplateTrapRequest）
 * CS 的 trapSquad 为 String[]，服务端原样写回
 */
export interface SetTrapSquadRequest {
  trapDomainId: string;
  trapSquad: string[];
}

/** 设置陷阱队响应（CS: UI.TemplateTrap.SetTemplateTrapResponse） */
export interface SetTrapSquadResponse extends PlayerDeltaResponse {
  trapDomainId: string;
  trapSquad: string[];
}

/** 特殊干员置顶请求（服务端自定义，无 CS 对应类） */
export interface PinSpecialOperatorRequest {
  instId: number;
}

/** 特殊干员置顶响应（服务端自定义；仅增量） */
export type PinSpecialOperatorResponse = PlayerDeltaResponse;
