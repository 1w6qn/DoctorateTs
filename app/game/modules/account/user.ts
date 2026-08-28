/**
 * 用户/账号信息协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * ChangeSecretary/ChangeAvatar/ChangeResume/UseRenameCard/UseItem/BuyAp/
 * ExchangeDiamondShard/ReceiveTeamCollectionReward/MedalSetCustomData/
 * UI.Birthday.BirthdaySetting 等类；gallery/cg/mainlineClue 等为服务端自定义接口。
 */
import { ItemBundle } from "@excel/excel";
import { AvatarInfo } from "../../kernel/model";
import { PlayerMedalCustomLayout } from "../../kernel/playerdata";
import { PlayerDeltaResponse } from "../../kernel/http/common";

/* ===== 请求类型 ===== */

/** 更换秘书干员请求（CS: ChangeSecretaryRequest） */
export interface ChangeSecretaryRequest {
  charInstId: number;
  skinId: string;
}

/**
 * 更换头像请求
 * CS: ChangeAvatarRequest { id }；服务端契约读取整个 avatar 对象，以服务端为准
 */
export interface ChangeAvatarRequest {
  avatar: AvatarInfo;
}

/** 更换简介请求（CS: ChangeResumeRequest） */
export interface ChangeResumeRequest {
  resume: string;
}

/** 绑定昵称请求（服务端自定义，无 CS 对应类；服务端管理器读取 nickname，路由按 nickName 透传） */
export interface BindNickNameRequest {
  nickName: string;
}

/** 使用改名卡请求（CS: UseRenameCardRequest） */
export interface UseRenameCardRequest {
  itemId: string;
  instId: number;
  nickName: string;
}

/** 领取团队收集奖励请求（CS: ReceiveTeamCollectionRewardRequest） */
export interface ReceiveTeamCollectionRewardRequest {
  rewardId: string;
}

/** 购买理智请求（CS: BuyApRequest，无字段） */
export interface BuyApRequest {}

/** 兑换源石碎片请求（CS: ExchangeDiamondShardRequest） */
export interface ExchangeDiamondShardRequest {
  count: number;
}

/** 使用单个物品请求（CS: UseItemRequest 字段名为 cnt；服务端兼容 count） */
export interface UseItemRequest {
  instId: number;
  itemId: string;
  /** CS 字段名（客户端实际发送） */
  cnt?: number;
  /** 兼容旧服务端命名 */
  count?: number;
}

/** 使用多个物品请求（CS: UseItemsRequest） */
export interface UseItemsRequest {
  items: UseItemsRequest.Item[];
}
export namespace UseItemsRequest {
  export interface Item {
    instId: number;
    itemId: string;
    cnt: number;
  }
}

/** 签到请求（CS 无独立类，对应 ServiceCode CHECKIN_HOME；服务端不读取） */
export interface CheckInHomeRequest {}

/** 绑定生日请求（CS: UI.Birthday.BirthdaySettingRequest） */
export interface BindBirthdayRequest {
  month: number;
  day: number;
}

/** 领取勋章奖励请求（服务端自定义，无 CS 对应类） */
export interface RewardMedalRequest {
  medalId: string;
  group: string;
}

/** 解锁主线线索请求（服务端自定义，无 CS 对应类） */
export interface UnlockClueRequest {
  id: string;
}

/** 获取 CG 收藏列表请求（服务端自定义，无 CS 对应类） */
export interface GetCgCollectionRequest {}

/** 添加 CG 收藏请求（服务端自定义，无 CS 对应类） */
export interface AddCgCollectionRequest {
  cgId: string;
}

/** 移除 CG 收藏请求（服务端自定义，无 CS 对应类） */
export interface RemoveCgCollectionRequest {
  cgId: string;
}

/** 获取画廊首通奖励请求（服务端自定义，无 CS 对应类） */
export interface GetFirstRewardsRequest {}

/** 获取画廊收集奖励请求（CS: ArtMagazineGetCollectionRewardsRequest { setId, missionId }） */
export interface GetCollectionRewardsRequest {
  setId?: string;
  missionId?: string;
}

/** 获取杂志缩略图 URL 请求（服务端自定义，无 CS 对应类） */
export interface GetThumbnailUrlRequest {
  idList: string[];
}

/** 修改杂志编队请求（服务端自定义，无 CS 对应类） */
export interface ChangeMagazineSquadRequest {}

/** 保存自定义杂志请求（V1/V2；服务端自定义，无 CS 对应类） */
export interface SaveDiyMagazineRequest {
  magazine: SaveDiyMagazineRequest.Magazine;
  /** 客户端生成的杂志缩略图（base64 字符串），用于展示环节回传；可选 */
  thumbnail?: string;
}
export namespace SaveDiyMagazineRequest {
  export interface Magazine {
    leafId: string;
    charSkin: unknown | null;
    decorList: unknown[];
  }
}

/** 设置勋章自定义数据请求（CS: MedalSetCustomDataRequest；服务端读取 data） */
export interface MedalSetCustomDataRequest {
  index?: string;
  data: PlayerMedalCustomLayout;
}

/* ===== 响应类型 ===== */

/** 更换秘书干员响应（CS: ChangeSecretaryResponse） */
export type ChangeSecretaryResponse = PlayerDeltaResponse;

/** 更换头像响应（CS: ChangeAvatarResponse） */
export type ChangeAvatarResponse = PlayerDeltaResponse;

/** 更换简介响应（CS: ChangeResumeResponse : ExaminResponse） */
export type ChangeResumeResponse = PlayerDeltaResponse;

/** 绑定昵称响应（服务端自定义；失败时仅返回 result） */
export interface BindNickNameResponse {
  result?: number;
  playerDataDelta?: PlayerDeltaResponse["playerDataDelta"];
}

/** 使用改名卡响应（CS: UseRenameCardResponse : ExaminResponse） */
export type UseRenameCardResponse = PlayerDeltaResponse;

/** 领取团队收集奖励响应（CS: ReceiveTeamCollectionRewardResponse；服务端仅返回增量） */
export type ReceiveTeamCollectionRewardResponse = PlayerDeltaResponse;

/** 购买理智响应（CS: BuyApResponse；服务端省略 result） */
export interface BuyApResponse extends PlayerDeltaResponse {
  result?: number;
}

/** 兑换源石碎片响应（服务端自定义；失败时仅返回 result + errMsg） */
export interface ExchangeDiamondShardResponse {
  result?: number;
  errMsg?: string;
  playerDataDelta?: PlayerDeltaResponse["playerDataDelta"];
}

/** 使用单个物品响应（CS: UseItemResponse；服务端仅返回增量） */
export type UseItemResponse = PlayerDeltaResponse;

/** 使用多个物品响应（服务端仅返回增量） */
export type UseItemsResponse = PlayerDeltaResponse;

/** 签到响应（服务端返回 signInRewards + subscriptionRewards + 增量） */
export interface CheckInHomeResponse extends PlayerDeltaResponse {
  signInRewards: ItemBundle[];
  subscriptionRewards: ItemBundle[];
}

/** 绑定生日响应（CS: UI.Birthday.BirthdaySettingResponse） */
export type BindBirthdayResponse = PlayerDeltaResponse;

/** 领取勋章奖励响应（服务端自定义） */
export interface RewardMedalResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 解锁主线线索响应（服务端自定义） */
export type UnlockClueResponse = PlayerDeltaResponse;

/** 获取 CG 收藏列表响应（服务端自定义） */
export interface GetCgCollectionResponse extends PlayerDeltaResponse {
  cgList: string[];
}

/** 添加/移除 CG 收藏响应（服务端自定义） */
export type AddCgCollectionResponse = GetCgCollectionResponse;
export type RemoveCgCollectionResponse = GetCgCollectionResponse;

/** 获取画廊首通奖励响应（服务端自定义） */
export type GetFirstRewardsResponse = PlayerDeltaResponse;

/** 获取画廊收集奖励响应（CS: ArtMagazineGetCollectionRewardsResponse { rewards }） */
export interface GetCollectionRewardsResponse extends PlayerDeltaResponse {
  rewards: ItemBundle[];
}

/** 获取杂志缩略图 URL 响应（服务端自定义） */
export interface GetThumbnailUrlResponse extends PlayerDeltaResponse {
  url: Array<string | null>;
}

/** 修改杂志编队响应（服务端自定义） */
export type ChangeMagazineSquadResponse = PlayerDeltaResponse;

/** 保存自定义杂志响应（V1/V2；服务端自定义） */
export type SaveDiyMagazineResponse = PlayerDeltaResponse;

/** 设置勋章自定义数据响应（CS: MedalSetCustomDataResponse） */
export type MedalSetCustomDataResponse = PlayerDeltaResponse;

/** 服务器时间响应（SDK/门户类接口，status/msg/data 包裹） */
export interface ServerTimeResponse {
  status: number;
  msg: string;
  data: {
    serverTime: number;
    isHoliday: boolean;
  };
}
