/**
 * 社交（social）请求 zod schema
 *
 * 对应 protocol/social.ts 中 DeleteFriendRequest / SendFriendRequest /
 * GetFriendListRequest 等 Request 接口字段，供 router/social.ts 经 validateBody
 * 做运行时校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（z.string/z.number/z.boolean/z.array）
 * - 服务端不读或抓包确认可省略的字段 .optional()
 * - 被 handler 读取内层字段的嵌套对象按被读字段收紧（如 param/assistCharList）。
 * - 空对象用 z.object({})
 */

import { z } from "zod";

/** 好友 id 列表请求体（CS: GetFriendListRequest / SearchPlayerRequest 等共用 idList） */
const idListRequest = z.object({
  idList: z.array(z.string()),
});

/** 删除好友请求（CS: DeleteFriendRequest；CS 字段名为 friendId，服务端契约为 id） */
export const deleteFriendSchema = z.object({
  id: z.string(),
});

/** 发送好友申请请求（CS: SendFriendRequest） */
export const sendFriendRequestSchema = z.object({
  friendId: z.string(),
  afterBattle: z.number(),
  originType: z.number(),
  battleOrigin: z.string().nullable(),
});

/** 处理好友申请请求（CS: ProcessFriendRequest；action 为 FriendDealEnum 数值） */
export const processFriendRequestSchema = z.object({
  friendId: z.string(),
  action: z.number(),
});

/** 搜索玩家请求（CS: SearchPlayerRequest） */
export const searchPlayerSchema = idListRequest;

/** 获取好友排序列表请求（CS: GetSortListInfoRequest；客户端常只传 type，其余可选） */
export const getSortListInfoSchema = z.object({
  type: z.number(),
  sortKeyList: z.array(z.string()).optional(),
  // param 为 { 字段名: 字符串值 } 字典——SocialManager#getSortListInfo 读 nickName/nickNumber
  // 组装完整昵称，故按被读字段收紧为 string→string 字典
  param: z.record(z.string(), z.string()).optional(),
});

/** 获取好友列表请求（CS: GetFriendListRequest） */
export const getFriendListSchema = idListRequest;

/** 获取好友申请列表请求（CS: GetFriendRequestListRequest） */
export const getFriendRequestListSchema = idListRequest;

/** 设置助战干员列表请求（CS: SetAssistCharListRequest） */
export const setAssistCharListSchema = z.object({
  // assistCharList 为 PlayerFriendAssist[]——handler 整段写入 social.assistCharList
  //（内层字段由展示侧读取），故按被读层级收紧到「JSON 数组」，元素结构透传
  assistCharList: z.array(z.json()),
});

/** 设置好友备注请求（CS: SetFriendAliasRequest） */
export const setFriendAliasSchema = z.object({
  friendId: z.string(),
  alias: z.string(),
});

/** 领取社交点请求（CS: ReceiveSocialPointRequest，无字段） */
export const receiveSocialPointSchema = z.object({});

/** 设置名片展示勋章请求（CS: SetCardShowMedalRequest） */
export const setCardShowMedalSchema = z.object({
  type: z.string(),
  customIndex: z.string(),
  templateGroup: z.string(),
});

/** 设置星标好友请求（CS: SetStarFriendListRequest） */
export const setStarFriendListSchema = idListRequest;