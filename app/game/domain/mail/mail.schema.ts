/**
 * 邮件（mail）请求 zod schema
 *
 * 对应 protocol/mail.ts 中 ListMailBoxRequest / ReceiveMailRequest /
 * ReceiveAllMailRequest / RemoveAllReceivedMailRequest / GetMetaInfoListRequest
 * 等 Request 接口字段，供 router/mail.ts 经 validateBody 做运行时校验：
 * 缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */

import { z } from "zod";

/**
 * 邮件 id 三列表请求体（CS 系列委托类的公共字段：mailIdList/sysMailIdList/surveyMailIdList）
 * 协议类型虽标必填，但客户端实际按需只传其一（如仅 mailIdList），
 * 其余列表标可选以免误伤正常请求，handler 内部对缺省列表按空处理。
 */
const mailIdListsRequest = z.object({
  mailIdList: z.array(z.number()).optional(),
  sysMailIdList: z.array(z.number()).optional(),
  surveyMailIdList: z.array(z.string()).optional(),
});

/** 一键删除已读邮件请求（CS: RemoveAllRecievedMailRequest，CS 拼写 Recieved） */
export const removeAllReceivedMailSchema = mailIdListsRequest;

/** 一键领取邮件请求（CS: ReceiveAllMailRequest） */
export const receiveAllMailSchema = mailIdListsRequest;

/** 获取邮件元信息列表请求（CS: GetMetaInfoListRequest） */
export const getMetaInfoListSchema = z.object({
  from: z.number(),
});

/** 领取单封邮件请求（CS: ReceiveMailRequest；type 为服务端自定义字段） */
export const receiveMailSchema = z.object({
  mailId: z.number(),
  type: z.number(),
});

/** 获取邮件列表请求（CS: ListMailBoxRequest） */
export const listMailBoxSchema = mailIdListsRequest;