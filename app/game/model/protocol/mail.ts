/**
 * 邮件协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * ListMailBox/ReceiveMail/ReceiveAllMail/RemoveAllRecievedMail/GetMetaInfoList 系列类。
 */
import { MailItem, MailMetaInfo, SurveyItem } from "../mail";
import { PlayerDeltaResponse } from "./common";

/** 获取邮件列表请求（CS: ListMailBoxRequest : ListMailBoxCommonRequest） */
export interface ListMailBoxRequest {
  mailIdList: number[];
  sysMailIdList: number[];
  surveyMailIdList: string[];
}

/** 获取邮件列表响应（CS: ListMailBoxResponse；服务端不返回 surveyMailList） */
export interface ListMailBoxResponse extends PlayerDeltaResponse {
  mailList: MailItem[];
  surveyMailList?: SurveyItem[];
}

/** 领取单封邮件请求（CS: ReceiveMailRequest : ReceiveCommonMailRequest；服务端额外读取 type） */
export interface ReceiveMailRequest {
  mailId: number;
  /** 服务端自定义字段（用于区分邮件类型） */
  type: number;
}

/** 领取邮件奖励（CS: MailGet） */
export interface MailGet {
  id: string;
  count: number;
}

/** 领取单封邮件响应（CS: ReceiveMailResponse） */
export interface ReceiveMailResponse extends PlayerDeltaResponse {
  result: number;
  items: MailGet[];
}

/** 邮件元信息列表请求（CS: GetMetaInfoListRequest） */
export interface GetMetaInfoListRequest {
  from: number;
}

/** 邮件元信息列表响应（CS: GetMetaInfoListResponse；服务端附带增量数据） */
export interface GetMetaInfoListResponse extends PlayerDeltaResponse {
  result: MailMetaInfo[];
}

/** 一键领取邮件请求（CS: ReceiveAllMailRequest : ReceiveAllCommonMailRequest） */
export interface ReceiveAllMailRequest {
  mailIdList: number[];
  sysMailIdList: number[];
  surveyMailIdList: string[];
}

/** 一键领取邮件响应（CS: ReceiveAllMailResponse） */
export interface ReceiveAllMailResponse extends PlayerDeltaResponse {
  items: MailGet[];
}

/** 一键删除已读邮件请求（CS: RemoveAllRecievedMailRequest，CS 拼写 Recieved） */
export interface RemoveAllReceivedMailRequest {
  mailIdList: number[];
  sysMailIdList: number[];
  surveyMailIdList: string[];
}

/** 一键删除已读邮件响应（CS: RemoveAllRecievedMailResponse） */
export type RemoveAllReceivedMailResponse = PlayerDeltaResponse;
