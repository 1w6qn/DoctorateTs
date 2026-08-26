/**
 * 账号/登录（account）请求 zod schema
 *
 * 对应 protocol/account.ts 的 Request 类型（参考 CS 2.7.61 协议类）。
 * 供 router/account.ts 经 validateBody 做运行时校验：缺失必填字段 /
 * 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */
import { z } from "zod";

/**
 * 登录请求（CS: Torappu.LoginRequest）
 * 服务端仅读取 token；其余 CS 字段客户端会发送但服务端不读取，标为可选
 */
export const loginSchema = z.object({
  token: z.string(),
  uid: z.string().optional(),
  assetsVersion: z.string().optional(),
  clientVersion: z.string().optional(),
  deviceId: z.string().optional(),
  deviceId2: z.string().optional(),
  deviceId3: z.string().optional(),
  networkVersion: z.string().optional(),
  udtVersion: z.string().optional(),
});

/** 全量数据同步请求（CS: Torappu.SyncDataRequest { platform }）；服务端不读取，标为可选 */
export const syncDataSchema = z.object({
  platform: z.number().optional(),
});

/** 状态同步请求（对应 ServiceCode SYNC_STATUS，空请求体） */
export const syncStatusSchema = z.object({});

/** 推送消息同步请求（对应 ServiceCode SYNC_PUSH_MSG，空请求体） */
export const syncPushMessageSchema = z.object({});