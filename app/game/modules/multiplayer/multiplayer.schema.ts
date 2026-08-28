/**
 * 联机V3（多人合作）与邀请请求 zod schema
 *
 * 对应 protocol/multiplayer.ts 的 Request 类型（均为空接口，服务端 handler
 * 全为占位实现、不读取 body），故所有端点统一使用空对象 schema。
 */
import { z } from "zod";

/** 联机V3/邀请统一空请求体（handler 全为占位，不读取 body） */
export const emptyRequestSchema = z.object({});