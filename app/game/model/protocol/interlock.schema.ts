/**
 * 连锁竞技（Act1Lock / Interlock）请求 zod schema
 *
 * 对应 protocol/interlock.ts 的 Request 类型（参考 CS 2.7.61 中
 * Torappu.Activity.Act1Lock 命名空间）。该路由为 stub 实现，各 handler 均不
 * 读取请求体，故所有请求 schema 为空对象 z.object({})。供 router/interlock.ts
 * 经 validateBody 做运行时校验：类型不符时返回 HTTP 4xx，避免非法 body 传入
 * 控制器抛 500。
 */
import { z } from "zod";

/** 获取连锁竞技里程碑奖励请求（CS: Act1LockGetMilestoneRequest，服务端不读取 body） */
export const getMilestoneSchema = z.object({});

/** 批量获取连锁竞技里程碑奖励请求（CS: Act1LockGetMilestoneBatchRequest，服务端不读取 body） */
export const getMilestoneBatchSchema = z.object({});

/** 设置连锁竞技防守请求（CS: Act1LockSetDefendRequest，服务端不读取 body） */
export const setDefendSchema = z.object({});

/** 设置连锁竞技编队请求（CS: Act1LockSetSquadRequest，服务端不读取 body） */
export const setSquadSchema = z.object({});