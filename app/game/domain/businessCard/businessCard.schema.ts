/**
 * 名片（NameCard / businessCard）请求 zod schema
 *
 * 对应 protocol/businessCard.ts 的 Request 类型（参考 CS 2.7.61 协议类），
 * 供 router/businessCard.ts 经 validateBody 做运行时校验：缺失必填字段 /
 * 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */
import { z } from "zod";

/** 更换名片皮肤请求（CS: ChangeNameCardSkinRequest { skinId }） */
export const changeNameCardSkinSchema = z.object({
  skinId: z.string(),
});

/** 更换名片组件请求（CS: ChangeNameCardComponentRequest { component }） */
export const changeNameCardComponentSchema = z.object({
  component: z.array(z.string()),
});

/**
 * 编辑名片请求（CS: EditNameCardRequest { flag, content }）
 * 抓包实测：content.skinId/component 可为 null，misc.showDetail/showBirthday 为 0/1 数字
 * （非 TS 声明的 boolean），并含未读取的 skinTmpl；全部按真实客户端形态放行。
 */
export const editNameCardSchema = z.object({
  flag: z.number(),
  content: z
    .object({
      // skinId/component 客户端可能显式传 null（未设置对应项）
      skinId: z.string().nullable().optional(),
      component: z.array(z.string()).nullable().optional(),
      // misc 布尔字段实为 0/1 数字；位置覆盖不深检，容错宽松
      // 修复：客户端在该请求非「杂项」模式（flag != 4）时会显式传 misc:null，
      // 仅 optional() 只放行 undefined 不放行 null → 抓包实测被拦成 422；补 nullable()
      misc: z
        .object({
          showDetail: z.union([z.boolean(), z.number()]).optional(),
          showBirthday: z.union([z.boolean(), z.number()]).optional(),
        })
        .partial()
        .passthrough()
        .nullable()
        .optional(),
      // 未读取的外部字段（skinTmpl 等）允许出现，不拦截
    })
    .partial()
    .passthrough(),
});

/** 获取其他玩家名片请求（CS: GetOtherPlayerNameCardRequest { uid, src }）；空 uid 视为非法 */
export const getOtherPlayerNameCardSchema = z.object({
  uid: z.string().min(1),
  src: z.string().optional(),
});