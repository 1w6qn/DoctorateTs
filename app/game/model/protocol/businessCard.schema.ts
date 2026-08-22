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

/** 编辑名片内容（服务端契约：flag + content；misc 仅读 showDetail/showBirthday） */
export const editNameCardSchema = z.object({
  flag: z.number(),
  content: z
    .object({
      skinId: z.string().optional(),
      component: z.array(z.string()).optional(),
      misc: z
        .object({
          showDetail: z.boolean().optional(),
          showBirthday: z.boolean().optional(),
        })
        .partial()
        .optional(),
    })
    .partial(),
});

/** 获取其他玩家名片请求（CS: GetOtherPlayerNameCardRequest { uid, src }）；空 uid 视为非法 */
export const getOtherPlayerNameCardSchema = z.object({
  uid: z.string().min(1),
  src: z.string().optional(),
});