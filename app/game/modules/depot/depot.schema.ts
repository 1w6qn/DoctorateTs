/**
 * 仓库（凭证）请求体 zod schema
 *
 * 参照反编译 CS（com.hypergryph.arknights_2.7.61.cs "Torappu" 命名空间下
 * GetVoucherDetailRequest / UseMaterialVoucherRequest / BoostPotentialRequest 等
 * Request 类）协议类字段定义，为 app/game/modules/depot/routes.ts 全部端点建立请求格式约束：
 * 缺失必填字段 / 类型不符时由 validateBody 中间件返回 HTTP 4xx，避免非法 body 传入
 * 控制器抛 500。
 *
 * 约定：
 * - z.any() 表示"键必须存在、值类型不深检"（如 choices 这类复杂嵌套数组）。
 * - .optional() 表示服务端不读或抓包确认可不传的字段。
 */
import { z } from "zod";

/** 获取凭证详情请求（CS: GetVoucherDetailRequest { instId, itemId }）；handler 仅读 itemId */
export const getVoucherDetailSchema = z.object({
  // instId 为凭证定位，客户端可能省略（handler 只读 itemId 查 voucher.json）
  instId: z.union([z.string(), z.number()]).optional(),
  itemId: z.string(),
});

/** 凭证抽卡请求（CS: VoucherGachaDetailRequest { instId, itemId, charId }；服务端不读 body，字段均标可选） */
export const voucherGachaSchema = z.object({
  instId: z.string().optional(),
  itemId: z.string().optional(),
  charId: z.string().optional(),
});

/** 获取干员抽卡凭证详情请求（CS: VoucherCharDetailRequest { itemId }） */
export const getCharGachaVoucherDetailSchema = z.object({
  itemId: z.string(),
});

/** 获取材料凭证详情请求（CS: VoucherItemDetailRequest { itemId }） */
export const getMaterialVoucherDetailSchema = z.object({
  itemId: z.string(),
});

/** 使用干员抽卡凭证请求（CS: useCharGachaVoucherRequest { instId, itemId }） */
export const useCharGachaVoucherSchema = z.object({
  instId: z.string(),
  itemId: z.string(),
});

/** 使用材料凭证请求（CS: UseMaterialVoucherRequest { instId, itemId, count }）；instId 可为数字/字符串（handler Number() 归一化） */
export const useMaterialVoucherSchema = z.object({
  instId: z.union([z.string(), z.number()]),
  itemId: z.string(),
  count: z.number().optional(),
});

/** 使用满潜能物品请求（CS: BoostPotentialRequest { charInstId, itemId, targetRank? }） */
export const useFullPotentialItemSchema = z.object({
  charInstId: z.number(),
  itemId: z.string(),
  // 服务端自行计算 targetRank，请求体未读取，故可选
  targetRank: z.number().optional(),
});

/** 使用选项凭证请求（CS: UseOptionalVoucherRequest { instId, itemId, choices, voucherCount? }） */
export const useOptionVoucherSchema = z.object({
  instId: z.union([z.string(), z.number()]),
  itemId: z.string(),
  // choices 为复杂嵌套数组（OptionalChoiceItem { id, count }），仅保证出现，不深检
  choices: z.array(z.any()),
  // 客户端选择数量，可能省略（handler 以 1 兜底）
  voucherCount: z.number().optional(),
});