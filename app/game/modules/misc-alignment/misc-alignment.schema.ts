/**
 * 全量对齐杂项请求 zod schema
 *
 * app/game/router/misc-alignment.ts 全部端点均为 stub（handler 不读 body，
 * 返回空/固定响应），请求体统一用空对象校验即可。
 */
import { z } from "zod";

/** 全部对齐杂项 stub 请求体 schema（空对象，校验任何多余字段会被剥除） */
export const miscAlignmentStubSchema = z.object({});