/**
 * 玩家数据模型（运行时唯一权威定义）
 *
 * 由 scripts/generate-types.ts 从 reference/com.hypergryph.arknights_2.7.61.cs
 * 自动生成（客户端闭包 + 服务端协议适配 + 线格式适配），线格式经真实官服存档
 * 标量+结构双维度校验（scripts/validate-playerdata-json.ts）。
 *
 * 生成命令: npm run generate:playerdata
 * 请勿手动修改生成文件 app/excel/types-playerdata.ts。
 */
export * from "@excel/types-playerdata";
