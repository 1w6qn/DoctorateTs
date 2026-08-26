/**
 * 商店模块（shop）统一导出
 *
 * 功能模块五文件约定：
 * - handler  路由处理（挂载于 /shop，见 app/game/routes.ts）
 * - logic    业务逻辑（ShopManager）
 * - trigger  事件订阅登记（refresh:daily / refresh:monthly 注册顺序不变）
 * - errors   业务错误（ShopError）
 * - models   领域模型（协议请求/响应类型）
 * - schemas  请求体运行时校验（zod）
 */
export * from "./logic";
export * from "./trigger";
export * from "./errors";
export * from "./models";
export * from "./schemas";
