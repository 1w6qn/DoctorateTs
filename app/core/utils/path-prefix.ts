/**
 * 路径前缀匹配与本地挂载点清单（单点实现）
 *
 * 三处消费方共享，消除复制粘贴漂移：
 * - proxy/official-forward：capture 模式下不转发官服的本地挂载点（LOCAL_ONLY_PREFIXES）
 * - utils/traffic-recorder：抓包默认排除前缀（原 DEFAULT_EXCLUDE_PREFIXES，与其逐项相同）
 * - config/host-router：路径级兜底分发的段匹配
 */

/**
 * 本地挂载点前缀：私服本地响应、capture 模式不转发官服、抓包默认排除——单一事实源。
 * 管理后台（/admin 页面 + API + 30s 轮询）、资源下载（/assetbundle 大文件）、
 * SDK（/pcSdk）、配置（/config /api——launcher/remote_config）、事件上报（/batch_event）、
 * 审计（/audit）。这些请求在两种模式下都由私服本地响应。
 * 注意：/arkodc（act53side ODC 小游戏「直到大地变成一颗酸橙」安洁莉娜的旅行小记路由）是游戏域接口，
 * 官服在活动开启期间客户端会调用——OBS 的 arkodc 路由即从官服逆向而来，故**不在**排除列表、
 * capture 模式照常转发官服以抓真实响应。
 */
export const LOCAL_ONLY_PREFIXES = [
  "/admin",
  "/assetbundle",
  "/pcSdk",
  "/config",
  "/api",
  "/audit",
  "/batch_event",
] as const;

/** 判断路径是否精确等于 prefix 或以 prefix/ 开头（避免误剥 /gamemode、误伤 /apiary 之类路径） */
export function hasPathPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix + "/");
}

/** 路径是否命中任一前缀（精确匹配前缀本身或以 前缀/ 开头） */
export function matchesAnyPrefix(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => hasPathPrefix(path, p));
}
