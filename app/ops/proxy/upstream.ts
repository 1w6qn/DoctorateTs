/**
 * 上游模型 / 注册表 / 通用转发目标解析（upstream.ts）
 *
 * 从 official-forward.ts 重构而来：官方 as/gs 硬编码规则收敛为数据（buildOfficialUpstreams），
 * 解析器 generalize 为三阶段（host 规则 → 路径前缀规则 → catchAll 兜底），支持自定义上游
 * （config 声明 + registerUpstream 代码 API 双通道）。纯数据模块，不依赖 config/网络，便于单元测试。
 *
 * 求值序：upstreams 数组顺序即优先级——自定义（config/API 注册）在前、官方内置在后，
 * 自定义可覆盖官方兜底（例：{id:"obs", paths:["/arkodc"]} 截获本会落官方 gs POST 兜底的请求）。
 *
 * 与旧 resolveForwardTarget 的语义差异（均为修正而非回归）：
 * - LOCAL_ONLY_PREFIXES 升为**全局守卫**：任何阶段命中本地挂载点前缀都保持本地，
 *   修正旧 as-host 分支不查本地前缀（/admin 带 as.* host 会转发官方 404）的问题。
 */
import { hasPathPrefix, matchesAnyPrefix, LOCAL_ONLY_PREFIXES } from "@utils/path-prefix";

/** 官服 as 主机（账号系统） */
export const OFFICIAL_AS_HOST = "https://as.hypergryph.com";
/** 官服 gs 主机（游戏服务器） */
export const OFFICIAL_GS_HOST = "https://ak-gs-gf.hypergryph.com";

/** as 域路径前缀（path-based 兜底识别，与旧 test.ts 注册规则一致） */
export const AS_PATH_PREFIXES = [
  "/user/auth",
  "/user/info",
  "/user/online",
  "/user/oauth2",
  "/u8",
  "/app",
  "/general",
] as const;

/** HTTP 方法（规则过滤用；缺省 = 全匹配） */
export type ProxyMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

/**
 * 单条匹配规则：匹配条件 + 路径改写一体。
 * 求值阶段：hosts → 阶段 1（忽略 methods）；paths → 阶段 2；catchAll → 阶段 3（均受 methods 约束）。
 */
export interface ProxyRule {
  /**
   * Host 通配匹配（小写；`*` 匹配任意字符序列含点号）。
   * 例："ak-gs-*.hypergryph.com" 命中 ak-gs-gf.hypergryph.com。
   */
  hosts?: string[];
  /** 路径前缀匹配（hasPathPrefix 语义：精确等于或 前缀/ 开头）；阶段 2 */
  paths?: string[];
  /** 允许的方法（大写）；缺省 = 全部方法（含 GET） */
  methods?: ProxyMethod[];
  /** 转发前剥除的路径前缀（如 "/game" → 转发 /account/login）；仅命中时才剥 */
  stripPrefix?: string;
  /** 阶段 3 兜底：任意未命中路径（配合 methods 限制，如官方 gs 仅 POST） */
  catchAll?: boolean;
}

/** 上游：唯一 id + 目标主机 + 有序规则 */
export interface ProxyUpstream {
  id: string;
  baseUrl: string;
  rules: ProxyRule[];
}

/** 解析结果：命中上游 + 转发目标 */
export interface ProxyTarget {
  upstream: ProxyUpstream;
  baseUrl: string;
  /** 应用 stripPrefix 后的转发路径（含前导斜杠，去 query） */
  path: string;
}

/** buildOfficialUpstreams 选项（对应旧 ForwardHostOptions） */
export interface OfficialUpstreamOptions {
  asHost?: string;
  gsHost?: string;
  /** 额外 as 域路径前缀（region 扩展——yostar 登录链路等；缺省不扩展） */
  asPathPrefixes?: string[];
}

/** host 通配模式 → 全匹配正则（`*` → `.*`，其余字符按字面） */
function wildcardToRegExp(pattern: string): RegExp {
  let re = "";
  for (const ch of pattern) {
    if (ch === "*") re += ".*";
    else re += /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  return new RegExp(`^${re}$`);
}

/** host 是否命中某通配模式（host 小写化比较；pattern 约定小写） */
function hostMatches(pattern: string, host: string): boolean {
  return wildcardToRegExp(pattern).test(host.toLowerCase());
}

/** 规则是否允许该 method（methods 缺省 = 全部放行） */
function methodAllowed(rule: ProxyRule, method: ProxyMethod): boolean {
  return rule.methods === undefined || rule.methods.includes(method);
}

/** 对 path 应用规则 stripPrefix（未命中前缀则原样） */
function applyStrip(rule: ProxyRule, path: string): string {
  if (rule.stripPrefix && hasPathPrefix(path, rule.stripPrefix)) {
    return path.slice(rule.stripPrefix.length) || "/";
  }
  return path;
}

/**
 * 解析请求应转发到的上游目标（纯函数）
 *
 * 规则（与旧 resolveForwardTarget 语义一一对应）：
 * 1. 路径归一化：去 query、前导多斜杠收敛为单斜杠（官服对 // 返回 404）
 * 2. 全局守卫：LOCAL_ONLY_PREFIXES 命中 → null（永不转发，保持本地）
 * 3. 阶段 1 host 规则：所有上游的 hosts 按序匹配（忽略 methods——Host 指向即转发）
 * 4. 阶段 2 路径前缀规则：paths 按序匹配（methods 生效）
 * 5. 阶段 3 catchAll 兜底（methods 生效）
 * 6. 无命中 → null（保持本地路由 next()）
 *
 * @param method - HTTP 方法（大小写不敏感）
 * @param url - 请求路径（含 query 也无妨，只取 pathname 部分）
 * @param host - Host 头（小写；无则传空串）
 * @param upstreams - 上游表（顺序即优先级；通常来自 resolveAllUpstreams）
 * @returns 命中目标 { upstream, baseUrl, path }；null 表示保持本地（不转发）
 */
export function resolveProxyTarget(
  method: string,
  url: string,
  host: string,
  upstreams: ProxyUpstream[],
): ProxyTarget | null {
  const m = method.toUpperCase() as ProxyMethod;
  const path = (url.split("?")[0] || "/").replace(/^\/+/, "/");

  // 全局守卫：本地挂载点永不转发（/admin /config /api /assetbundle /pcSdk /audit /batch_event）
  if (matchesAnyPrefix(path, LOCAL_ONLY_PREFIXES)) return null;

  // 阶段 1：host 规则（忽略 methods）
  for (const u of upstreams) {
    for (const rule of u.rules) {
      if (rule.hosts && rule.hosts.some((p) => hostMatches(p, host))) {
        return { upstream: u, baseUrl: u.baseUrl, path: applyStrip(rule, path) };
      }
    }
  }
  // 阶段 2：路径前缀规则（methods 生效）
  for (const u of upstreams) {
    for (const rule of u.rules) {
      if (rule.paths && methodAllowed(rule, m) && rule.paths.some((p) => hasPathPrefix(path, p))) {
        return { upstream: u, baseUrl: u.baseUrl, path: applyStrip(rule, path) };
      }
    }
  }
  // 阶段 3：catchAll 兜底（methods 生效）
  for (const u of upstreams) {
    for (const rule of u.rules) {
      if (rule.catchAll && methodAllowed(rule, m)) {
        return { upstream: u, baseUrl: u.baseUrl, path: applyStrip(rule, path) };
      }
    }
  }
  return null;
}

/**
 * 官方内置上游表（行为与旧 resolveForwardTarget 完全等价）
 *
 * official-as（baseUrl = asHost，缺省 OFFICIAL_AS_HOST）：
 *   1. hosts ["as.hypergryph.com", "as.*.hypergryph.com"]（原样转发，含 GET）
 *   2. paths ["/as"] + stripPrefix "/as"（路径化前缀）
 *   3. paths [AS_PATH_PREFIXES + asPathPrefixes]（/u8 等路径保留防双写）
 * official-gs（baseUrl = gsHost，缺省 OFFICIAL_GS_HOST）：
 *   1. hosts ["ak-gs-*.hypergryph.com"] + stripPrefix "/game"
 *   2. paths ["/game"] + stripPrefix "/game"（POST/GET 均转发）
 *   3. catchAll + methods ["POST"]（根路径游戏域兜底）
 *
 * @param opts - as/gs 主机与 as 域前缀覆写（region 主机优先级由调用方解析后传入）
 */
export function buildOfficialUpstreams(opts: OfficialUpstreamOptions = {}): ProxyUpstream[] {
  const asHost = opts.asHost || OFFICIAL_AS_HOST;
  const gsHost = opts.gsHost || OFFICIAL_GS_HOST;
  const asPathPrefixes = [...AS_PATH_PREFIXES, ...(opts.asPathPrefixes ?? [])];
  return [
    {
      id: "official-as",
      baseUrl: asHost,
      rules: [
        { hosts: ["as.hypergryph.com", "as.*.hypergryph.com"] },
        { paths: ["/as"], stripPrefix: "/as" },
        { paths: asPathPrefixes },
      ],
    },
    {
      id: "official-gs",
      baseUrl: gsHost,
      rules: [
        { hosts: ["ak-gs-*.hypergryph.com"], stripPrefix: "/game" },
        { paths: ["/game"], stripPrefix: "/game" },
        { catchAll: true, methods: ["POST"] },
      ],
    },
  ];
}

/* ---------- 注册表（config 声明 + 代码 API 双通道） ---------- */

/** 已注册自定义上游（config/API；求值序在官方内置之前） */
const customUpstreams: ProxyUpstream[] = [];

/** 代码通道：注册单个上游（同名 id 覆盖） */
export function registerUpstream(u: ProxyUpstream): void {
  const idx = customUpstreams.findIndex((x) => x.id === u.id);
  if (idx >= 0) customUpstreams[idx] = u;
  else customUpstreams.push(u);
}

/** config 通道：批量注册静态上游（幂等——同名 id 覆盖，不重复） */
export function registerUpstreams(list: ProxyUpstream[]): void {
  for (const u of list) registerUpstream(u);
}

/** 代码通道：按 id 移除；返回是否命中 */
export function unregisterUpstream(id: string): boolean {
  const idx = customUpstreams.findIndex((x) => x.id === id);
  if (idx < 0) return false;
  customUpstreams.splice(idx, 1);
  return true;
}

/** 只读快照：当前全部自定义上游（不含官方内置） */
export function listUpstreams(): ProxyUpstream[] {
  return [...customUpstreams];
}

/** 清空全部自定义上游（测试/热重载用；官方内置不受影响） */
export function resetUpstreams(): void {
  customUpstreams.length = 0;
}

/**
 * 解析器实际使用的上游表：自定义在前 + 官方内置在后（opts 覆写官方主机）
 * @param opts - 官方内置上游选项（region/主机覆写由调用方解析传入；缺省官方默认主机）
 */
export function resolveAllUpstreams(opts: OfficialUpstreamOptions = {}): ProxyUpstream[] {
  return [...customUpstreams, ...buildOfficialUpstreams(opts)];
}
