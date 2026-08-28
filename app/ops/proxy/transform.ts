/**
 * 变换器管线（transform.ts）
 *
 * 在转发链上插入可编程修改：request 阶段（转发前，可改 headers/body）与 response 阶段
 * （回写前，可改 status/responseBody）。规则按 上游 id + 路径（前缀字符串/正则）匹配，
 * 注册序链式执行——前一规则输出喂给后一规则输入（类似 mitmproxy addon）。
 *
 * 内置响应变换器：arkhub enterHall（从 official-forward.ts 迁移）——跟随官服网关目标
 * （updateGatewayTarget）+ 有代理信息时改写 endpoint/port 指向本代理。
 */
import {
  adaptArkhubEnterHallResponse,
  ArkhubGatewayInfo,
  updateGatewayTarget,
} from "@game/modules/activities/arkhub/public";
import type { RawAxiosRequestHeaders } from "axios";
import type { ProxyUpstream } from "./upstream";

/** 变换上下文（request 阶段改 headers/body；response 阶段改 status/responseBody） */
export interface ProxyTransformContext {
  /** HTTP 方法（大写） */
  method: string;
  /** 原始请求 URL（含 query） */
  originalUrl: string;
  /** 转发路径（剥 query、已应用上游 stripPrefix） */
  path: string;
  /** 命中的上游 */
  upstream: ProxyUpstream;
  // —— 请求阶段（转发前，可改）——
  headers: RawAxiosRequestHeaders;
  /** 转发体（JSON 对象或原始 Buffer） */
  body?: unknown;
  // —— 响应阶段（回写前，可改）——
  status: number;
  /** 上游响应体（axios data：JSON 对象/字符串/Buffer） */
  responseBody: unknown;
}

/** 变换函数：同步或异步，必须返回（修改后的）ctx */
export type ProxyTransform = (
  ctx: ProxyTransformContext,
) => Promise<ProxyTransformContext> | ProxyTransformContext;

/** 变换规则：upstreamId + path 双条件 AND（缺省即放行） */
export interface ProxyTransformRule {
  /** 仅作用于指定上游（缺省 = 任意上游） */
  upstreamId?: string;
  /** 路径匹配：字符串前缀 或 正则（缺省 = 任意路径） */
  path?: string | RegExp;
  fn: ProxyTransform;
}

/** 已注册变换规则（注册序即执行序） */
const requestTransforms: ProxyTransformRule[] = [];
const responseTransforms: ProxyTransformRule[] = [];

/** arkhub 网关代理信息（forwarder 创建时注入；null = 不改写 enterHall endpoint） */
let arkhubGatewayInfo: ArkhubGatewayInfo | null = null;

/** 内置 enterHall 响应变换器（迁移自 official-forward.ts 的 isArkhubEnterHall 分支） */
const enterHallTransform: ProxyTransform = (ctx) => {
  const data = ctx.responseBody as { endpoint?: unknown; port?: unknown } | null | undefined;
  // 1) 先动态更新 TCP 转发器目标（官服 enterHall endpoint 会变化——灰度域名跟随）
  if (data && typeof data === "object") {
    updateGatewayTarget(
      typeof data.endpoint === "string" ? data.endpoint : "",
      typeof data.port === "number" ? data.port : 30000,
    );
    // 2) 有代理信息时改写为代理地址——客户端才会连到本代理、网关流量才经过代理被抓
    if (arkhubGatewayInfo) {
      ctx.responseBody = adaptArkhubEnterHallResponse(ctx.responseBody, arkhubGatewayInfo);
    }
  }
  return ctx;
};

/** 注册 request 变换器（链尾追加） */
export function registerRequestTransform(rule: ProxyTransformRule): void {
  requestTransforms.push(rule);
}

/** 注册 response 变换器（链尾追加） */
export function registerResponseTransform(rule: ProxyTransformRule): void {
  responseTransforms.push(rule);
}

/** 规则是否命中 ctx（upstreamId 精确 + path 前缀/正则；缺省放行） */
function ruleMatches(rule: ProxyTransformRule, ctx: ProxyTransformContext): boolean {
  if (rule.upstreamId !== undefined && rule.upstreamId !== ctx.upstream.id) return false;
  if (rule.path === undefined) return true;
  if (typeof rule.path === "string") return ctx.path.startsWith(rule.path);
  return rule.path.test(ctx.path);
}

/** 链式执行规则（注册序；前一输出喂后一输入） */
async function runChain(
  rules: ProxyTransformRule[],
  ctx: ProxyTransformContext,
): Promise<ProxyTransformContext> {
  let current = ctx;
  for (const rule of rules) {
    if (!ruleMatches(rule, current)) continue;
    current = await rule.fn(current);
  }
  return current;
}

/** 执行全部匹配的 request 变换器（返回新 ctx） */
export function applyRequestTransforms(ctx: ProxyTransformContext): Promise<ProxyTransformContext> {
  return runChain(requestTransforms, ctx);
}

/** 执行全部匹配的 response 变换器（返回新 ctx） */
export function applyResponseTransforms(ctx: ProxyTransformContext): Promise<ProxyTransformContext> {
  return runChain(responseTransforms, ctx);
}

/** 注入 arkhub 网关代理信息（forwarder 创建时调用；null 表示转发器未启动） */
export function setArkhubGatewayInfo(info: ArkhubGatewayInfo | null): void {
  arkhubGatewayInfo = info;
}

/** 当前 arkhub 网关代理信息（forwarder 启动判断/测试用） */
export function getArkhubGatewayInfo(): ArkhubGatewayInfo | null {
  return arkhubGatewayInfo;
}

/** 清空全部自定义变换器（测试/热重载用；内置 enterHall 重新注册） */
export function resetTransforms(): void {
  requestTransforms.length = 0;
  responseTransforms.length = 0;
  registerResponseTransform({ path: "/activity/arkhub/enterHall", fn: enterHallTransform });
}

// 模块加载即注册内置 enterHall 变换器
resetTransforms();
