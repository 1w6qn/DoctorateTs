/**
 * Proxy 通用转发管线 public 出口（index.ts）
 *
 * server.ts / 外部消费统一入口：上游注册（config + 代码 API）、变换器注册、
 * 转发中间件与预热。官方硬编码 as/gs 规则已收敛为数据（buildOfficialUpstreams）。
 */
export {
  // 上游模型与注册表
  resolveProxyTarget,
  buildOfficialUpstreams,
  registerUpstream,
  registerUpstreams,
  unregisterUpstream,
  listUpstreams,
  resetUpstreams,
  resolveAllUpstreams,
  OFFICIAL_AS_HOST,
  OFFICIAL_GS_HOST,
  AS_PATH_PREFIXES,
  type ProxyRule,
  type ProxyUpstream,
  type ProxyTarget,
  type ProxyMethod,
  type OfficialUpstreamOptions,
} from "./upstream";
// 变换器管线
export {
  registerRequestTransform,
  registerResponseTransform,
  applyRequestTransforms,
  applyResponseTransforms,
  resetTransforms,
  setArkhubGatewayInfo,
  getArkhubGatewayInfo,
  type ProxyTransformContext,
  type ProxyTransform,
  type ProxyTransformRule,
} from "./transform";
// 转发中间件
export {
  createProxyForwarder,
  warmUpOfficialConnections,
  officialHttpAgent,
  officialHttpsAgent,
  type ProxyForwarderOptions,
} from "./forwarder";
