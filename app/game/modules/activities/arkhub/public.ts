/**
 * arkhub（奇象巡展）活动模块 public 出口
 *
 * 对外收敛网关基础设施（TCP 协议处理 / 帧路由 / 本地应答器 / enterHall 适配）：
 * ops 侧（server/forwarder/transform/admin/scripts）统一经此入口消费，避免绕过模块出口。
 * 注意：活动业务符号（arkhubOnDuelSettle / arkdex / arkpixel 等）暂未收敛——
 * server.ts 等既有消费方仍直接 import 子路径，后续单独迭代。
 */
// gateway（TCP 转发器 + enterHall 适配 + capture 记录注入）
export {
  startArkhubGatewayProxy,
  ArkhubGatewayProxyOptions,
  ArkhubGatewayProxyResult,
  updateGatewayTarget,
  getGatewayTarget,
  adaptArkhubEnterHallResponse,
  isArkhubEnterHall,
  ArkhubGatewayInfo,
  setGatewayRecordSink,
  getGatewayRecordSink,
  GatewayRecordSink,
  OFFICIAL_ARKHUB_GATEWAY_HOST,
  OFFICIAL_ARKHUB_GATEWAY_PORT,
  OFFICIAL_ARKHUB_GATEWAY_CANARY_HOST,
} from "./gateway/gateway";
// local（本地网关应答器——私服模式空广场）
export {
  startArkhubLocalGateway,
  isArkhubLocalGatewayActive,
  setArkhubLocalGatewayActive,
  getArkhubLocalGatewayPort,
  ArkhubLocalGatewayOptions,
  ArkdexDocsData,
} from "./gateway/local";
// router（帧路由 + 网关类型契约）
export {
  GW_CODE_OK,
  ArkhubFrameRouter,
  ArkhubFrameHandler,
  ArkhubGatewayFrame,
  ArkhubGatewayHandlerContext,
  ArkhubGatewayConnectionState,
} from "./gateway/router";
// protocol（网关帧协议解析——admin/scripts 消费）
export * from "./gateway/protocol";
// codec（帧编解码）
export * from "./gateway/codec";
