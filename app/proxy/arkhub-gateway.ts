/**
 * arkhub 网关特殊适配（capture 模式）
 *
 * 官服 `POST /activity/arkhub/enterHall` 响应返回 `{ result, endpoint, port }`，
 * 客户端随后用 BestHTTP WebSocket 连接 `endpoint:port`（阿卡狄亚大厅实时网关，私有协议）。
 * capture 模式下需要两件事才能让客户端连到本代理、网关流量也被抓：
 *   1. **改写 enterHall 响应**：endpoint 改为代理主机（config.Host 去 scheme）、port 保持 30000，
 *      否则客户端直连官服网关（hosts 重写时连 127.0.0.1:30000 无监听而失败，且网关流量不经过代理）
 *   2. **30000 端口 TCP 转发器**：监听本机端口，把客户端连接透传到官服网关
 *      `arkhub-gateway.hypergryph.com:30000`，双向字节流原样转发并落盘 tmp/arkhub-gateway/
 *
 * 网关为明文 TCP（官服 30000 可 TCP 连接；TLS 握手被直接断开、明文 WebSocket 握手无响应），
 * 因此转发器是纯 TCP pipe（不做协议解析）；客户端自带上层握手/鉴权，原样透传即可。
 */
import net from "net";
import { mkdir, writeFile } from "fs/promises";
import * as path from "path";
import { logger } from "@utils/logger";

/** 官服 arkhub 网关主机 */
export const OFFICIAL_ARKHUB_GATEWAY_HOST = "arkhub-gateway.hypergryph.com";
/** 官服 arkhub 网关端口 */
export const OFFICIAL_ARKHUB_GATEWAY_PORT = 30000;
/** 默认记录根目录（与 traffic-recorder 的 tmp/ 一致） */
const DEFAULT_RECORD_ROOT = "tmp/arkhub-gateway";

/** arkhub 网关代理信息（用于改写 enterHall 响应 + 启动转发器） */
export interface ArkhubGatewayInfo {
  /** 改写后的网关地址（客户端可连接的代理主机，如 127.0.0.1） */
  endpoint: string;
  /** 改写后的网关端口（代理监听端口，缺省 30000） */
  port: number;
}

/**
 * 改写 arkhub enterHall 响应中的网关 endpoint/port
 *
 * 纯函数（可单测）：仅当 payload 为对象且含 string endpoint + number port 时改写，
 * 否则原样返回（不破坏其它响应）。playerDataDelta 等字段不动。
 *
 * @param payload - 转发响应的 body（axios 解析后的对象）
 * @param gateway - 代理网关信息
 * @returns 改写后的 payload（原地修改并返回）
 */
export function adaptArkhubEnterHallResponse(
  payload: unknown,
  gateway: ArkhubGatewayInfo,
): unknown {
  if (payload && typeof payload === "object" && !Buffer.isBuffer(payload)) {
    const data = payload as { endpoint?: unknown; port?: unknown };
    if (typeof data.endpoint === "string" && typeof data.port === "number") {
      data.endpoint = gateway.endpoint;
      data.port = gateway.port;
    }
  }
  return payload;
}

/** 判断转发目标路径是否为 arkhub enterHall（/game 基址前缀已在 resolveForwardTarget 剥除） */
export function isArkhubEnterHall(pathname: string): boolean {
  return pathname === "/activity/arkhub/enterHall";
}

/** TCP 转发器启动选项 */
export interface ArkhubGatewayProxyOptions {
  /** 本机监听端口（缺省 30000；config.capture.gatewayPort 可覆盖） */
  port?: number;
  /** 目标官服网关主机（测试可覆写） */
  targetHost?: string;
  /** 目标官服网关端口（测试可覆写） */
  targetPort?: number;
  /** 记录根目录（测试传独立临时目录） */
  recordRoot?: string;
}

/** 网关转发器启动结果 */
export interface ArkhubGatewayProxyResult {
  /** 监听成功的 net.Server；失败为 null */
  server: net.Server | null;
  /** 是否因端口被占而失败（该端口上很可能已有另一实例的网关转发器在跑） */
  portBusy: boolean;
}

/**
 * 启动 arkhub 网关 TCP 转发器
 *
 * 监听本机端口，每个客户端连接建立到官服网关的透传管道，双向字节流落盘
 * `tmp/arkhub-gateway/{connectionId}/`（up.bin=客户端→官服、down.bin=官服→客户端、meta.json）。
 *
 * @param opts - 监听/目标/记录配置
 * @returns 启动结果：{ server } 监听成功；{ server: null, portBusy: true } 端口被占；
 *          { server: null, portBusy: false } 其它错误
 */
export function startArkhubGatewayProxy(
  opts: ArkhubGatewayProxyOptions = {},
): Promise<ArkhubGatewayProxyResult> {
  const {
    port = OFFICIAL_ARKHUB_GATEWAY_PORT,
    targetHost = OFFICIAL_ARKHUB_GATEWAY_HOST,
    targetPort = OFFICIAL_ARKHUB_GATEWAY_PORT,
    recordRoot = DEFAULT_RECORD_ROOT,
  } = opts;

  const server = net.createServer((client) => {
    const connectionId = new Date().toISOString().replace(/[:.]/g, "-");
    const upstream = net.connect({ host: targetHost, port: targetPort });
    let upBytes = 0;
    let downBytes = 0;
    let metaWritten = false;

    const record = (dir: string, file: string, chunk: Buffer): void => {
      // 先建目录（data 事件可能先于 meta.json 的 mkdir），再追加写
      void (async () => {
        try {
          await mkdir(dir, { recursive: true });
          await writeFile(path.join(dir, file), chunk, { flag: "a" });
        } catch {
          /* 记录失败不影响转发 */
        }
      })();
    };

    // 客户端 → 官服
    client.on("data", (chunk: Buffer) => {
      upBytes += chunk.length;
      if (upstream.destroyed) return;
      upstream.write(chunk);
      record(path.join(recordRoot, connectionId), "up.bin", chunk);
    });
    // 官服 → 客户端
    upstream.on("data", (chunk: Buffer) => {
      downBytes += chunk.length;
      if (client.destroyed) return;
      client.write(chunk);
      record(path.join(recordRoot, connectionId), "down.bin", chunk);
    });

    const finish = (reason: string): void => {
      if (metaWritten) return;
      metaWritten = true;
      void (async () => {
        try {
          const dir = path.join(recordRoot, connectionId);
          await mkdir(dir, { recursive: true });
          await writeFile(
            path.join(dir, "meta.json"),
            JSON.stringify(
              {
                timestamp: new Date().toISOString(),
                clientAddr: client.remoteAddress,
                targetAddr: `${targetHost}:${targetPort}`,
                upBytes,
                downBytes,
                reason,
              },
              null,
              2,
            ),
            "utf-8",
          );
        } catch {
          /* 元数据写失败不影响转发 */
        }
      })();
    };

    client.on("error", (e) => {
      logger.debug("capture", "arkhub 客户端连接错误:", e.message);
      upstream.destroy();
      finish("client-error");
    });
    upstream.on("error", (e) => {
      logger.debug("capture", "arkhub 官服网关连接错误:", e.message);
      client.destroy();
      finish("upstream-error");
    });
    client.on("close", () => {
      upstream.destroy();
      finish("closed");
    });
    upstream.on("close", () => {
      client.destroy();
      finish("closed");
    });
  });

  return new Promise((resolve) => {
    server.once("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "EADDRINUSE") {
        // 端口被占（多半是另一实例的网关转发器）：返回 portBusy=true，调用方仍改写 enterHall
        // endpoint 指向该端口——否则客户端直连官服网关、网关流量不经过任何代理（实测无法进入）
        logger.warn("capture", `arkhub 网关端口 ${port} 被占用（可能为另一实例的转发器）——enterHall 响应仍改写指向本代理，客户端网关流量经占用该端口的转发器`);
        resolve({ server: null, portBusy: true });
      } else {
        logger.error("capture", `arkhub 网关转发器启动失败: ${e.message}`);
        resolve({ server: null, portBusy: false });
      }
    });
    server.listen(port, () => {
      logger.info("capture", `arkhub 网关转发器已启动：监听 :${port} → ${targetHost}:${targetPort}（流量记录 ${recordRoot}）`);
      resolve({ server, portBusy: false });
    });
  });
}
