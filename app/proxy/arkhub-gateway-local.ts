/**
 * arkhub 网关本地应答器（私服模式——客户端进入广场不再依赖官服网关）
 *
 * 官服 `POST /activity/arkhub/enterHall` 返回 endpoint:port，客户端随后用 TCP 连接
 * 网关（长连接二进制协议）：帧 = [4B 大端总长][4B mainID][8B subID][protobuf 消息体]。
 * 抓包逆向（tmp/arkhub-gateway/）：
 *   UserLoginReq/Resp   main=4 sub=0x0fa1 / 0x0fa2（body: {1:uid,2:secret,3:1,4:deviceId}）
 *   SceneHello          main=8 sub=0x00018fb64de29cdb（登录后必发）
 *   心跳                main=1 sub=0x0（8B 时间戳）→ 服务端 main=2 sub=0x0 回显 16B
 *   场景数据            服务端 main=8 sub=0x0002c89b38b37d3d（3899B：{1:时间,2:[玩家],3:自己}）
 *
 * 本地应答器对任意登录凭据回 code=100（私服账号），心跳回显，场景回最小空广场
 * （empty 玩家列表）——客户端可进入空广场（好友/实时位置等真实网关数据不可用）。
 */
import net from "net";
import { logger } from "@utils/logger";

/** 本地网关是否已启动（enterHall 路由据此把客户端导向本地而非官服域名） */
let _localGatewayActive = false;
export function isArkhubLocalGatewayActive(): boolean {
  return _localGatewayActive;
}
export function setArkhubLocalGatewayActive(v: boolean): void {
  _localGatewayActive = v;
}

/** 登录请求/响应 subID */
const GW_USER_LOGIN_REQ = BigInt(0x0fa1);
const GW_USER_LOGIN_RESP = BigInt(0x0fa2);
/** 场景 hello subID（登录后客户端必发） */
const GW_SCENE_HELLO = BigInt("0x00018fb64de29cdb");
/** 场景数据响应 subID（服务端回给 hello 的大场景帧） */
const GW_SCENE_DATA = BigInt("0x0002c89b38b37d3d");
/** 网关返回码：100 = OK */
const GW_CODE_OK = 100;

/** 本地应答器启动选项 */
export interface ArkhubLocalGatewayOptions {
  /** 本机监听端口（缺省 30000，对齐官服网关端口） */
  port?: number;
}

/* ---------- protobuf wire 编解码（子集） ---------- */

function varint(v: number): Buffer {
  const out: number[] = [];
  let value = v >>> 0;
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    out.push(byte);
  } while (value !== 0);
  return Buffer.from(out);
}

/** 编码 varint 字段 */
function fv(field: number, v: number): Buffer {
  return Buffer.concat([Buffer.from([field << 3]), varint(v)]);
}

/** 编码 bytes/string 字段 */
function fb(field: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([(field << 3) | 2]), varint(data.length), data]);
}

/** 组帧：[4B len][4B mainID][8B subID][body] */
function buildFrame(mainID: number, subID: bigint, proto: Buffer): Buffer {
  const len = 16 + proto.length;
  const frame = Buffer.alloc(len);
  frame.writeUInt32BE(len, 0);
  frame.writeUInt32BE(mainID, 4);
  frame.writeBigUInt64BE(subID, 8);
  proto.copy(frame, 16);
  return frame;
}

/** 登录响应 body：{1: code=100, 2: count, 3: base64 token json} */
function buildLoginResp(uid: string): Buffer {
  // 官服 field3 为 base64 的 {"uuid":"...","gameId":...} JSON——客户端用于后续会话
  const token = Buffer.from(
    JSON.stringify({ uuid: uid, gameId: 2000 }),
    "utf8",
  ).toString("base64");
  return Buffer.concat([
    fv(1, GW_CODE_OK),
    fv(2, 2000),
    fb(3, Buffer.from(token, "utf8")),
  ]);
}

/** 最小场景响应 body：{1: 时间结构, 2: []（空玩家列表）, 3: 自己（空）} */
function buildMinimalScene(uid: string): Buffer {
  // field1：时间/版本结构（对齐抓包形状：{1:ts,2:ts,3:1,5:1,6:1}）
  const ts = Math.floor(Date.now() / 1000);
  const tsStruct = Buffer.concat([
    fv(1, ts),
    fv(2, ts),
    fv(3, 1),
    fv(5, 1),
    fv(6, 1),
  ]);
  // field3：自己的条目（uid + 空位置）
  const self = Buffer.concat([
    fv(1, Math.floor(Date.now() / 1000)),
    fb(2, Buffer.from(uid, "utf8")),
  ]);
  return Buffer.concat([
    fb(1, tsStruct),
    fb(2, Buffer.alloc(0)), // 空玩家列表
    fb(3, self),
  ]);
}

/* ---------- TCP 服务 ---------- */

/**
 * 启动 arkhub 本地网关应答器
 *
 * 监听本机端口，解析客户端帧并应答：登录（任意凭据 code=100）、心跳回显、
 * 场景 hello（最小空广场）、其余帧最小 ACK。端口被占返回 null。
 *
 * @param opts - 监听配置
 * @returns 成功返回 net.Server，端口被占返回 null
 */
export function startArkhubLocalGateway(
  opts: ArkhubLocalGatewayOptions = {},
): Promise<net.Server | null> {
  const { port = 30000 } = opts;

  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      let buffer = Buffer.alloc(0);
      const send = (mainID: number, subID: bigint, proto: Buffer): void => {
        if (sock.destroyed) return;
        sock.write(buildFrame(mainID, subID, proto));
      };

      sock.on("data", (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 16) {
          const len = buffer.readUInt32BE(0);
          if (len < 16 || len > 65536) {
            // 帧头非法——断开（不解析）
            sock.destroy();
            return;
          }
          if (buffer.length < len) break; // 等待完整帧
          const mainID = buffer.readUInt32BE(4);
          const subID = buffer.readBigUInt64BE(8);
          const body = buffer.subarray(16, len);
          buffer = buffer.subarray(len);

          try {
            if (mainID === 4 && subID === GW_USER_LOGIN_REQ) {
              // 登录：解析 uid（field1）用于 token，任意凭据均放行（私服）
              let uid = "";
              for (let p = 0; p < body.length; ) {
                const key = body[p++];
                const field = key >> 3;
                const wire = key & 7;
                if (wire === 2) {
                  let l = 0;
                  for (let s = 0; ; s += 7) {
                    const byte = body[p++];
                    l |= (byte & 0x7f) << s;
                    if (!(byte & 0x80)) break;
                  }
                  if (field === 1) uid = body.subarray(p, p + l).toString("utf8");
                  p += l;
                } else if (wire === 0) {
                  for (;;) {
                    const byte = body[p++];
                    if (!(byte & 0x80)) break;
                  }
                } else break;
              }
              logger.info("arkhub-gateway", `本地网关登录: uid=${uid || "?"}`);
              send(4, GW_USER_LOGIN_RESP, buildLoginResp(uid));
            } else if (mainID === 1) {
              // 心跳：回显 16B（客户端时间戳 + 服务端时间戳）
              const echo = Buffer.alloc(16);
              body.copy(echo, 0, 0, Math.min(body.length, 8));
              echo.writeBigUInt64BE(BigInt(Date.now()), 8);
              send(2, BigInt(0), echo);
            } else if (mainID === 8 && subID === GW_SCENE_HELLO) {
              // 场景 hello → 最小空广场
              logger.info("arkhub-gateway", "场景 hello → 返回最小空广场");
              send(8, GW_SCENE_DATA, buildMinimalScene(""));
            } else {
              // 其余玩法帧：空 ACK（main=8，subID+1 对齐 req→resp 的错位规律）
              send(8, subID + BigInt(1), Buffer.alloc(0));
            }
          } catch (e) {
            logger.warn("arkhub-gateway", `帧处理失败: ${(e as Error).message}`);
          }
        }
      });

      sock.on("error", (e) => logger.debug("arkhub-gateway", `连接错误: ${e.message}`));
    });

    server.once("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "EADDRINUSE") {
        logger.warn("arkhub-gateway", `端口 ${port} 被占用，本地网关未启动`);
        resolve(null);
      } else {
        logger.error("arkhub-gateway", `本地网关启动失败: ${e.message}`);
        resolve(null);
      }
    });

    server.listen(port, () => {
      _localGatewayActive = true;
      logger.info("arkhub-gateway", `本地网关已监听 :${port}（客户端可进入空广场）`);
      resolve(server);
    });
  });
}
