/**
 * arkhub 网关本地应答器（私服模式——客户端进入广场不再依赖官服网关）
 *
 * 官服 `POST /activity/arkhub/enterHall` 返回 endpoint:port，客户端随后用 TCP 连接
 * 网关（长连接二进制协议）：帧 = [4B 大端总长][4B mainID][8B subID][protobuf 消息体]。
 * 抓包逆向（tmp/arkhub-gateway/）：
 *   UserLoginReq/Resp   main=4 sub=0x0fa1 / 0x0fa2（body: {1:uid,2:secret,3:1,4:deviceId}）
 *   SceneHello          main=8 sub=0x00018fb64de29cdb（登录后必发，实为 EnterSceneReq）
 *   心跳                main=1 sub=0x0（8B 时间戳）→ 服务端 main=2 sub=0x0 回显 16B
 *   场景数据            服务端 main=8 sub=0x0002c89b38b37d3d（EnterSceneNotify：
 *                       {1: HallInfo, 2: PlayerSyncData(自己), 3: PlayerHallBrief}）
 *
 * 本地应答器对任意登录凭据回 code=100（私服账号），心跳回显，场景回合法的
 * EnterSceneNotify（TOWN 广场 + 自己的 PlayerSyncData）——客户端能进入空广场
 * （好友/实时位置等真实网关数据不可用）。
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
/** 场景 hello subID（登录后客户端必发，实为 EnterSceneReq） */
const GW_SCENE_HELLO = BigInt("0x00018fb64de29cdb");
/** 场景数据响应 subID（服务端回给 hello 的 EnterSceneNotify 帧） */
const GW_SCENE_DATA = BigInt("0x0002c89b38b37d3d");
/** 网关返回码：100 = OK */
const GW_CODE_OK = 100;
/** 方舟枢纽广场 map_id（activity.ARK_HUB.sceneTypeMap：-1520665757 = TOWN 广场） */
const HALL_MAP_ID = -1520665757;
/** 场景类型（官服 EnterSceneNotify HallInfo.scene_type 恒定 200） */
const HALL_SCENE_TYPE = 200;
/** 广场属性位（HallInfo.attributes 恒定 1） */
const HALL_ATTRIBUTES = 1;
/** 位置同步间隔 ms（HallInfo.sync_interval 恒定 200） */
const HALL_SYNC_INTERVAL = 200;

/** 本地应答器启动选项 */
export interface ArkhubLocalGatewayOptions {
  /** 本机监听端口（缺省 30000，对齐官服网关端口） */
  port?: number;
  /** 可选：按 uid 解析玩家昵称（私服存档 data/user/databases/{uid}.json；缺省回退 博士{uid}） */
  resolveNickname?: (uid: string) => string;
}

/* ---------- protobuf wire 编解码（子集） ---------- */

/** 无符号 varint 编码（支持 64 位 BigInt） */
function varint(v: bigint | number): Buffer {
  const out: number[] = [];
  let value = BigInt(v);
  do {
    let byte = Number(value & BigInt(0x7f));
    value >>= BigInt(7);
    if (value !== BigInt(0)) byte |= 0x80;
    out.push(byte);
  } while (value !== BigInt(0));
  return Buffer.from(out);
}

/** 编码 varint 字段（value 为带符号 int64/int32——负数自动 10 字节符号扩展） */
function fv(field: number, v: bigint | number): Buffer {
  let value = BigInt(v);
  if (value < BigInt(0)) value = BigInt.asUintN(64, value);
  return Buffer.concat([Buffer.from([field << 3]), varint(value)]);
}

/** 编码 bytes/string 字段 */
function fb(field: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([(field << 3) | 2]), varint(data.length), data]);
}

/** 编码 fixed32 字段（Vector3 用 field1/2/3 wire5，即标签 0x0d/0x15/0x1d） */
function ff32(field: number, v: number): Buffer {
  const tag = (field << 3) | 5;
  const buf = Buffer.alloc(4);
  buf.writeFloatLE(v, 0);
  return Buffer.concat([Buffer.from([tag]), buf]);
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

/** 登录响应 body：{1: code=100, 2: heartbeatInterval, 3: reconnectToken(payload.signature)} */
function buildLoginResp(uid: string): Buffer {
  // 官服 field3 = `base64({uuid, device_id, expire_time}).signature` 两段式（签名部分任意）
  const payload = Buffer.from(
    JSON.stringify({ uuid: uid, device_id: "0".repeat(32), expire_time: Math.floor(Date.now() / 1000) + 86400 }),
    "utf8",
  ).toString("base64");
  const token = `${payload}.local-gateway`;
  return Buffer.concat([
    fv(1, GW_CODE_OK),
    fv(2, 2000),
    fb(3, Buffer.from(token, "utf8")),
  ]);
}

/** Vector3 位置（3× fixed32，15B） */
function buildVector3(x: number, y: number, z: number): Buffer {
  return Buffer.concat([ff32(1, x), ff32(2, y), ff32(3, z)]);
}

/**
 * 合法 EnterSceneNotify body：{1: HallInfo, 2: PlayerSyncData(自己), 3: PlayerHallBrief}
 * 官方形状（抓包验证）：
 * - HallInfo: {1:unique_id, 2:map_id(-1520665757=TOWN), 3:scene_type(200), 5:attributes(1), 6:sync_interval(200)}
 * - PlayerSyncData: {1: PlayerBrief{1:uid,2:nickname,3:nicknumber}, 4: attrDoc{1:attributes[]}}
 * - PlayerHallBrief: {1:unique_id, 2:pos(Vector3)}
 */
function buildEnterScene(uid: string, nickname: string): Buffer {
  // HallInfo（unique_id 每会话生成，取 uid 数值稳定）
  const uidNum = BigInt(uid || "0") || BigInt(Date.now());
  const hallUnique = BigInt.asUintN(32, uidNum) | BigInt(1);
  const hallInfo = Buffer.concat([
    fv(1, hallUnique),
    fv(2, HALL_MAP_ID),
    fv(3, HALL_SCENE_TYPE),
    fv(5, HALL_ATTRIBUTES),
    fv(6, HALL_SYNC_INTERVAL),
  ]);
  // PlayerBrief + PlayerSyncData（attrDoc 空列表；客户端 selfUnitInfo.Fill 依赖 field1/field4）
  const playerBrief = Buffer.concat([
    fb(1, Buffer.from(uid, "utf8")),
    fb(2, Buffer.from(nickname, "utf8")),
    fb(3, Buffer.from(String(uidNum & BigInt(9999)), "utf8")),
  ]);
  const attrDoc = fb(1, Buffer.alloc(0)); // AttributeData{1: attributes[]}
  const playerSync = Buffer.concat([fb(1, playerBrief), fb(4, attrDoc)]);
  // PlayerHallBrief：{1: unique_id(ulong), 2: pos}
  const selfUnitId = BigInt.asUintN(64, uidNum) | (BigInt(1) << BigInt(40));
  const hallBrief = Buffer.concat([
    fv(1, selfUnitId),
    fb(2, buildVector3(4.38, 0.0065, 8.2)),
  ]);
  return Buffer.concat([
    fb(1, hallInfo),
    fb(2, playerSync),
    fb(3, hallBrief),
  ]);
}

/* ---------- TCP 服务 ---------- */

/**
 * 启动 arkhub 本地网关应答器
 *
 * 监听本机端口，解析客户端帧并应答：登录（任意凭据 code=100，记录 uid 供场景使用）、
 * 心跳回显、场景 hello（合法 EnterSceneNotify——含自己的 PlayerSyncData）、其余帧最小 ACK。
 * 端口被占返回 null。
 *
 * @param opts - 监听配置
 * @returns 成功返回 net.Server，端口被占返回 null
 */
export function startArkhubLocalGateway(
  opts: ArkhubLocalGatewayOptions = {},
): Promise<net.Server | null> {
  const { port = 30000, resolveNickname } = opts;

  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      let buffer = Buffer.alloc(0);
      // 当前连接的登录 uid（登录帧解析；场景 hello 用它构建自己的玩家条目）
      let loginUid = "";
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
              // 登录：解析 uid（field1）用于 token/场景，任意凭据均放行（私服）
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
              loginUid = uid || "";
              logger.info("arkhub-gateway", `本地网关登录: uid=${loginUid || "?"}`);
              send(4, GW_USER_LOGIN_RESP, buildLoginResp(loginUid));
            } else if (mainID === 1) {
              // 心跳：回显 16B（客户端时间戳 + 服务端时间戳）
              const echo = Buffer.alloc(16);
              body.copy(echo, 0, 0, Math.min(body.length, 8));
              echo.writeBigUInt64BE(BigInt(Date.now()), 8);
              send(2, BigInt(0), echo);
            } else if (mainID === 8 && subID === GW_SCENE_HELLO) {
              // 场景 hello（EnterSceneReq）→ 合法 EnterSceneNotify（TOWN 广场 + 自己）
              const nickname = resolveNickname
                ? resolveNickname(loginUid)
                : `博士${loginUid || "1"}`;
              logger.info("arkhub-gateway", `场景 hello → EnterSceneNotify (uid=${loginUid})`);
              send(8, GW_SCENE_DATA, buildEnterScene(loginUid, nickname));
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
