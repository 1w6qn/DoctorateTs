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

/** 本地网关实际监听端口（enterHall 路由回报给客户端；未启动为 0） */
let _localGatewayPort = 0;
export function getArkhubLocalGatewayPort(): number {
  return _localGatewayPort;
}

/** 登录请求/响应 subID */
const GW_USER_LOGIN_REQ = BigInt(0x0fa1);
const GW_USER_LOGIN_RESP = BigInt(0x0fa2);
/** 场景 hello subID（登录后客户端必发，实为 EnterSceneReq） */
const GW_SCENE_HELLO = BigInt("0x00018fb64de29cdb");
/** 场景数据响应 subID（服务端回给 hello 的 EnterSceneNotify 帧） */
const GW_SCENE_DATA = BigInt("0x0002c89b38b37d3d");
/** 切场景请求 subID（low32；高 32 位为会话/场景前缀，随场景变化——需按低 32 位匹配） */
const GW_SCENE_SWITCH = BigInt(0x38b3b60b);
/** 切场景 ACK 响应 subID（low32；响应前缀固定 0x2c89b3） */
const GW_SCENE_SWITCH_ACK = BigInt(0x38b3a5a8);
/** 交互提交请求（领奖/AVG 完成：{1: actorId, 2: operationId("get_reward")}） */
const GW_INTERACT_REQ = BigInt(0x38b3116d);
/** ARKDUEL 商店请求（打开对战道具商店；请求体 [4B seq]）→ 0x28f5229c 价格表 */
const GW_DUEL_SHOP_REQ = BigInt(0x28f5ba6f);
const GW_DUEL_SHOP_RESP = BigInt(0x28f5229c);
/** 令牌刷新请求（诱引剂/宠物实体令牌，[4B seq] + {1:ts?, 2:hex}）→ 0x31d60cf6 新令牌 */
const GW_TOKEN_REQ = BigInt(0x31d603b3);
const GW_TOKEN_RESP = BigInt(0x31d60cf6);
/** ARKDUEL 战斗开始（[4B seq] + {1:squad JSON}）→ 0xb7c20f13 敌方单位/奖励 */
const GW_DUEL_BATTLE_START_REQ = BigInt(0xb7c267d7);
const GW_DUEL_BATTLE_START_RESP = BigInt(0xb7c20f13);
/** ARKDUEL 战斗结算（[4B seq] + {1:battleId}）→ 0xb7c2b07e code100 */
const GW_DUEL_BATTLE_FINISH_REQ = BigInt(0xb7c204e8);
const GW_DUEL_BATTLE_FINISH_RESP = BigInt(0xb7c2b07e);
/** ARKDUEL 战斗结果推送（服务端在结算后主动下发） */
const GW_DUEL_RESULT_PUSH_1 = BigInt(0xb7c26451);
const GW_DUEL_RESULT_PUSH_2 = BigInt(0xb7c2d119);
/** 网关返回码：100 = OK */
const GW_CODE_OK = 100;
/** 方舟枢纽广场 map_id（activity.ARK_HUB.sceneTypeMap：-1520665757 = TOWN 广场） */
const HALL_MAP_ID = -1520665757;
/** 巡展捕抓区 map_id（sceneTypeMap：CAPTURE 场景 1/2/3） */
const CAPTURE_MAP_IDS = [-820616879, -820813487, -820747951];
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
  /** 端口被占时自动避让尝试次数上限（缺省 50：port, port+1, ...） */
  maxPortTries?: number;
  /** 可选：按 uid 解析玩家昵称（旧接口；新实现用 resolvePlayerProfile 统一返回） */
  resolveNickname?: (uid: string) => string;
  /** 可选：按 uid 解析广场玩家资料（昵称/等级/秘书干员/皮肤——客户端据此渲染玩家模型） */
  resolvePlayerProfile?: (uid: string) => {
    nickname?: string;
    level?: number;
    charId?: string;
    skinId?: string;
    avatarId?: string;
  };
  /** 可选：ARKDUEL 战斗结算回调（uid=已登录账号；私服据此发 15 券 + 对战计数） */
  onDuelSettle?: (uid: string) => void;
  /** 可选：每日物资领取回调（uid；私服据此记录领取天数 + 发 100 券） */
  onDailySupplyClaimed?: (uid: string) => void;
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
 * 官方形状（抓包验证，tmp/capture/records/2026-08-09T04-29-12-534Z/parsed.json）：
 * - HallInfo: {1:unique_id, 2:map_id(-1520665757=TOWN), 3:scene_type(200), 5:attributes(1), 6:sync_interval(200)}
 * - PlayerSyncData: {
 *     1: PlayerBrief{1:uid, 2:nickname, 3:nicknumber, 4:level, 5:avatarId, 6:charId, 7:skinId}
 *     2: AvatarInfo{1:"ICON", 2:avatarId, 3:charId, 4:skinId}
 *     3: GuideFlags{1:[{1:key, 2:value}...], 2:ts}
 *     4: GameplayAttr{1:[{1:attrId, 2:level}...]}
 *   }
 * - PlayerHallBrief: {1:unique_id, 2:pos(Vector3)}
 *
 * 修复：原 PlayerBrief 仅 uid/nickname/nicknumber——缺 charId/skinId → 客户端广场
 * 渲染不出玩家模型（"不显示人物模型"）；缺 guide 标记 → 区域/引导状态缺失。
 */
/** 枢纽 GuideFlags 默认值（对齐官服完成态快照） */
function defaultGuideFlags(): Record<string, number> {
  return {
    arkdex_battle_guide: 2,
    area_2_guard: 1,
    area_3_guard: 1,
    terminal_guide: 1,
    area_3_blcok: 1,
    terminal_guide_arkdex: 1,
    arkhub_login: 1,
    arkdex_mmkabi1: 1,
    // capture_catch_guide_02 取 2（完成态）——取 1 会触发 mmkabi_01b [AUTO] 引导
    // （ReceiveArkhubReward 领奖帧无官服响应样本，客户端 9s 超时重试 → 对话无法结束）。
    // 设施解锁（pixel_unlock → UnlockArkhubFunc）在 02=1 会话已执行，客户端本地缓存保留。
    capture_catch_guide_02: 2,
    pixel_unlock: 1,
    pixel_unlock_system: 1,
    area_2_block: 1,
    area_1_block: 1,
    capture_catch_guide_01: 2,
  };
}

function buildEnterScene(
  uid: string,
  profile: {
    nickname: string;
    level: number;
    charId: string;
    skinId: string;
    avatarId?: string;
  },
  mapId: number = HALL_MAP_ID,
  guideValues: Record<string, number> = defaultGuideFlags(),
): Buffer {
  // HallInfo（unique_id 每会话生成，取 uid 数值稳定；map_id 决定客户端加载哪个场景——
  // TOWN 广场 = -1520665757，捕抓区 CAPTURE 1/2/3 = -820616879/-820813487/-820747951）
  const uidNum = BigInt(uid || "0") || BigInt(Date.now());
  const hallUnique = BigInt.asUintN(32, uidNum) | BigInt(1);
  const hallInfo = Buffer.concat([
    fv(1, hallUnique),
    fv(2, mapId),
    fv(3, HALL_SCENE_TYPE),
    fv(5, HALL_ATTRIBUTES),
    fv(6, HALL_SYNC_INTERVAL),
  ]);
  // PlayerBrief：1~3 基本，4=等级，5=avatarId，6=charId，7=skinId（官方形状）
  const playerBrief = Buffer.concat([
    fb(1, Buffer.from(uid, "utf8")),
    fb(2, Buffer.from(profile.nickname, "utf8")),
    fb(3, Buffer.from(String(uidNum & BigInt(9999)), "utf8")),
    fv(4, profile.level || 1),
    fv(5, 1),
    fb(6, Buffer.from(profile.charId, "utf8")),
    fb(7, Buffer.from(profile.skinId, "utf8")),
  ]);
  // AvatarInfo：{1:"ICON", 2:avatarId, 3:charId, 4:skinId}
  const avatarInfo = Buffer.concat([
    fb(1, Buffer.from("ICON", "utf8")),
    fb(2, Buffer.from(profile.avatarId || "avatar_dyn_04", "utf8")),
    fb(3, Buffer.from(profile.charId, "utf8")),
    fb(4, Buffer.from(profile.skinId, "utf8")),
  ]);
  // GuideFlags：hub 区域/引导标记——形状与取值对齐官服完成态抓包
  // （tmp/capture/records/2026-08-09T04-29-12-534Z）。f1 为【重复字段】，
  // 每条 {1:key, 2:value} 独立一条，f2 为时间戳。
  // capture_catch_guide_02 默认 1（设施解锁 pixel_unlock 触发条件）；mmkabi 领奖后置 2。
  const guideFlags = Buffer.concat([
    ...Object.entries(guideValues).map(([key, val]) =>
      fb(1, Buffer.concat([fb(1, Buffer.from(key, "utf8")), fv(2, val)])),
    ),
    fv(2, BigInt(Date.now())),
  ]);
  // GameplayAttr：官方样例 [{1:4,2:1},{1:5,2:1},{1:9}]
  const gameAttrs = Buffer.concat([
    fb(1, Buffer.concat([fv(1, 4), fv(2, 1)])),
    fb(1, Buffer.concat([fv(1, 5), fv(2, 1)])),
    fb(1, Buffer.concat([fv(1, 9)])),
  ]);
  const playerSync = Buffer.concat([
    fb(1, playerBrief),
    fb(2, avatarInfo),
    fb(3, guideFlags),
    fb(4, gameAttrs),
  ]);
  // PlayerHallBrief：{1: unique_id(ulong), 2: pos}
  const selfUnitId = BigInt.asUintN(64, uidNum) | (BigInt(1) << BigInt(40));
  const hallBrief = Buffer.concat([
    fv(1, selfUnitId),
    fb(2, buildVector3(...spawnPointFor(mapId))),
  ]);
  return Buffer.concat([
    fb(1, hallInfo),
    fb(2, playerSync),
    fb(3, hallBrief),
  ]);
}

/**
 * 各场景出生点（官服抓包验证：EnterSceneNotify PlayerHallBrief.pos）
 * - TOWN 广场 = (4.742, -0.008, 6.079)
 * - CAPTURE 1 = (1.945, 0.513, -6.850)（CAPTURE 2/3 无样本，沿用 CAPTURE 1）
 * 修复：原实现所有场景统一用广场坐标 → 传送后出生点错误。
 */
function spawnPointFor(mapId: number): [number, number, number] {
  if (CAPTURE_MAP_IDS.includes(mapId)) return [1.945, 0.513, -6.85];
  return [4.742, -0.008, 6.079];
}

/* ---------- ARKDUEL 网关帧响应构建（官服抓包 2026-08-09 字节级对齐） ---------- */

/**
 * ARKDUEL 商店价格表（0x28f5ba6f → 0x28f5229c）
 * 官服响应：{1:100, 3:{1:ts, 2:[{1:序号, 2:itemNumId, 3:价格, 4:库存}×7]}}
 * 道具与价格对齐官服（activity.ARK_HUB.itemData 的 itemNumId）：
 * 5004 标准诱引剂 40 / 5005 专业诱引剂 60 / 5006 稀有诱引剂 250 /
 * 5009 甜味诱引剂 60 / 5010 辣味诱引剂 60 / 5015 专业信息素 60 / 5021 苦味信息素 60
 */
function buildDuelShopResp(seq: number): Buffer {
  const items = [
    [1, 5004, 40, 99],
    [2, 5005, 60, 99],
    [3, 5006, 250, 2],
    [4, 5009, 60, 5],
    [5, 5010, 60, 5],
    [6, 5015, 60, 5],
    [7, 5021, 60, 5],
  ].map(([no, numId, price, avail]) =>
    fb(2, Buffer.concat([fv(1, no as number), fv(2, numId as number), fv(3, price as number), fv(4, avail as number)])),
  );
  const payload = Buffer.concat([
    fv(1, GW_CODE_OK),
    fb(3, Buffer.concat([fv(1, BigInt(Date.now())), ...items])),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/**
 * 令牌刷新响应（0x31d603b3 → 0x31d60cf6）
 * 官服响应：[seq] {1:100, 2:{1:<实体id>, 2:<新32位hex令牌>, 3:ts}}——客户端发送
 * 旧令牌，服务端签发新令牌（诱引剂/宠物实体用）。私服签发随机新令牌。
 */
function buildTokenResp(seq: number): Buffer {
  const newToken = Array.from({ length: 32 }, () =>
    "0123456789abcdef"[Math.floor(Math.random() * 16)],
  ).join("");
  const id = Number(BigInt.asUintN(32, BigInt(Math.floor(Math.random() * 0xffffffff) + 1)));
  const payload = Buffer.concat([
    fv(1, GW_CODE_OK),
    fb(2, Buffer.concat([
      fv(1, id),
      fb(2, Buffer.from(newToken, "utf8")),
      fv(3, BigInt(Date.now())),
    ])),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/** ARKDUEL 敌方单位（官服响应 5 个单位，f2=19005 基 id，f3=状态位 64/256/2/32/512） */
const DUEL_ENEMY_UNITS: Array<[number, number]> = [
  [19005, 64],
  [19005, 256],
  [19005, 2],
  [19005, 32],
  [19005, 512],
];

/**
 * ARKDUEL 战斗开始响应（0xb7c267d7 → 0xb7c20f13，无 seq 前缀）
 * 官服响应：{1:[{2:19005,3:flag}×5], 2:"act1arkhub_14", 3:1}——敌方单位 + 战斗/奖励标识
 */
function buildDuelBattleStartResp(): Buffer {
  const units = DUEL_ENEMY_UNITS.map(([id, flag]) =>
    fb(1, Buffer.concat([fv(2, id), fv(3, flag)])),
  );
  return Buffer.concat([
    fb(1, Buffer.concat(units)),
    fb(2, Buffer.from("act1arkhub_14", "utf8")),
    fv(3, 1),
  ]);
}

/**
 * ARKDUEL 战斗结算响应（0xb7c204e8 → 0xb7c2b07e）
 * 官服响应：[seq=战斗开始 seq] {1:100, 2:<battleId 回显>}
 */
function buildDuelBattleFinishResp(seq: number, battleId: string): Buffer {
  const payload = Buffer.concat([
    fv(1, GW_CODE_OK),
    fb(2, Buffer.from(battleId, "utf8")),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/**
 * ARKDUEL 战斗结果推送（结算后服务端主动下发）
 * 0xb7c26451：[seq] {1:{1:1, 2:ts, 3:[{1:unitId,2:19005,3:flag}×5]}}
 * 0xb7c2d119：{1:[{1:unitId,2:19005,3:flag,5:ts}×5], 3:{1:19005,2:890,3:10}}
 */
function buildDuelResultPush1(seq: number): Buffer {
  const units = DUEL_ENEMY_UNITS.map(([, flag], i) =>
    fb(3, Buffer.concat([fv(1, 154 + i), fv(2, 19005), fv(3, flag)])),
  );
  const payload = Buffer.concat([
    fb(1, Buffer.concat([fv(1, 1), fv(2, BigInt(Date.now())), ...units])),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}
function buildDuelResultPush2(): Buffer {
  const units = DUEL_ENEMY_UNITS.map(([, flag], i) =>
    fb(1, Buffer.concat([
      fv(1, 154 + i),
      fv(2, 19005),
      fv(3, flag),
      fv(5, BigInt(Date.now())),
    ])),
  );
  return Buffer.concat([
    ...units,
    fb(3, Buffer.concat([fv(1, 19005), fv(2, 890), fv(3, 10)])),
  ]);
}

/* ---------- 枢纽交互提交（0x38b3116d：{1:actorId, 2:operationId("get_reward")}） ---------- */

/** 枢纽 actor → 领奖奖励（activity.ARK_HUB.rewardDataDict 映射；据官服/抓包） */
const HUB_REWARD_MAP: Record<string, { id: string; count: number; type: string }[]> = {
  arkhub_capture1_mmkabi_01b: [{ id: "arkdex_1_gold", count: 50, type: "COIN" }], // reward_guide_01
  arkhub_main_daily_task_02a: [{ id: "arkdex_1_gold", count: 100, type: "COIN" }], // reward_daily_task_01
};

/**
 * 交互提交响应（0x38b3116d → 0x38b3116e）
 *
 * 官服无响应样本（抓包会话过短未捕获），按战斗结算响应模式（[seq]{1:100, 2:…}）构造：
 * {1:100, 2:<奖励物品列表>}——客户端领奖展示。mmkabi 引导领奖后推进
 * capture_catch_guide_02 1→2（下一次场景 hello 生效，引导链完成不再重放）。
 */
function buildInteractResp(seq: number, reward: { id: string; count: number; type: string }[]): Buffer {
  const items = reward.map((r) =>
    fb(2, Buffer.concat([fb(1, Buffer.from(r.id, "utf8")), fv(2, r.count), fb(3, Buffer.from(r.type, "utf8"))])),
  );
  const payload = Buffer.concat([fv(1, GW_CODE_OK), ...items]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/* ---------- TCP 服务 ---------- */

/**
 * 启动 arkhub 本地网关应答器（端口自动避让）
 *
 * 监听首选端口，被占（另一实例/其它程序占用）时自动尝试下一个端口（port, port+1, ...
 * 最多 maxPortTries 次，仿 startArkhubGatewayProxy）——多实例并存或端口冲突时各拿一个
 * 空闲端口，enterHall 经 getArkhubLocalGatewayPort() 回报实际端口。监听成功后：
 * 解析客户端帧并应答——登录（任意凭据 code=100，记录 uid 供场景使用）、心跳回显、
 * 场景 hello（合法 EnterSceneNotify——含自己的 PlayerSyncData）、切场景（传送门：
 * 解析目标 map_id 回 ACK + 新场景 EnterSceneNotify，TOWN/CAPTURE 场景切换）、
 * 其余帧最小 ACK。全部帧收发均记录 [arkhub-gateway] 日志（心跳/位置同步为 DEBUG，
 * 其余 INFO 含 hex 预览）。
 * 全部避让端口被占返回 null（本地网关不可用，enterHall 回退官服域名）。
 *
 * @param opts - 监听配置
 * @returns 成功返回 net.Server，全部端口被占返回 null
 */
export function startArkhubLocalGateway(
  opts: ArkhubLocalGatewayOptions = {},
): Promise<net.Server | null> {
  const { port = 30000, resolveNickname, resolvePlayerProfile, maxPortTries = 50 } = opts;
  const handleConnection = (sock: net.Socket): void => {
    let buffer = Buffer.alloc(0);
    // 当前连接的登录 uid（登录帧解析；场景 hello 用它构建自己的玩家条目）
    let loginUid = "";
    // 当前场景 map_id（初始 TOWN；切场景后更新）
    let currentMapId = HALL_MAP_ID;
    // ARKDUEL 战斗开始 seq（结算响应回显用）
    let battleStartSeq = 0;
    // 枢纽 GuideFlags（按连接维护——mmkabi 引导领奖后 capture_catch_guide_02 1→2）
    let guideState = defaultGuideFlags();
    /**
     * 帧日志（完整记录收发——调试枢纽玩法帧协议用）
     *
     * 心跳（main=1）与位置同步（sub low32=38b32a34）为高频噪音帧 → DEBUG；
     * 其余帧 → INFO。日志可读化：已知帧类型显示语义名 + 解析后的字段摘要
     * （protobuf 轻解析），未知帧显示首字节 hex 预览。
     */
    const frameName = (low: string): string => {
      const names: Record<string, string> = {
        "00000fa1": "登录",
        "00000fa2": "登录响应",
        "00000000": "心跳",
        "0de29cdb": "场景hello",
        "38b37d3d": "场景数据",
        "38b3b60b": "切场景",
        "38b3a5a8": "切场景ACK",
        "38b32a34": "位置同步",
        "38b32a35": "位置ACK",
        "38b3360a": "玩家同步",
        "38b31d8f": "位置广播",
        "38b3116d": "交互提交",
        "38b3116e": "交互响应",
        "b7c267d7": "ARKDUEL开始",
        "b7c204e8": "ARKDUEL结算",
        "b7c26451": "ARKDUEL结果",
        "b7c2d119": "ARKDUEL明细",
        "31d603b3": "令牌帧",
        "28f5ba6f": "ARKDUEL商店",
        "38b3ab0c": "交互帧",
        "38b39680": "交互帧",
        "38b3c3c9": "交互帧",
      };
      return names[low] ?? "未知";
    };
    /** protobuf 轻解析为可读字段摘要（field=值，嵌套/字节截断） */
    const summarize = (buf: Buffer, max = 200): string => {
      const parts: string[] = [];
      let p = 0;
      const rv = (): bigint => {
        let v = 0n;
        let s = 0n;
        for (;;) {
          if (p >= buf.length) break;
          const b = buf[p++];
          v |= BigInt(b & 0x7f) << s;
          if (!(b & 0x80)) break;
          s += 7n;
        }
        return v;
      };
      try {
        while (p < buf.length && parts.length < 6) {
          const tag = rv();
          if (tag === 0n) break;
          const f = Number(tag >> 3n);
          const w = Number(tag & 7n);
          if (w === 2) {
            const l = Number(rv());
            if (p + l > buf.length) break;
            const chunk = buf.subarray(p, p + l);
            p += l;
            // 可读文本（完整显示，不截断——交互/令牌帧的 actorId/operationId 需可见）
            const txt = chunk.toString("utf8");
            if (/^[\x20-\x7e\xe4-\xe9][\x20-\x7e\xe4-\xe9\u4e00-\u9fff]*$/.test(txt) && l >= 2 && !chunk.includes(0)) {
              parts.push(`f${f}="${txt}"`);
            } else {
              parts.push(`f${f}[${l}B]`);
            }
          } else if (w === 0) {
            const v = rv();
            const signed = Number(BigInt.asIntN(64, v));
            parts.push(`f${f}=${signed}`);
          } else if (w === 5) {
            if (p + 4 > buf.length) break;
            parts.push(`f${f}=float(${buf.readFloatLE(p).toFixed(2)})`);
            p += 4;
          } else break;
        }
      } catch {
        // 解析失败保留 hex 预览
      }
      const out = parts.join(" ");
      if (out.length > max) return out.slice(0, max) + "…";
      return out;
    };
    const logFrame = (
      dir: "→" | "←",
      mainID: number,
      subID: bigint,
      body: Buffer,
    ): void => {
      const low = (subID & 0xffffffffn).toString(16).padStart(8, "0");
      // 噪音：心跳（main=1 请求 / main=2 响应 sub=0）与位置同步/ACK（38b32a34/35）→ DEBUG
      const noisy =
        mainID === 1 ||
        (mainID === 2 && subID === BigInt(0)) ||
        low === "38b32a34" ||
        low === "38b32a35";
      const name = frameName(low);
      const detail = summarize(body);
      const hex =
        body.length > 32
          ? `hex=${body.toString("hex").slice(0, 32)}…`
          : `hex=${body.toString("hex")}`;
      const line = `${dir} 帧 [${name}] sub=0x${low} len=${body.length} ${detail || hex}`;
      if (noisy) logger.debug("arkhub-gateway", line);
      else logger.info("arkhub-gateway", line);
    };
    const send = (mainID: number, subID: bigint, proto: Buffer): void => {
      if (sock.destroyed) return;
      logFrame("→", mainID, subID, proto);
      sock.write(buildFrame(mainID, subID, proto));
    };
    /** 玩家资料（charId/skinId 供客户端渲染广场玩家模型；缺省回退通用值） */
    const buildProfile = (): {
      nickname: string;
      level: number;
      charId: string;
      skinId: string;
      avatarId?: string;
    } => {
      const nickname = resolveNickname
        ? resolveNickname(loginUid)
        : `博士${loginUid || "1"}`;
      const profile = resolvePlayerProfile
        ? resolvePlayerProfile(loginUid)
        : undefined;
      return {
        nickname: profile?.nickname || nickname,
        level: profile?.level || 1,
        charId: profile?.charId || "",
        skinId: profile?.skinId || "",
        avatarId: profile?.avatarId,
      };
    };
    /** 场景数据帧：EnterSceneNotify（目标 map_id 决定客户端加载场景） */
    const sendScene = (mapId: number): void => {
      send(8, GW_SCENE_DATA, buildEnterScene(loginUid, buildProfile(), mapId, guideState));
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
        logFrame("←", mainID, subID, body);

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
            currentMapId = HALL_MAP_ID;
            logger.info("arkhub-gateway", `本地网关登录: uid=${loginUid || "?"}`);
            send(4, GW_USER_LOGIN_RESP, buildLoginResp(loginUid));
          } else if (mainID === 1) {
            // 心跳：回显 16B（客户端时间戳 + 服务端时间戳）
            const echo = Buffer.alloc(16);
            body.copy(echo, 0, 0, Math.min(body.length, 8));
            echo.writeBigUInt64BE(BigInt(Date.now()), 8);
            send(2, BigInt(0), echo);
          } else if (mainID === 8 && subID === GW_SCENE_HELLO) {
            // 场景 hello（EnterSceneReq）→ 合法 EnterSceneNotify（当前场景 + 自己）
            currentMapId = HALL_MAP_ID;
            logger.info(
              "arkhub-gateway",
              `场景 hello → EnterSceneNotify (uid=${loginUid}, map=${currentMapId})`,
            );
            sendScene(currentMapId);
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_SCENE_SWITCH
          ) {
            // 切场景（传送门）：请求 {1:2, 2:<目标 map_id 有符号 varint>}（官服抓包：
            // 0x38b3b60b → ACK 0x38b3a5a8{f1:9} + 新场景 EnterSceneNotify 0x38b37d3d）
            let targetMapId = currentMapId;
            try {
              let p = 0;
              const rv = (): bigint => {
                let v = 0n;
                let s = 0n;
                for (;;) {
                  const b = body[p++];
                  v |= BigInt(b & 0x7f) << s;
                  if (!(b & 0x80)) break;
                  s += 7n;
                }
                return v;
              };
              while (p < body.length) {
                const tag = rv();
                const field = tag >> 3n;
                const wire = tag & 7n;
                if (wire === 0n) {
                  const v = rv();
                  if (field === 2n) {
                    targetMapId = Number(BigInt.asIntN(64, v));
                  }
                } else break;
              }
            } catch {
              // 解析失败保持原场景
            }
            currentMapId = targetMapId;
            const mapName = CAPTURE_MAP_IDS.includes(targetMapId)
              ? `CAPTURE(${CAPTURE_MAP_IDS.indexOf(targetMapId) + 1})`
              : targetMapId === HALL_MAP_ID
                ? "TOWN"
                : "?";
            logger.info(
              "arkhub-gateway",
              `切场景 → ${mapName} (map=${targetMapId}) uid=${loginUid}`,
            );
            // 官服序列：先小 ACK（{1:9}），再发新场景 EnterSceneNotify
            send(
              8,
              (BigInt("0x2c89b3") << BigInt(32)) | GW_SCENE_SWITCH_ACK,
              Buffer.from([0x08, 0x09]),
            );
            sendScene(currentMapId);
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DUEL_SHOP_REQ
          ) {
            // ARKDUEL 商店：请求体为 [4B seq]（可能带空 f1）→ 返回价格表（0x28f5229c）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            logger.info("arkhub-gateway", `ARKDUEL 商店 → 价格表 (seq=${seq})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_SHOP_RESP,
              buildDuelShopResp(seq),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_TOKEN_REQ
          ) {
            // 令牌刷新：请求 [4B seq] + {1:ts?, 2:旧令牌} → 签发新令牌（0x31d60cf6）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            logger.info("arkhub-gateway", `令牌刷新 → 新令牌 (seq=${seq})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_TOKEN_RESP,
              buildTokenResp(seq),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DUEL_BATTLE_START_REQ
          ) {
            // ARKDUEL 战斗开始：请求 [4B seq] + {1:squad JSON} → 敌方单位响应（0xb7c20f13）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            battleStartSeq = seq;
            logger.info("arkhub-gateway", `ARKDUEL 战斗开始 (seq=${seq}) → 敌方单位`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_BATTLE_START_RESP,
              buildDuelBattleStartResp(),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DUEL_BATTLE_FINISH_REQ
          ) {
            // ARKDUEL 战斗结算：请求 [4B seq] + {1:battleId} → code100 回显（0xb7c2b07e）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            // 解析 battleId（f1 字符串）
            let battleId = "";
            try {
              const payload = body.subarray(4);
              let p = 0;
              const rv2 = (): bigint => {
                let v = 0n;
                let s = 0n;
                for (;;) {
                  if (p >= payload.length) break;
                  const b = payload[p++];
                  v |= BigInt(b & 0x7f) << s;
                  if (!(b & 0x80)) break;
                  s += 7n;
                }
                return v;
              };
              while (p < payload.length) {
                const tag = rv2();
                const field = Number(tag >> 3n);
                const wire = Number(tag & 7n);
                if (wire === 2) {
                  const l = Number(rv2());
                  if (p + l > payload.length) break;
                  if (field === 1) battleId = payload.subarray(p, p + l).toString("utf8");
                  p += l;
                } else if (wire === 0) rv2();
                else break;
              }
            } catch {
              // 解析失败用空 battleId
            }
            // 官服响应 seq 用战斗开始时的 seq（回显开始帧序号）
            const respSeq = battleStartSeq || seq;
            logger.info(
              "arkhub-gateway",
              `ARKDUEL 战斗结算 (seq=${seq}, battleId=${battleId}) → code100 + 结果推送`,
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_BATTLE_FINISH_RESP,
              buildDuelBattleFinishResp(respSeq, battleId),
            );
            // 战斗结果推送（服务端主动下发；官服顺序 0xb7c26451 → 0xb7c2d119）
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_RESULT_PUSH_1,
              buildDuelResultPush1(respSeq),
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_RESULT_PUSH_2,
              buildDuelResultPush2(),
            );
            // 私服奖励挂钩：结算完成 → 服务端发 15 券 + 对战计数（onDuelSettle 由
            // index.ts 注入，经 arkhubOnDuelSettle 落 activity.ARK_HUB + 任务/事件）
            try {
              opts.onDuelSettle?.(loginUid);
            } catch (e) {
              logger.warn("arkhub-gateway", `ARKDUEL 结算奖励处理失败: ${(e as Error).message}`);
            }
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_INTERACT_REQ
          ) {
            // 枢纽交互提交（领奖）：[seq] {1:actorId, 2:operationId("get_reward")}
            // 官服形状（2026-08-14 抓包：arkhub_main_daily_task_02a + get_reward）。
            // 响应 [seq] {1:100, 2:[奖励物品]}（无官服样本，按战斗结算模式构造）。
            // mmkabi 捕抓引导领奖后 capture_catch_guide_02 1→2（下次场景生效，
            // 引导链完成不再重放）。
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            let actorId = "";
            let operationId = "";
            try {
              const payload = body.subarray(4);
              let p = 0;
              const rv2 = (): bigint => {
                let v = 0n;
                let s = 0n;
                for (;;) {
                  if (p >= payload.length) break;
                  const b = payload[p++];
                  v |= BigInt(b & 0x7f) << s;
                  if (!(b & 0x80)) break;
                  s += 7n;
                }
                return v;
              };
              while (p < payload.length) {
                const tag = rv2();
                const field = Number(tag >> 3n);
                const wire = Number(tag & 7n);
                if (wire === 2) {
                  const l = Number(rv2());
                  if (p + l > payload.length) break;
                  const str = payload.subarray(p, p + l).toString("utf8");
                  if (field === 1) actorId = str;
                  else if (field === 2) operationId = str;
                  p += l;
                } else if (wire === 0) rv2();
                else break;
              }
            } catch {
              // 解析失败按空 actor 处理
            }
            const reward = HUB_REWARD_MAP[actorId] ?? [];
            if (actorId === "arkhub_capture1_mmkabi_01b" && guideState.capture_catch_guide_02 === 1) {
              guideState.capture_catch_guide_02 = 2;
              logger.info(
                "arkhub-gateway",
                `捕抓引导完成（mmkabi_01b 领奖）→ capture_catch_guide_02=2，设施已解锁`,
              );
            }
            // 每日物资：服务端记录领取天数 + 发 100 券（onDailySupplyClaimed 由
            // index.ts 注入，经 arkhubOnDailySupply 落 ARK_HUB + 任务事件）
            if (actorId === "arkhub_main_daily_task_02a") {
              try {
                opts.onDailySupplyClaimed?.(loginUid);
              } catch (e) {
                logger.warn("arkhub-gateway", `每日物资处理失败: ${(e as Error).message}`);
              }
            }
            logger.info(
              "arkhub-gateway",
              `交互提交 actor=${actorId} op=${operationId} → 奖励 ${reward.map((r) => `${r.id}x${r.count}`).join(",") || "无"}`,
            );
            send(
              8,
              subID + BigInt(1),
              buildInteractResp(seq, reward),
            );
          } else {
            // 其余玩法帧：回 {f1:100} 业务成功码（main=8，subID+1 对齐 req→resp 的错位规律）
            // ——空 body 会被部分客户端当失败（奖励/交互帧空 ACK → 对话无法完成）；
            // code=100 语义为成功（登录响应同款），客户端可继续流程
            send(8, subID + BigInt(1), Buffer.from([0x08, 0x64]));
          }
        } catch (e) {
          logger.warn("arkhub-gateway", `帧处理失败: ${(e as Error).message}`);
        }
      }
    });

    sock.on("error", (e) => logger.debug("arkhub-gateway", `连接错误: ${e.message}`));
  };

  // 自动避让监听：首选端口被占 → 依次尝试 port, port+1, ...（每次新建 server，避免复用
  // 同一 server 重 listen 的回调错乱）；全部避让端口被占返回 null（enterHall 回退官服）
  return new Promise((resolve) => {
    const tryListen = (p: number, attempt: number): void => {
      const server = net.createServer(handleConnection);
      server.once("error", (e: NodeJS.ErrnoException) => {
        if (e.code === "EADDRINUSE" && attempt + 1 < maxPortTries) {
          tryListen(p + 1, attempt + 1);
          return;
        }
        if (e.code === "EADDRINUSE") {
          logger.warn(
            "arkhub-gateway",
            `端口 ${port}~${p} 均被占用（耗尽 ${maxPortTries} 次避让），本地网关未启动`,
          );
          resolve(null);
          return;
        }
        logger.error("arkhub-gateway", `本地网关启动失败: ${e.message}`);
        resolve(null);
      });
      server.listen(p, () => {
        const actualPort = (server.address() as net.AddressInfo).port;
        _localGatewayActive = true;
        _localGatewayPort = actualPort;
        if (attempt > 0) {
          logger.warn(
            "arkhub-gateway",
            `端口 ${port} 被占用，本地网关避让到 :${actualPort}（客户端可进入空广场）`,
          );
        } else {
          logger.info("arkhub-gateway", `本地网关已监听 :${actualPort}（客户端可进入空广场）`);
        }
        resolve(server);
      });
    };
    tryListen(port, 0);
  });
}
