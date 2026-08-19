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
// 引导 actor → 推进的 GuideFlags 映射（与私服玩法事件模块共用，避免两套映射漂移）
import { ARKHUB_GUIDE_ACTOR_FLAGS } from "@game/manager/activity/arkhub";

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
/**
 * 交互提交 ACK（0x38b38cd6，官服实锤 2026-08-19 抓包）
 * 形状：[4B 请求序号回显] + {1:100}。交互提交后官服下发三帧：
 * 38b38cd6 ACK → 3000ee32 奖励通知 → 38b36462 引导更新广播。
 */
const GW_INTERACT_ACK = BigInt(0x38b38cd6);
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
/**
 * 战斗触发请求（入座/匹配/开始扫描：{1:1}）→ 0xb7c25f13 触发确认 {2:1}
 * （草丛扫描与拟合对决共用此帧开启战斗流程；官服抓包 2026-08-16 实锤）
 */
const GW_BATTLE_TRIGGER_REQ = BigInt(0xb7c21f3a);
const GW_BATTLE_TRIGGER_RESP = BigInt(0xb7c25f13);
/**
 * 草丛遭遇生物上报（扫描特有：{1:生物种类id, 2:个体id}）
 * 客户端走草丛随机遭遇后把个体种类上报服务端——遭遇引擎的遭遇来源（arkdex.ts）。
 */
const GW_SCAN_CREATURE_SELECT = BigInt(0xb7c2369e);
/** 战斗数据上传（客户端编队确认：{1:16B 编队}）→ ACK */
const GW_BATTLE_DATA_UPLOAD = BigInt(0xb7c2cbf4);
/** 战斗确认/准备帧（[8B]）→ ACK */
const GW_BATTLE_CONFIRM = BigInt(0xb7c277bf);
/** 战斗就绪帧（{1:2}）→ ACK */
const GW_BATTLE_READY = BigInt(0xb7c264e3);
/**
 * 战斗结果通知（服务端结算后主动下发：{1:"uid:entity", 2:关卡id, 3:entity,
 * 4:结果, 5:{玩家+敌队策略组}}）——客户端据此结算展示/奖励
 */
const GW_BATTLE_RESULT_NOTIFY = BigInt(0xb7c2ef4f);
/** 战斗结果 ACK（服务端主动下发：{f1:100}） */
const GW_BATTLE_ACK = BigInt(0xb7c2a2e2);
/** 草丛扫描关卡（stage_table：act1arkhub_15 = "奇象收录时间！"） */
const SCAN_STAGE_ID = "act1arkhub_15";
/** 拟合对决关卡（stage_table：act1arkhub_08 = "奇象拟合对战场"） */
const DUEL_STAGE_ID = "act1arkhub_08";
/**
 * 重连登录请求/响应（UserReconnectReq/Resp，main=4）
 * up {1:uid, 2:base64 JWT} → down {1:101（重连成功）}——客户端断线重连用。
 */
const GW_RECONNECT_REQ = BigInt(0x0fa3);
const GW_RECONNECT_RESP = BigInt(0x0fa4);
/**
 * 查看游客（GetBusinessCardReq：{1:游客uid, 2:实体id}）——点击游客查看信息。
 * 单机无真实游客，回 ACK（subID+1）。
 */
const GW_VIEW_PLAYER_REQ = BigInt(0x31d61490);
/**
 * 实体信息查询（{1:实体id}）→ 0x31d67d3e ACK（[4B序号回显] + {1:100}）
 * 31d6d13b / 31d65453 两个 subID 同形（官服分属不同实体类型查询）。
 */
const GW_ENTITY_INFO_REQ_1 = BigInt(0x31d6d13b);
const GW_ENTITY_INFO_REQ_2 = BigInt(0x31d65453);
const GW_ENTITY_INFO_RESP = BigInt(0x31d67d3e);
/**
 * 道具购买（BuyItemReq）→ 0x28f5568f 购买响应（{1:100, 2:?, 3:itemNumId, 4:库存, 5:价格}）
 * 28f56f2c：{1:商店序号, 2:数量}；28f5b1ab：{1:itemNumId, 2:数量}（官服两种形态）。
 * 购买接 arkhubBuyProp（扣券 + 道具箱 +生效次数 + 每日库存限购）。
 */
const GW_BUY_ITEM_REQ_1 = BigInt(0x28f56f2c);
const GW_BUY_ITEM_REQ_2 = BigInt(0x28f5b1ab);
const GW_BUY_ITEM_RESP = BigInt(0x28f5568f);
/** UI/功能页切换（{1:{1:页码}}）→ ACK */
const GW_UI_SWITCH = BigInt(0x38b36054);
/** 表情/动作发送（{1:房间id, 2:表情id}）→ ACK（单机 fire-and-forget） */
const GW_EMOTE = BigInt(0x38b3170a);
/** 定时状态上报（[4B序号] + {1:高分辨率时间戳}）→ ACK */
const GW_STATUS_REPORT = BigInt(0x38b322c3);
/**
 * GuideFlags 广播（服务端引导推进后主动下发）
 * 形状：{2:{1:更新数}, 5:[{1:{1:key, 2:value}}×N]}——客户端据此更新引导状态并结束对话
 * （官服 2026-08-16：mmkabi 领奖后下发 capture_catch_guide_02/01=2）。
 */
const GW_GUIDE_FLAGS_NOTIFY = BigInt(0x38b36462);
/**
 * 奖励/掉落通知（服务端主动下发：{1:类型, 3:生物id列表} / {1:4, 4:npcPixel id}）
 * 草丛扫描结算后下发捕获生物（官服 3000ee32 形状：{1:2, 3:[19026,19016,19060]}）。
 */
const GW_REWARD_NOTIFY = BigInt(0x3000ee32);
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
  /**
   * 可选：按 uid 解析枢纽 GuideFlags（渐进引导/剧情推进）。
   * 返回完整 flag 表（含完成态兜底）；返回 undefined 时用网关默认完成态。
   * 支持异步（动态加载玩法模块场景）——登录后 fire-and-forget 更新，场景 hello 前生效。
   * 缺省不提供 → 维持"全完成态"（不触发任何引导，§25.2c 对齐官服完成态快照）。
   */
  resolveGuideFlags?: (
    uid: string,
  ) => Record<string, number> | undefined | Promise<Record<string, number> | undefined>;
  /**
   * 可选：枢纽引导推进回调（交互帧 actor 命中引导链时；私服据此落持久化 + 出展指引任务）。
   * 与 onDuelSettle/onDailySupplyClaimed 同源（index.ts 注入 arkhub.ts 的 arkhubAdvanceGuide）。
   */
  onGuideAdvance?: (uid: string, actorId: string, operationId: string) => void;
  /**
   * 可选：按 uid 解析玩家当前奇象兑换券数（arkdex_1_gold 持有量）。
   * 引导推进广播（38b36462）的 f2.f1 需携带当前券数（官服实锤：领奖后 f2={1:155,...}）；
   * 私服从 ARK_HUB.act1arkhub.coin 读。缺省返回 0。
   */
  resolveArkDexGold?: (uid: string) => number;
  /**
   * 可选：草丛遭遇/扫描开始回调（战斗触发帧 b7c21f3a 后，捕获区场景时）。
   * 私服据此调 arkhubStartEncounter 生成/记录遭遇（ARK_HUB.arkdexState.activeEncounter），
   * 供结算 arkhubEndScan 做亚种/活动频繁映射。与 onDuelSettle 同源（index.ts 注入）。
   */
  onScanStart?: (uid: string, areaId: number | string) => void;
  /**
   * 可选：草丛扫描结算回调（战斗结算帧 b7c204e8 后，遭遇生物非空时）。
   * capturedNumIds = 客户端 b7c2369e 上报的遭遇生物种类 id 列表——私服据此调
   * arkhubEndScan（扫描成功 15 券 + 数据库收录 + 扫描仪入袋，失败无奖励）。
   */
  onScanSettle?: (uid: string, capturedNumIds: number[]) => void;
  /**
   * 可选：巡展道具购买回调（购买帧 28f56f2c/28f5b1ab 后；私服据此扣券 + 道具箱 +
   * 生效次数 + 每日库存限购——arkhubBuyProp）。
   */
  onBuyProp?: (uid: string, itemNumId: number, count: number) => void;
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

/** 商店条目：{序号, itemNumId, 价格, 每日库存}（购买帧 28f56f2c 按序号、28f5b1ab 按 itemNumId） */
const DUEL_SHOP_ITEMS: Array<[number, number, number, number]> = [
  [1, 5004, 40, 99],
  [2, 5005, 60, 99],
  [3, 5006, 250, 2],
  [4, 5009, 60, 5],
  [5, 5010, 60, 5],
  [6, 5015, 60, 5],
  [7, 5021, 60, 5],
];

/** 商店序号 → itemNumId（购买帧 28f56f2c f1=序号 用） */
const DUEL_SHOP_INDEX_TO_ITEM: Record<number, number> = Object.fromEntries(
  DUEL_SHOP_ITEMS.map(([no, numId]) => [no, numId]),
);

function buildDuelShopResp(seq: number): Buffer {
  const items = DUEL_SHOP_ITEMS.map(([no, numId, price, avail]) =>
    fb(2, Buffer.concat([fv(1, no), fv(2, numId), fv(3, price), fv(4, avail)])),
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

/** 拟合对决默认敌方单位（无遭遇/策略组时兜底；官服响应 f2=生物id, f3=状态位） */
const DUEL_ENEMY_UNITS: Array<[number, number]> = [
  [19005, 64],
  [19005, 256],
  [19005, 2],
  [19005, 32],
  [19005, 512],
];

/**
 * 战斗开始响应（b7c267d7 → b7c20f13，无 seq 前缀）
 * 官服响应：{1:[{2:生物id,3:状态}×5], 2:关卡id, 3:1}
 * - 草丛扫描：关卡 = act1arkhub_15"奇象收录时间！"，敌方 = 遭遇生物（b7c2369e 上报）
 * - 拟合对决：关卡 = act1arkhub_08"奇象拟合对战场"，敌方 = 默认策略敌队
 *
 * @param units - 敌方单位 [{2:生物id, 3:状态}]
 * @param stageId - 关卡 id（扫描/对决）
 */
function buildBattleStartResp(units: Array<[number, number]>, stageId: string): Buffer {
  const u = units.map(([id, flag]) =>
    fb(1, Buffer.concat([fv(2, id), fv(3, flag)])),
  );
  return Buffer.concat([
    fb(1, Buffer.concat(u)),
    fb(2, Buffer.from(stageId, "utf8")),
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
 * 0xb7c26451：[seq] {1:{1:1, 2:ts, 3:[{1:unitId,2:生物id,3:状态}×N]}}
 * 0xb7c2d119：{1:[{1:unitId,2:生物id,3:状态,5:ts}×N], 3:{1:生物id,2:890,3:10}}
 */
function buildDuelResultPush1(seq: number, units: Array<[number, number]>): Buffer {
  const us = units.map(([id, flag], i) =>
    fb(3, Buffer.concat([fv(1, 154 + i), fv(2, id), fv(3, flag)])),
  );
  const payload = Buffer.concat([
    fb(1, Buffer.concat([fv(1, 1), fv(2, BigInt(Date.now())), ...us])),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}
function buildDuelResultPush2(units: Array<[number, number]>): Buffer {
  const us = units.map(([id, flag], i) =>
    fb(1, Buffer.concat([
      fv(1, 154 + i),
      fv(2, id),
      fv(3, flag),
      fv(5, BigInt(Date.now())),
    ])),
  );
  return Buffer.concat([
    ...us,
    fb(3, Buffer.concat([fv(1, units[0]?.[0] ?? 19005), fv(2, 890), fv(3, 10)])),
  ]);
}

/**
 * 战斗结果通知（b7c2ef4f，服务端结算后主动下发；官服形状 2026-08-16 实锤）
 * {1:"uid:entity", 2:关卡id, 3:entity, 4:结果, 5:{1:1, 4:ts, 5:{玩家资料}, 6:{1:?,2:敌队策略组}}}
 * f4 = 结果（官服对决 2/11，私服简化 1=成功 0=失败）；玩家资料含 uid/昵称/等级/出战生物。
 *
 * @param uid - 登录玩家 uid
 * @param stageId - 关卡 id
 * @param entity - 战斗实体 id（会话级，取 uid 稳定值）
 * @param result - 结果码
 * @param enemyGroupId - 敌队策略组 id（strategy_group_*；缺省空）
 */
function buildBattleResultNotify(
  uid: string,
  stageId: string,
  entity: bigint,
  result: number,
  enemyGroupId: string,
): Buffer {
  const uidNum = BigInt(uid || "0") || BigInt(Date.now());
  const playerBrief = Buffer.concat([
    fb(1, Buffer.from(uid, "utf8")),
    fb(2, Buffer.from(`博士${uid || "1"}`, "utf8")),
    fb(3, Buffer.from(String(uidNum & BigInt(9999)), "utf8")),
    fv(8, 1), // 等级（私服简化 1）
  ]);
  const playerInfo = Buffer.concat([
    fv(1, 1),
    fv(4, BigInt(Date.now())),
    fb(5, playerBrief),
    // f6 敌队策略组：{1:1, 2:"strategy_group_*"}
    fb(6, Buffer.concat([fv(1, 1), fb(2, Buffer.from(enemyGroupId, "utf8"))])),
  ]);
  return Buffer.concat([
    fb(1, Buffer.from(`${uid}:${entity.toString()}`, "utf8")),
    fb(2, Buffer.from(stageId, "utf8")),
    fv(3, entity),
    fv(4, result),
    fb(5, playerInfo),
  ]);
}

/** 战斗结果 ACK（b7c2a2e2，服务端主动下发：{1:100}） */
function buildBattleAck(): Buffer {
  return Buffer.from([0x08, GW_CODE_OK]);
}

/**
 * 道具购买响应（28f56f2c/28f5b1ab → 0x28f5568f）
 * 官服形状：[4B seq回显] {1:100, 2:?, 3:itemNumId, 4:剩余库存, 5:价格}。
 *
 * @param seq - 请求序号回显
 * @param itemNumId - 道具 id（商店表校验；不在表内返回 null 由调用方回通用 ACK）
 * @param count - 购买数量
 */
function buildBuyItemResp(seq: number, itemNumId: number, count: number): Buffer | null {
  const entry = DUEL_SHOP_ITEMS.find(([, numId]) => numId === itemNumId);
  if (!entry) return null;
  const [, , price, avail] = entry;
  const payload = Buffer.concat([
    fv(1, GW_CODE_OK),
    fv(2, count),
    fv(3, itemNumId),
    fv(4, Math.max(0, avail - count)), // 剩余库存（每日固定库存减本次购买）
    fv(5, price),
  ]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/**
 * 实体信息查询 ACK（31d6d13b/31d65453 → 0x31d67d3e）
 * 官服形状：[4B 请求序号回显] + {1:100}。单机无真实游客实体，仅确认。
 */
function buildEntityInfoResp(seq: number): Buffer {
  const payload = Buffer.from([0x08, GW_CODE_OK]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, payload]);
}

/**
 * 重连登录响应（0x0fa3 → 0x0fa4）
 * 官服形状：{1:101（重连成功 code）}。重连凭据（base64 JWT）任意放行（私服单账号）。
 */
function buildReconnectResp(): Buffer {
  return Buffer.from([0x08, 101]);
}

/**
 * 奖励/掉落通知（3000ee32，服务端主动下发）
 * 官服形状：{1:2, 3:[生物种类id…]}（草丛扫描结算后下发捕获生物）；
 * 另见 {1:4, 4:"npcPixel_npc_2"}（画像 NPC 奖励）。
 *
 * @param numIds - 奖励生物种类 id 列表
 */
function buildRewardNotify(numIds: number[]): Buffer {
  const ids = (numIds ?? []).map((id) => fv(3, id));
  return Buffer.concat([fv(1, 2), ...ids]);
}

/**
 * 道具奖励通知（3000ee32，交互提交领奖后服务端下发）
 * 官服形状（2026-08-19 shiane_02b 领奖实锤）：{1:1, 2:[{1:奖励id, 2:数量}×N]}。
 * 与 buildRewardNotify（f1=2 生物奖励）区分——f1=1 为道具/物品奖励。
 *
 * @param items - 奖励条目（{id: 数值奖励 id, count: 数量}）
 */
function buildItemRewardNotify(items: Array<{ id: number; count: number }>): Buffer {
  const entries = (items ?? []).map((it) => fb(2, Buffer.concat([fv(1, it.id), fv(2, it.count)])));
  return Buffer.concat([fv(1, 1), ...entries]);
}

/**
 * GuideFlags 广播（38b36462，引导推进后服务端主动下发）
 * 形状对齐官服：{2:{1:当前券数, 2:[{1:奖励道具id, 2:数量}×N]}, 5:[{1:{1:key, 2:value}}×N]}
 * ——官服实锤（2026-08-19 shiane_02b 领奖后 38b36462：f2={1:155, 2:[{1:5012,2:1},
 * {1:5022,2:1}]} 当前券数+本次领奖道具；f5=[capture_update_guide=1]）。
 *
 * @param flags - 本次推进的 GuideFlags（{key: value}）
 * @param gold - 玩家当前奇象兑换券数（arkdex_1_gold 持有量，f2.f1）
 * @param items - 本次领奖道具（{id, count}，f2.f2）
 */
function buildGuideFlagsNotify(
  flags: Record<string, number>,
  gold = 0,
  items: Array<{ id: number; count: number }> = [],
): Buffer {
  const entries = Object.entries(flags).map(([key, val]) =>
    fb(5, Buffer.concat([fb(1, Buffer.from(key, "utf8")), fv(2, val)])),
  );
  const f2 = Buffer.concat([
    fv(1, gold),
    ...(items ?? []).map((it) => fb(2, Buffer.concat([fv(1, it.id), fv(2, it.count)]))),
  ]);
  return Buffer.concat([fb(2, f2), ...entries]);
}

/* ---------- 枢纽交互提交（0x38b3116d：{1:actorId, 2:operationId("get_reward")}） ---------- */

/** 枢纽 actor → 领奖奖励（activity.ARK_HUB.rewardDataDict 映射；据官服/抓包） */
const HUB_REWARD_MAP: Record<string, { id: string; count: number; type: string }[]> = {
  // 夏妮引导（capture_catch_guide_01）：mmkabi 同款引导奖励 reward_guide_01（×50 券）
  arkhub_main_shiane_02b: [{ id: "arkdex_1_gold", count: 50, type: "COIN" }],
  arkhub_capture1_mmkabi_01b: [{ id: "arkdex_1_gold", count: 50, type: "COIN" }], // reward_guide_01
  arkhub_main_daily_task_02a: [{ id: "arkdex_1_gold", count: 100, type: "COIN" }], // reward_daily_task_01
};

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
     * 战斗流程状态（草丛扫描 / 拟合对决共用 b7c2* 链路，官服抓包 2026-08-16 实锤）：
     * - phase：idle（无战斗）→ triggered（b7c21f3a 触发）→ battling（b7c267d7 开始）→ settled（b7c204e8 结算）
     * - encounterCreatures：草丛遭遇生物种类 id（客户端 b7c2369e 上报；扫描敌队 + 结算捕获来源）
     */
    let battlePhase: "idle" | "triggered" | "battling" | "settled" = "idle";
    let encounterCreatures: number[] = [];
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
        "0de29cdb": "场景hello", // 兼容旧 key
        "4de29cdb": "场景hello",
        "38b37d3d": "场景数据",
        "38b3b60b": "切场景",
        "38b3a5a8": "切场景ACK",
        "38b32a34": "位置同步",
        "38b32a35": "位置ACK",
        "38b3360a": "玩家同步",
        "38b31d8f": "位置广播",
        "38b3116d": "交互提交",
        "38b3116e": "交互响应",
        "38b38cd6": "交互ACK",
        "38b36462": "GuideFlags广播",
        "3000ee32": "奖励通知",
        "b7c267d7": "ARKDUEL开始",
        "b7c204e8": "ARKDUEL结算",
        "b7c26451": "ARKDUEL结果",
        "b7c2d119": "ARKDUEL明细",
        "b7c21f3a": "战斗触发",
        "b7c25f13": "战斗触发确认",
        "b7c2369e": "遭遇生物上报",
        "b7c2cbf4": "战斗数据上传",
        "b7c277bf": "战斗确认",
        "b7c264e3": "战斗就绪",
        "b7c2ef4f": "战斗结果通知",
        "b7c2a2e2": "战斗结果ACK",
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
      // 官服进图后不发 38b36462（场景帧 GuideFlags 即初始引导状态，客户端从场景帧读取；
      // 38b36462 仅在交互提交/引导推进后下发——2026-08-19 capture 会话实锤）
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
            // 渐进引导：登录后按 uid 解析 GuideFlags（persisted，缺省回退完成态）。
            // 支持异步回调（动态加载玩法模块）——fire-and-forget，场景 hello 前生效。
            // 未配置 resolveGuideFlags 时维持默认完成态（不触发任何引导）。
            const guideResolved = opts.resolveGuideFlags?.(loginUid);
            if (guideResolved && typeof (guideResolved as Promise<unknown>).then === "function") {
              (guideResolved as Promise<Record<string, number> | undefined>)
                .then((flags) => {
                  if (flags) guideState = flags;
                })
                .catch((e: Error) =>
                  logger.warn("arkhub-gateway", `GuideFlags 解析失败: ${e.message}`),
                );
            } else if (guideResolved) {
              guideState = guideResolved as Record<string, number>;
            }
            logger.info("arkhub-gateway", `本地网关登录: uid=${loginUid || "?"}`);
            send(4, GW_USER_LOGIN_RESP, buildLoginResp(loginUid));
          } else if (mainID === 4 && subID === GW_RECONNECT_REQ) {
            // 重连登录（UserReconnectReq：{1:uid, 2:base64 JWT}）→ {1:101} 重连成功
            // 私服单账号：任意凭据放行（重连凭据由登录帧 field3 签发，客户端断线重连用）
            loginUid = "";
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
                if (field === 1) loginUid = body.subarray(p, p + l).toString("utf8");
                p += l;
              } else if (wire === 0) {
                for (;;) {
                  const byte = body[p++];
                  if (!(byte & 0x80)) break;
                }
              } else break;
            }
            logger.info("arkhub-gateway", `本地网关重连登录: uid=${loginUid || "?"}`);
            send(4, GW_RECONNECT_RESP, buildReconnectResp());
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
            (subID & 0xffffffffn) === GW_BATTLE_TRIGGER_REQ
          ) {
            // 战斗触发（入座/匹配/开始扫描）：{1:1} → 触发确认（0xb7c25f13 {2:1}）
            // 官服形状（2026-08-16 抓包）：b7c21f3a {1:1} → b7c25f13 {2:1}。
            // 捕获区触发 = 草丛扫描流程开始 → 服务端生成/记录遭遇（onScanStart → arkhubStartEncounter）。
            battlePhase = "triggered";
            if (CAPTURE_MAP_IDS.includes(currentMapId)) {
              try {
                opts.onScanStart?.(loginUid, currentMapId);
              } catch (e) {
                logger.warn("arkhub-gateway", `草丛遭遇生成失败: ${(e as Error).message}`);
              }
            }
            logger.info(
              "arkhub-gateway",
              `战斗触发 (map=${currentMapId}) → 确认 (uid=${loginUid || "?"})`,
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_BATTLE_TRIGGER_RESP,
              Buffer.from([0x10, 0x01]), // {2:1}
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_SCAN_CREATURE_SELECT
          ) {
            // 草丛遭遇生物上报：{1:生物种类id, 2:个体id}（官服 2026-08-16：{19058, 4}）
            // 记录为本次扫描的遭遇生物（战斗开始敌方 + 结算捕获来源）。
            let creatureId = 0;
            try {
              const payload = body.subarray(0);
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
                if (wire === 0) {
                  const v = rv2();
                  if (field === 1) creatureId = Number(v);
                } else if (wire === 2) {
                  const l = Number(rv2());
                  p += l;
                } else break;
              }
            } catch {
              // 解析失败忽略
            }
            if (creatureId > 0 && !encounterCreatures.includes(creatureId)) {
              encounterCreatures.push(creatureId);
            }
            if (battlePhase === "idle") battlePhase = "triggered";
            logger.info(
              "arkhub-gateway",
              `遭遇生物上报: ${creatureId}（累计 ${encounterCreatures.length} 种）`,
            );
            // 无官服响应样本；回 ACK {1:100}（subID+1，与通用兜底同形状）
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BATTLE_DATA_UPLOAD ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BATTLE_CONFIRM ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BATTLE_READY
          ) {
            // 战斗数据上传（编队确认 {1:16B}）/ 战斗确认（[8B]）/ 战斗就绪（{1:2}）
            // ——官服多为 fire-and-forget 或回显，本地回 ACK {1:100} 即可
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DUEL_BATTLE_START_REQ
          ) {
            // 战斗开始：请求 [4B seq] + {1:squad JSON} → 敌方单位响应（0xb7c20f13）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            battleStartSeq = seq;
            battlePhase = "battling";
            // 草丛扫描：敌方 = 遭遇生物（b7c2369e 上报）+ act1arkhub_15"奇象收录时间！"；
            // 拟合对决：敌方 = 默认策略敌队 + act1arkhub_08"奇象拟合对战场"
            const isScan = encounterCreatures.length > 0;
            const units: Array<[number, number]> = isScan
              ? (encounterCreatures.map((id, i) => [id, 32 + i]) as Array<[number, number]>)
              : DUEL_ENEMY_UNITS;
            const stageId = isScan ? SCAN_STAGE_ID : DUEL_STAGE_ID;
            logger.info(
              "arkhub-gateway",
              `战斗开始 (seq=${seq}, ${isScan ? "草丛扫描" : "拟合对决"}) → 敌方 ${units.map(([id]) => id).join(",")} (${stageId})`,
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_BATTLE_START_RESP,
              buildBattleStartResp(units, stageId),
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
            battlePhase = "settled";
            // 草丛扫描 vs 拟合对决（遭遇生物非空 = 扫描；敌方单位/关卡按此区分）
            const isScan = encounterCreatures.length > 0;
            const units: Array<[number, number]> = isScan
              ? (encounterCreatures.map((id, i) => [id, 32 + i]) as Array<[number, number]>)
              : DUEL_ENEMY_UNITS;
            const stageId = isScan ? SCAN_STAGE_ID : DUEL_STAGE_ID;
            logger.info(
              "arkhub-gateway",
              `战斗结算 (seq=${seq}, battleId=${battleId}, ${isScan ? "草丛扫描" : "拟合对决"}) → code100 + 结果推送`,
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
              buildDuelResultPush1(respSeq, units),
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_DUEL_RESULT_PUSH_2,
              buildDuelResultPush2(units),
            );
            // 战斗结果通知 + ACK（服务端主动下发；客户端据此结算展示/奖励）
            const battleEntity =
              (BigInt.asUintN(64, BigInt(loginUid || "0") || BigInt(Date.now())) |
                (BigInt(1) << BigInt(40)));
            send(
              8,
              (subID & ~0xffffffffn) | GW_BATTLE_RESULT_NOTIFY,
              buildBattleResultNotify(loginUid, stageId, battleEntity, 1, ""),
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_BATTLE_ACK,
              buildBattleAck(),
            );
            // 私服奖励挂钩：
            // - 草丛扫描（遭遇生物非空）：发 15 券 + 数据库收录 + 扫描仪入袋
            //   （onScanSettle 由 index.ts 注入，经 arkhubEndScan 落 ARK_HUB + 任务/勋章事件）
            // - 拟合对决：发 15 券 + 对战计数（onDuelSettle → arkhubOnDuelSettle）
            if (isScan) {
              const captured = [...encounterCreatures];
              // 草丛扫描结算：下发奖励/掉落通知（3000ee32，捕获生物列表）
              send(
                8,
                (subID & ~0xffffffffn) | GW_REWARD_NOTIFY,
                buildRewardNotify(captured),
              );
              try {
                opts.onScanSettle?.(loginUid, captured);
              } catch (e) {
                logger.warn("arkhub-gateway", `草丛扫描结算奖励处理失败: ${(e as Error).message}`);
              }
              // 本场遭遇已结算，清理（下一次 b7c2369e 重新上报）
              encounterCreatures = [];
            } else {
              try {
                opts.onDuelSettle?.(loginUid);
              } catch (e) {
                logger.warn("arkhub-gateway", `ARKDUEL 结算奖励处理失败: ${(e as Error).message}`);
              }
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
            // 引导推进：命中引导 actor（shiane 夏妮/mmkabi 捕抓/bryota 对决引导）→ 本连接
            // guideState 同步 + 通知私服落持久化/出展指引任务（onGuideAdvance 由
            // index.ts 注入 arkhubAdvanceGuide）。引导推进后服务端主动下发 GuideFlags
            // 广播（38b36462）——客户端据此更新引导状态并结束当前对话（官服同款）。
            const guideFlags = ARKHUB_GUIDE_ACTOR_FLAGS[actorId];
            let guideBroadcast: Buffer | null = null;
            if (guideFlags) {
              for (const [key, value] of Object.entries(guideFlags)) {
                guideState[key] = Math.max(guideState[key] ?? 0, value as number);
              }
              // 引导更新广播 key = capture_update_guide=1（官服实锤 2026-08-19：shiane_02b
              // 领奖后 38b36462 广播 capture_update_guide=1，而非把 capture_catch_guide_01/02
              // 直接置 2——客户端收到该标记后重新读取引导状态并结束当前对话）。
              // f2 对齐官服：{1: 当前券数, 2:[本次领奖道具 5012/5022]}（官服 f2={1:155,2:[...]}）
              const gold = opts.resolveArkDexGold?.(loginUid) ?? 0;
              guideBroadcast = buildGuideFlagsNotify(
                { capture_update_guide: 1 },
                gold,
                [
                  { id: 5012, count: 1 },
                  { id: 5022, count: 1 },
                ],
              );
              try {
                opts.onGuideAdvance?.(loginUid, actorId, operationId);
              } catch (e) {
                logger.warn("arkhub-gateway", `引导推进处理失败: ${(e as Error).message}`);
              }
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
            // 交互提交响应三帧（官服实锤 2026-08-19 shiane_02b 领奖抓包）：
            // ① 38b38cd6 通用 ACK（[seq回显]{1:100}）
            // ② 3000ee32 道具奖励通知（{1:1, 2:[{1:5012,2:1},{1:5022,2:1}]}）
            // ③ 38b36462 引导更新广播（capture_update_guide=1）
            // 客户端据 ACK 确认领奖成功、据 3000ee32 展示奖励、据广播结束对话。
            send(8, (subID & ~0xffffffffn) | GW_INTERACT_ACK, buildEntityInfoResp(seq));
            send(
              8,
              (subID & ~0xffffffffn) | GW_REWARD_NOTIFY,
              buildItemRewardNotify([
                { id: 5012, count: 1 },
                { id: 5022, count: 1 },
              ]),
            );
            if (guideBroadcast) {
              send(
                8,
                (subID & ~0xffffffffn) | GW_GUIDE_FLAGS_NOTIFY,
                guideBroadcast,
              );
            }
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_VIEW_PLAYER_REQ
          ) {
            // 查看游客（GetBusinessCardReq：{1:游客uid, 2:实体id}）→ ACK（单机无真实游客）
            let viewerUid = "";
            try {
              let p = 0;
              const rv2 = (): bigint => {
                let v = 0n;
                let s = 0n;
                for (;;) {
                  if (p >= body.length) break;
                  const b = body[p++];
                  v |= BigInt(b & 0x7f) << s;
                  if (!(b & 0x80)) break;
                  s += 7n;
                }
                return v;
              };
              while (p < body.length) {
                const tag = rv2();
                const field = Number(tag >> 3n);
                const wire = Number(tag & 7n);
                if (wire === 2) {
                  const l = Number(rv2());
                  if (p + l > body.length) break;
                  if (field === 1) viewerUid = body.subarray(p, p + l).toString("utf8");
                  p += l;
                } else if (wire === 0) rv2();
                else break;
              }
            } catch {
              // 解析失败按空 uid
            }
            logger.info("arkhub-gateway", `查看游客 uid=${viewerUid || "?"} → ACK`);
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BUY_ITEM_REQ_1 ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BUY_ITEM_REQ_2
          ) {
            // 道具购买（BuyItemReq）→ 0x28f5568f 购买响应 + onBuyProp（扣券/道具箱/库存）
            // 28f56f2c：{1:商店序号, 2:数量}；28f5b1ab：{1:itemNumId, 2:数量}
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            const payload = body.subarray(4);
            let f1 = 0;
            let count = 1;
            try {
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
                if (wire === 0) {
                  const v = rv2();
                  if (field === 1) f1 = Number(v);
                  else if (field === 2) count = Number(v);
                } else if (wire === 2) {
                  const l = Number(rv2());
                  p += l;
                } else break;
              }
            } catch {
              // 解析失败按默认
            }
            // 商店序号（28f56f2c）→ itemNumId；28f5b1ab f1 即 itemNumId
            const isIndexForm = (subID & 0xffffffffn) === GW_BUY_ITEM_REQ_1;
            const itemNumId = isIndexForm ? (DUEL_SHOP_INDEX_TO_ITEM[f1] ?? 0) : f1;
            if (itemNumId > 0) {
              const resp = buildBuyItemResp(seq, itemNumId, Math.max(1, count));
              if (resp) {
                logger.info("arkhub-gateway", `道具购买 itemNumId=${itemNumId} ×${count} → 响应`);
                send(
                  8,
                  (subID & ~0xffffffffn) | GW_BUY_ITEM_RESP,
                  resp,
                );
                try {
                  opts.onBuyProp?.(loginUid, itemNumId, Math.max(1, count));
                } catch (e) {
                  logger.warn("arkhub-gateway", `道具购买处理失败: ${(e as Error).message}`);
                }
                continue;
              }
            }
            // 未知道具 → 通用 ACK
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_ENTITY_INFO_REQ_1 ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_ENTITY_INFO_REQ_2
          ) {
            // 实体信息查询（{1:实体id}）→ 0x31d67d3e [4B序号回显]{1:100}（单机无游客实体）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            logger.info("arkhub-gateway", `实体信息查询 (seq=${seq}) → ACK`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_ENTITY_INFO_RESP,
              buildEntityInfoResp(seq),
            );
          } else if (
            mainID === 8 &&
            ((subID & 0xffffffffn) === GW_UI_SWITCH ||
              (subID & 0xffffffffn) === GW_EMOTE ||
              (subID & 0xffffffffn) === GW_STATUS_REPORT)
          ) {
            // UI/功能页切换（{1:{1:页码}}）/ 表情发送（{1:房间,2:表情}）/ 状态上报
            // （[4B序号]+时间戳）——单机 fire-and-forget，回 ACK 即可
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            logger.debug("arkhub-gateway", `交互帧 ACK (sub=0x${(subID & 0xffffffffn).toString(16)}, seq=${seq})`);
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
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
