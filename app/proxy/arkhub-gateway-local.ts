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
import {
  allocPixelArtId,
  pixelMeta,
  registerPixelUploadToken,
  deletePixel,
  listPixelsByUid,
  ARKPIXEL_MAX_PUBLISH,
} from "@game/manager/activity/arkpixel";

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
/** 像素上传 token 请求（RequestPixelArtUploadTokenReq：{1:pixel_art_id, 2:md5}）→ 0x31d60cf6 凭据 */
const GW_PIXEL_UPLOAD_TOKEN_REQ = BigInt(0x31d603b3);
const GW_PIXEL_UPLOAD_TOKEN_RESP = BigInt(0x31d60cf6);
/** 捕捉信息查询（GetCaptureInfoReq，low32）→ GetCaptureInfoResp */
const GW_CAPTURE_INFO_REQ = BigInt(0xb7c2ad8b);
const GW_CAPTURE_INFO_RESP = BigInt(0xb7c2b4de);
/** 捕捉开始（StartCaptureReq）→ StartCaptureResp，随后服务端主动推 EncounterCreatureNotify */
const GW_START_CAPTURE_REQ = BigInt(0xb7c267d7);
const GW_START_CAPTURE_RESP = BigInt(0xb7c2b07e);
const GW_ENCOUNTER_CREATURE_NOTIFY = BigInt(0xb7c20f13);
/** 捕捉结束（EndCaptureReq）→ EndCaptureResp（ArkDexSettleInfo 结算） */
const GW_END_CAPTURE_REQ = BigInt(0xb7c204e8);
const GW_END_CAPTURE_RESP = BigInt(0xb7c26451);
/** 对局入座（JoinDuelReq）→ JoinDuelResp；入座后服务端主动推 OnJoinDuelNotify */
const GW_JOIN_DUEL_REQ = BigInt(0xb7c277bf);
const GW_JOIN_DUEL_RESP = BigInt(0xb7c2a2e2);
const GW_ON_JOIN_DUEL_NOTIFY = BigInt(0xb7c2ef4f);
/** 取消对局（CancelDuelReq）→ ACK */
const GW_CANCEL_DUEL_REQ = BigInt(0xb7c21661);
/** 对局开始（StartDuelReq）→ StartDuelResp{code} */
const GW_START_DUEL_REQ = BigInt(0xf8faa515);
const GW_START_DUEL_RESP = BigInt(0xf8fa2dce);
/** 回合准备 / 战报上传 / 加载完成 / 离开对局（服务端 fire-and-forget → ACK） */
const GW_ROUND_PREPARE_REQ = BigInt(0xf8fa9c6e);
const GW_UPLOAD_BATTLE_DATA_REQ = BigInt(0xf8faab16);
const GW_LOADING_FINISH_REQ = BigInt(0xf8faf090);
const GW_LEAVE_DUEL_REQ = BigInt(0xf8fad282);
/** 对局回合结算上报（DuelRoundResultReportReq）→ onDuelSettle（对局结算发券）+ ACK */
const GW_DUEL_ROUND_RESULT_REPORT_REQ = BigInt(0xf8fa293a);
/** 交换信息（GetAllCreatureExchangeInfoReq）→ GetAllCreatureExchangeInfoResp（本地空状态） */
const GW_GET_ALL_EXCHANGE_INFO_REQ = BigInt(0xb7c21f3a);
const GW_GET_ALL_EXCHANGE_INFO_RESP = BigInt(0xb7c25f13);
/** 预设交换 / 发起交换 / 应答交换（单机无真实玩家 → ACK） */
const GW_PRESET_EXCHANGE_REQ = BigInt(0xb7c2369e);
const GW_CREATE_EXCHANGE_REQ = BigInt(0xb7c2394d);
const GW_ANSWER_EXCHANGE_REQ = BigInt(0xb7c2be4f);
/** 交换状态广播（CreatureExchangeStateNotify，收到仅记录日志） */
const GW_EXCHANGE_STATE_NOTIFY = BigInt(0xb7c283a3);
/** 生物管理请求（单机本地回官方 resp 或 {1:100} ACK） */
const GW_DELETE_CREATURE_REQ = BigInt(0xb7c264e3);
const GW_SET_CREATURE_LIKE_REQ = BigInt(0xb7c28d19);
const GW_SET_FOLLOWING_CREATURE_REQ = BigInt(0xb7c20b13);
const GW_SET_CREATURE_SQUAD_REQ = BigInt(0xb7c2cbf4);
/** 生物变更广播（CreatureAlterNotify，收到仅记录日志） */
const GW_CREATURE_ALTER_NOTIFY = BigInt(0xb7c2d119);
/** 巡展捕抓关卡（stage_table：act1arkhub_15 = "奇象收录时间！"） */
const SCAN_STAGE_ID = "act1arkhub_15";
/** 拟合对局关卡（stage_table：act1arkhub_08 = "奇象拟合对战场"） */
const DUEL_STAGE_ID = "act1arkhub_08";
/**
 * 私服本地捕捉遭遇生物兜底（StartCaptureReq 时 encounterCreatures 为空则回填，
 * 用于 EncounterCreatureNotify 推送与 onScanSettle 结算入参——单机无真实随机遭遇）。
 */
const CAPTURE_ENCOUNTER_CREATURES: number[] = [19005, 19016, 19060];
/**
 * 重连登录请求/响应（UserReconnectReq/Resp，main=4）
 * up {1:uid, 2:base64 JWT} → down {1:101（重连成功）}——客户端断线重连用。
 */
const GW_RECONNECT_REQ = BigInt(0x0fa3);
const GW_RECONNECT_RESP = BigInt(0x0fa4);
/**
 * 像素保存确认（SavePixelArtReq：{1:pixel_art_id, 2:upload_success, 3:do_publish}，
 * HTTP savePixelArt 成功后客户端发——官方 fire-and-forget 无 ACK）→ 随后服务端
 * 主动推 PixelArtDataAlterNotify（0x31d62bbd）通知像素数据变更，客户端据此确认保存。
 */
const GW_SAVE_PIXEL_ART_REQ = BigInt(0x31d674d5);
const GW_PIXEL_DATA_ALTER_NOTIFY = BigInt(0x31d62bbd);
/** 收集画像（CollectPixelArtReq：{1:target_uid, 2:pixel_art_id}）——单机无真实匿名画像，
 * 记录日志后回 {1:100} ACK（subID+1）。 */
const GW_COLLECT_PIXEL_REQ = BigInt(0x31d61490);
/**
 * 删除像素 / 删除像素收藏（DeletePixelArtReq / DeletePixelArtCollectionReq，均
 * {1:pixel_art_id}）→ 各自独立的 Resp（{1:code=100}）。
 */
const GW_DELETE_PIXEL_REQ = BigInt(0x31d6d13b);
const GW_DELETE_PIXEL_RESP = BigInt(0x31d67d3e);
const GW_DELETE_PIXEL_COLLECTION_REQ = BigInt(0x31d65453);
const GW_DELETE_PIXEL_COLLECTION_RESP = BigInt(0x31d6ea56);
/**
 * 道具购买（BuyItemReq → 店铺按序号）→ 0x28f5568f 购买响应（{1:100, 2:index, 3:item_id,
 * 4:数量, 5:价格, 6:当前券数}）——28f56f2c：{1:商店序号, 2:数量}，接 arkhubBuyProp
 * （扣券 + 道具箱 + 生效次数 + 每日库存限购）。用道具另见 GW_USE_ITEM_REQ(28f5b1ab)。
 */
const GW_BUY_ITEM_REQ_1 = BigInt(0x28f56f2c);
const GW_BUY_ITEM_RESP = BigInt(0x28f5568f);
/** 使用道具（UseItemReq：{1:item_id, 2:count}）→ UseItemResp 0x28f5de74 {1:code=100} */
const GW_USE_ITEM_REQ = BigInt(0x28f5b1ab);
const GW_USE_ITEM_RESP = BigInt(0x28f5de74);
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
   * 可选：按 uid 解析玩家奇象展册户籍数据（ARK_HUB.act1arkhub：dex/scanBag/coin/道具箱）。
   * 场景帧（EnterSceneNotify）的 PlayerSyncData 据此构造 f5-f9（生物图鉴/道具/像素/状态/功能位）
   * ——客户端没有这些字段时"数据库/功能"显示未解锁（户籍裁剪）。
   * 返回 undefined 时维持现状（场景帧不带 f5-f9，不影响既有用例）。
   */
  resolveArkdexDocs?: (uid: string) => ArkdexDocsData | undefined;
  /**
   * 可选：捕捉开始回调（StartCaptureReq b7c267d7 后，捕获区场景时）。
   * 私服据此调 arkhubStartEncounter 生成/记录遭遇（ARK_HUB.arkdexState.activeEncounter），
   * 供结算 arkhubEndScan 做亚种/活动频繁映射。与 onDuelSettle 同源（index.ts 注入）。
   */
  onScanStart?: (uid: string, areaId: number | string) => void;
  /**
   * 可选：捕捉结算回调（EndCaptureReq b7c204e8 后，遭遇生物非空时）。
   * capturedNumIds = 本次遭遇生物种类 id（encounterCreatures）——私服据此调
   * arkhubEndScan（扫描成功 15 券 + 数据库收录 + 扫描仪入袋，失败无奖励）。
   */
  onScanSettle?: (uid: string, capturedNumIds: number[]) => void;
  /**
   * 可选：巡展道具购买回调（购买帧 28f56f2c/28f5b1ab 后；私服据此扣券 + 道具箱 +
   * 生效次数 + 每日库存限购——arkhubBuyProp）。
   */
  onBuyProp?: (uid: string, itemNumId: number, count: number) => void;
}

/**
 * 玩家奇象展册户籍数据（EnterSceneNotify PlayerSyncData f5-f9 的数据源）。
 * 来源：私服存档 ARK_HUB.act1arkhub（dex 图鉴收录 / scanBag 持有个体 / coin 券 / props 道具箱）。
 */
export interface ArkdexDocsData {
  /** 图鉴收录种类集（key = numId 字符串，value 计 1/可忽略 → CreatureCollection.template_id） */
  dex: Record<string, number>;
  /** 持有的生物个体（→ Creature：id→unique_id，numId→template_id，source→source） */
  scanBag: Array<{ id: number; numId: number; persona?: number; source?: string }>;
  /** 奇象兑换券（→ ArkhubItemData.coin） */
  coin: number;
  /** 巡展道具箱（→ ArkhubItemData.items[item_id, count]；可空） */
  items?: Array<{ itemId: number; count: number }>;
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
  arkdocs?: ArkdexDocsData,
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
  // PlayerBrief：1~3 基本，4=level，5=channel，6=charater，7=skin（权威字段名 §10；
  // PlayerBrief 无 avatarId 字段——玩家形象走下方 Avatar f3/f4 = secretary/secretary_skin_id）
  const playerBrief = Buffer.concat([
    fb(1, Buffer.from(uid, "utf8")),
    fb(2, Buffer.from(profile.nickname, "utf8")),
    fb(3, Buffer.from(String(uidNum & BigInt(9999)), "utf8")),
    fv(4, profile.level || 1),
    fv(5, 1), // channel（登录渠道，官方 f5；原注释误标 avatarId）
    fb(6, Buffer.from(profile.charId, "utf8")),
    fb(7, Buffer.from(profile.skinId, "utf8")),
  ]);
  // Avatar：{1:type="ICON", 2:avatar_id, 3:secretary(代表干员), 4:secretary_skin_id(秘书皮肤)}（§10）
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
  // 户籍裁剪：配置 resolveArkdexDocs 时补 f5-f9（客户端据此渲染生物图鉴/道具/功能位，
  // 否则"数据库等"显示未解锁）。缺省/未配置时维持现状（不带 f5-f9，不影响既有用例）。
  const syncParts = [
    fb(1, playerBrief),
    fb(2, avatarInfo),
    fb(3, guideFlags),
    fb(4, gameAttrs),
  ];
  if (arkdocs) {
    syncParts.push(fb(5, buildCreatureData(arkdocs)));
    syncParts.push(fb(6, buildArkhubItemData(arkdocs)));
    syncParts.push(fb(7, buildPixelArtData(uid)));
    syncParts.push(fb(8, buildBuffDoc()));
    syncParts.push(fb(9, buildFeatureDoc()));
  }
  const playerSync = Buffer.concat(syncParts);
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

/* ---------- PlayerSyncData f5-f9 户籍构建（奇象展册，字段号对齐官服逆向） ---------- */

/**
 * 生物图鉴数据（PlayerSyncData.f5 CreatureData）
 * 官方结构：f1 creatures[]（Creature），f2 collections[]（CreatureCollection）。
 * - Creature: f1 unique_id(ulong), f2 template_id(uint), f3 persona(uint), f4 likely(uint),
 *   f5 gain_time(ulong), f6 source(string)
 * - CreatureCollection: f1 template_id(uint), f2 persona(uint), f3 caught_count(uint),
 *   f4 victories(uint)
 * dex 每种收录 → collections 一条 CreatureCollection（template_id=numId）；scanBag 每个持有个体
 * → creatures 一条 Creature（unique_id=个体id，template_id=numId）。
 */
function buildCreatureData(docs: ArkdexDocsData): Buffer {
  const creatures = (docs.scanBag ?? []).map((b) =>
    fb(1, Buffer.concat([
      fv(1, BigInt(b.id)), // unique_id
      fv(2, b.numId), // template_id
      fv(3, b.persona ?? 0), // persona
      fv(5, BigInt(Date.now())), // gain_time
      ...(b.source ? [fb(6, Buffer.from(b.source, "utf8"))] : []), // source(string)
    ])),
  );
  const collections = Object.keys(docs.dex ?? {}).map((numId) =>
    fb(2, Buffer.concat([
      fv(1, Number(numId)), // template_id
      fv(3, 1), // caught_count
    ])),
  );
  return Buffer.concat([...creatures, ...collections]);
}

/**
 * 道具数据（PlayerSyncData.f6 ArkhubItemData）
 * 官方结构：f1 coin(int)，f2 items[]（ArkhubItem{1:item_id(int), 2:count(int)}）。
 * coin = 奇象兑换券；无道具箱则 items 为空。
 */
function buildArkhubItemData(docs: ArkdexDocsData): Buffer {
  const items = (docs.items ?? []).map((it) =>
    fb(2, Buffer.concat([fv(1, it.itemId), fv(2, it.count)])),
  );
  return Buffer.concat([fv(1, docs.coin ?? 0), ...items]);
}

/**
 * 像素画条目（PixelArtInfo，PixelArtData.f1 creations[] / PixelArtDataAlterNotify.f1）
 * 权威字段（PixelArtInfo_metadata）：f1 id(ulong)、f2 md5(string)、f3 status(uint)、
 * f4 create_time(int64)、f5 update_time(int64)、f6 publish_time(int64)、
 * f7 revision(uint)、f8 collected_count(uint)。
 *
 * @param id - 像素 id
 * @param md5 - 像素数据 md5
 * @param ts - 创建/更新时间（秒级时间戳）
 * @returns PixelArtInfo 消息体
 */
function buildPixelArtInfo(id: number, md5: string, ts: number): Buffer {
  return Buffer.concat([
    fv(1, BigInt(id)),
    fb(2, Buffer.from(md5 || "", "utf8")),
    fv(3, 1), // status（1=正常）
    fv(4, BigInt(ts)), // create_time
    fv(5, BigInt(ts)), // update_time
    fv(6, BigInt(ts)), // publish_time
    fv(7, 1), // revision
  ]);
}

/**
 * 像素画数据（PlayerSyncData.f7 PixelArtData）
 * 权威字段（PixelArtData_metadata）：f1 creations[](PixelArtInfo)、f2 collections[]、
 * f3 display_pixel_art_id、f4 show_nickname、f5 album_display_id、f6 obtained_npc_pixel_arts、
 * f7 remaining_publish_count(int)、f8 last_refresh_time(int64)、f9 claimed_grants、f10 hide_display。
 * ⚠️ 此前返回空容器 → 客户端读不到 creations 与 remaining_publish_count → "每次保存都新建
 * 一幅画"（列表空，重传不带 id）+ "发布次数为 0，无法发布"（f7 缺失）。现按像素索引构造。
 *
 * @param uid - 当前玩家 uid（筛选其发布的像素为 creations；发布次数 = 上限 - 已发布数）
 */
function buildPixelArtData(uid: string): Buffer {
  const creations = listPixelsByUid(uid).map((p) =>
    fb(1, buildPixelArtInfo(p.id, p.md5, p.ts)),
  );
  const remaining = Math.max(0, ARKPIXEL_MAX_PUBLISH - creations.length);
  return Buffer.concat([
    ...creations,
    fv(7, remaining), // remaining_publish_count
    fv(8, BigInt(Math.floor(Date.now() / 1000))), // last_refresh_time
  ]);
}

/**
 * 像素数据变更通知（31d674d5 SavePixelArtReq 后服务端主动推；官方字节对齐）
 * 权威结构 PixelArtDataAlterNotify：f1 altered_creations[](PixelArtInfo)、
 * f2 deleted_creation_ids[](ulong)、f3 altered_collections[]、f4 deleted_collection_ids[]、
 * f5 display_pixel_art_id、f9 remaining_publish_count、f10 status_changed_creation_ids。
 * 客户端据此刷新自己的像素列表与剩余发布次数（保存后 altered 新条目、删除后 deleted 删除 id）。
 *
 * @param uid - 当前玩家 uid（剩余发布次数 = 上限 - 已发布数）
 * @param opts - { altered?: {id,md5,ts}[]（新增/修改条目）；deleted?: number[]（删除 id 集）}
 */
function buildPixelDataAlterNotify(
  uid: string,
  opts: { altered?: Array<{ id: number; md5: string; ts: number }>; deleted?: number[] } = {},
): Buffer {
  const parts: Buffer[] = [];
  const altered = opts.altered ?? [];
  const deleted = opts.deleted ?? [];
  for (const a of altered) parts.push(fb(1, buildPixelArtInfo(a.id, a.md5, a.ts)));
  // deleted_creation_ids（f2）为 packed uint64 或重复 varint——重复 varint 与客户端兼容
  for (const d of deleted) parts.push(fv(2, BigInt(d)));
  // remaining_publish_count（f9）= 上限 - 当前已发布数（含本次 altered/deleted 后的状态）
  const currentCount = listPixelsByUid(uid).length;
  parts.push(fv(9, Math.max(0, ARKPIXEL_MAX_PUBLISH - currentCount)));
  return Buffer.concat(parts);
}

/**
 * 状态数据（PlayerSyncData.f8 BuffDoc）：空容器。
 * 官方结构：f1 buff_list[]（UnitBuff{1:buff_id(int), 2:count(int)}，可空）。
 */
function buildBuffDoc(): Buffer {
  return Buffer.alloc(0);
}

/** 非永久功能菜单解锁位：假定官服 feature id = ActArkHubMenuType 枚举值（=menuData.sortId），
 *  下发 FeatureFlagsDoc{flags:{menuType: FuncMenuStatus}}，客户端 `UpdateFuncStatus` → funcDict
 *  把对应菜单置为解锁。枚举：4=扫描仪 ARKDEX_CREATURE、5=道具箱 ARKDEX_ITEM、
 *  6=数据库 ARKDEX_ALBUM、7=画像册 ARKPIXEL、8=交换站 ARKDEX_TRADE。
 *  ⚠️ 此前 pixel_unlock→1/2 的占位不匹配官服，已弃用（数据库=6、画像册=7）。 */
const ARKHUB_MENU_UNLOCK_IDS = [4, 5, 6, 7, 8];

/**
 * 功能位数据（PlayerSyncData.f9 FeatureFlagsDoc）
 * 官方结构：f1 flags 为 Dictionary<int,int>（proto map：重复 f1 元素 {1:menuType, 2:value}）。
 * 把上述非永久功能菜单下发为 UNLOCKED(1)——客户端据此把 funcDict 对应菜单置解锁，
 * 从而"数据库/画像册/扫描仪/道具箱/交换站"等可进入。
 */
function buildFeatureDoc(): Buffer {
  return Buffer.concat(
    ARKHUB_MENU_UNLOCK_IDS.map((id) =>
      fb(1, Buffer.concat([fv(1, id), fv(2, 1)])),
    ),
  );
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

/** 商店条目：{序号, itemNumId, 价格, 每日库存}（购买帧 28f56f2c 按商店序号） */
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
 * 像素上传 token 响应（0x31d603b3 → 0x31d60cf6）
 * 官服形状（抓包 2026-08-12 实锤，字节级对齐）：
 *   [4B 请求序号回显] {1:code, 2:credential=PixelArtUploadCredential{
 *     1:pixel_art_id(ulong), 2:upload_token(32hex), 3:expire_time(now+1800s)}}。
 * ⚠️ 与旧实现三处差异（此前"像素画上传失败"的根因，均已按官服字节修正）：
 *   ① 响应必须带 4B 请求序号回显——客户端按 [seq]+proto 解析，缺前缀会把它当 seq
 *      导致整个响应错乱、上传流程中止（不发后续 HTTP savePixelArt）；
 *   ② code=100（GW_CODE_OK）——此前误用 0（缺官服样本时的错误推断，官服实为 100）；
 *   ③ 新画布（请求未携带 pixel_art_id）时服务端分配真实 id 下发，不再回 0。
 *
 * @param seq - 请求序号（body 前 4B 大端；新画布上传为递增序号）
 * @param pixelArtId - 请求携带的 pixel_art_id（已存在画布重传；0 = 新画布需分配）
 * @param md5 - 请求携带的像素 md5（暂不校验，保持官服形状）
 * @returns { id, token, buffer }——分配/沿用的 pixel_art_id、upload_token、完整帧体
 *          （调用方据 id/token 登记上传暂存，保证客户端 getPixelArt 加载命中）
 */
function buildPixelUploadTokenResp(
  seq: number,
  pixelArtId: number,
  md5: string,
): { id: number; token: string; buffer: Buffer } {
  const uploadToken = Array.from({ length: 32 }, () =>
    "0123456789abcdef"[Math.floor(Math.random() * 16)],
  ).join("");
  // 已存在画布沿用请求 id；新画布分配全局唯一 id（对齐官服：token 阶段下发真实 id）
  const actualId = pixelArtId > 0 ? pixelArtId : allocPixelArtId();
  const credential = Buffer.concat([
    fv(1, BigInt(actualId)),
    fb(2, Buffer.from(uploadToken, "utf8")),
    fv(3, BigInt(Math.floor(Date.now() / 1000) + 1800)),
  ]);
  const payload = Buffer.concat([fv(1, GW_CODE_OK), fb(2, credential)]);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return { id: actualId, token: uploadToken, buffer: Buffer.concat([seqBuf, payload]) };
}

/* ---------- 捕捉（capture）/ 对局（duel）/ 交换（exchange）/ 生物（creature）响应构建 ---------- */

/**
 * CreatureBrief 消息体：{1:unique_id(ulong), 2:template_id(uint), 3:persona(uint)}
 * 权威字段：CreatureBrief.cs ProtoMember(1/2/3)。
 *
 * @param uniqueId - 生物个体唯一 id（会话内稳定即可）
 * @param templateId - 生物模板 id（arkdex creature_numId）
 * @param persona - 个性/变体（缺省 0）
 */
function buildCreatureBrief(uniqueId: bigint, templateId: number, persona = 0): Buffer {
  return Buffer.concat([fv(1, uniqueId), fv(2, templateId), fv(3, persona)]);
}

/**
 * 由生物模板 id 列表生成 CreatureBrief 数组（每人个体 id 取 0x100000000 递增基底，
 * 保证 neg-id 空间独立且稳定——单机遭遇/结算均引用同一批）。
 */
function buildCreatureBriefs(creatureTemplates: number[]): Buffer[] {
  return (creatureTemplates ?? []).map((t, i) =>
    buildCreatureBrief(BigInt(0x100000000) + BigInt(i + 1), t, 0),
  );
}

/**
 * CreatureBattleInfo 消息体：{1:creatures[](CreatureBrief), 2:stage_id, 3:capture_type}
 * 权威字段：CreatureBattleInfo.cs ProtoMember(1/2/3)。
 */
function buildCreatureBattleInfo(creatureBriefs: Buffer[], stageId: string, captureType = 1): Buffer {
  return Buffer.concat([
    ...creatureBriefs.map((b) => fb(1, b)),
    fb(2, Buffer.from(stageId, "utf8")),
    fv(3, captureType),
  ]);
}

/**
 * 捕捉开始响应（StartCaptureResp）：{1:code(uint), 2:battle_id}
 * 权威字段：StartCaptureResp.cs ProtoMember(1/2)。会话 battleId 由时间戳生成。
 */
function buildStartCaptureResp(): Buffer {
  const battleId = `cap_${BigInt.asUintN(32, BigInt(Date.now())).toString(16)}`;
  return Buffer.concat([fv(1, GW_CODE_OK), fb(2, Buffer.from(battleId, "utf8"))]);
}

/**
 * 遭遇生物通知（EncounterCreatureNotify，服务端在 StartCapture 后主动推）：
 * {1:battle_info=CreatureBattleInfo{...}}——客户端据此展示本次捕捉遭遇生物。
 * 权威字段：EncounterCreatureNotify.cs ProtoMember(1)、CreatureBattleInfo.cs。
 */
function buildEncounterCreatureNotify(creatureBriefs: Buffer[], stageId: string): Buffer {
  return fb(1, buildCreatureBattleInfo(creatureBriefs, stageId));
}

/**
 * 捕捉结算响应（EndCaptureResp）：{1:settle_info=ArkDexSettleInfo{1:is_success,
 * 2:end_time, 3:creatures[]}}——权威字段：EndCaptureResp.cs/ArkDexSettleInfo.cs。
 */
function buildEndCaptureResp(isSuccess: boolean, creatureBriefs: Buffer[]): Buffer {
  const settle = Buffer.concat([
    fv(1, isSuccess ? 1 : 0),
    fv(2, BigInt(Date.now())),
    ...creatureBriefs.map((b) => fb(3, b)),
  ]);
  return fb(1, settle);
}

/**
 * 捕捉信息查询响应（GetCaptureInfoResp）：{1:code, 2:battle_info}
 * 权威字段：GetCaptureInfoResp.cs ProtoMember(1/2)。单机回当前遭遇（可为空）。
 */
function buildGetCaptureInfoResp(creatureBattleInfo: Buffer): Buffer {
  return Buffer.concat([fv(1, GW_CODE_OK), fb(2, creatureBattleInfo)]);
}

/**
 * 对局入座响应（JoinDuelResp）：{1:code(int), 2:mode_type(int)}
 * 权威字段：JoinDuelResp.cs ProtoMember(1/2)。
 */
function buildJoinDuelResp(): Buffer {
  return Buffer.concat([fv(1, GW_CODE_OK), fv(2, 0)]);
}

/**
 * 对局入座广播（OnJoinDuelNotify，服务端入座后主动推）：
 * {1:duel_id, 2:stage_id, 3:battle_id, 4:mode_type}——权威字段：JoinDuelNotify.cs。
 * 单机最小化：仅 duel_id + stage_id + mode_type=0。
 */
function buildOnJoinDuelNotify(): Buffer {
  return Buffer.concat([
    fb(1, Buffer.from(`duel_${BigInt.asUintN(32, BigInt(Date.now())).toString(16)}`, "utf8")),
    fb(2, Buffer.from(DUEL_STAGE_ID, "utf8")),
    fv(4, 0),
  ]);
}

/**
 * 对局开始响应（StartDuelResp）：{1:code(int)=100}
 * 权威字段：StartDuelResp.cs ProtoMember(1)。
 */
function buildStartDuelResp(): Buffer {
  return Buffer.from([0x08, GW_CODE_OK]);
}

/**
 * 交换信息响应（GetAllCreatureExchangeInfoResp）：本地空状态。
 * 权威字段：GetAllCreatureExchangeInfoRsp.cs——{1:requests[](空), 2:exchange_type,
 * 3:player_avatars(空)}；单机无真实交换请求，按 Data 结构给空状态（仅 exchange_type=0）。
 */
function buildEmptyExchangeInfoResp(): Buffer {
  return fv(2, 0);
}

/**
 * 道具购买响应（28f56f2c → 0x28f5568f）
 * 官服形状：[4B seq回显] {1:100, 2:index, 3:item_id, 4:数量, 5:价格}。
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
 * 使用道具响应（28f5b1ab → 0x28f5de74）
 * 官服形状：{1:code=100}。UseItemResp.cs ProtoMember(1)。
 */
function buildUseItemResp(): Buffer {
  return Buffer.from([0x08, GW_CODE_OK]);
}

/**
 * 删除像素响应（31d6d13b → 0x31d67d3e）
 * 官服形状（抓包 2026-08-12）：[4B 请求序号回显] {1:code=100}。DeletePixelArtResp.cs ProtoMember(1)。
 * @param seq - 请求序号（body 前 4B 大端）
 */
function buildDeletePixelResp(seq: number): Buffer {
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, Buffer.from([0x08, GW_CODE_OK])]);
}

/**
 * 删除像素收藏响应（31d65453 → 0x31d6ea56）
 * 官服形状：{1:code=100}（与删除像素同带 [seq] 回显）。DeletePixelArtCollectionResp.cs ProtoMember(1)。
 * @param seq - 请求序号（body 前 4B 大端）
 */
function buildDeletePixelCollectionResp(seq: number): Buffer {
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32BE(seq, 0);
  return Buffer.concat([seqBuf, Buffer.from([0x08, GW_CODE_OK])]);
}

/**
 * 重连登录响应（0x0fa3 → 0x0fa4）
 * 官服形状：{1:101（重连成功 code）}。重连凭据（base64 JWT）任意放行（私服单账号）。
 */
function buildReconnectResp(): Buffer {
  return Buffer.from([0x08, 101]);
}

/**
 * 道具奖励通知（3000ee32，交互提交领奖后服务端下发）
 * 官服形状（2026-08-19 shiane_02b 领奖实锤）：{1:1, 2:[{1:奖励id, 2:数量}×N]}。
 * ——— f1=1 为道具/物品奖励（与旧"f1=2 生物奖励"区分，生物奖励现改走 EndCaptureResp）。
 *
 * @param items - 奖励条目（{id: 数值奖励 id, count: 数量}）
 */
function buildItemRewardNotify(items: Array<{ id: number; count: number }>): Buffer {
  const entries = (items ?? []).map((it) => fb(2, Buffer.concat([fv(1, it.id), fv(2, it.count)])));
  return Buffer.concat([fv(1, 1), ...entries]);
}

/** 引导 flag → feature_doc(f6) 功能位 id（FeatureFlagsDoc.flags 的 int key）。
 *  兜底双通道：主通道 task_alter_data(f5) 必发；这里再按功能位下发 feature_doc，
 *  客户端 `UpdateFuncStatus` 应用（用于画像册等设施解锁）。
 *  ⚠️ 以下 id 为本地侧稳定占位（官服 feature id 无公开来源）：必须按官服 feature 配置核齐，
 *  否则客户端按官方 id 找不到该位（仅结构就位、语义待校）。 */
const ARKHUB_FEATURE_IDS: Record<string, number> = {
  pixel_unlock: 1,
  pixel_unlock_system: 2,
};

/**
 * GuideFlags 广播（38b36462，引导推进后服务端主动下发）
 *
 * 该帧官方业务对象为 PlayerAlterDataNotify（SyncAlterDataNotify），字段：
 *   f2 = item_alter_data:ItemChangeNotify{ 1:coin, 2:modified:ArkhubItem[], 3:deleted }
 *   f5 = task_alter_data:TaskAlterList{ 1:modified:TaskInfo[] }，TaskInfo{ 1:seq_number,
 *        2:status }
 * 本地发送对齐官方结构：f2 放当前券数 + 本次领奖道具（ArkhubItem{item_id, count} 兼容），
 * f5 把引导推进项封装为 task_alter_data.modified（TaskInfo{seq_number=引导key, status=值}），
 * 客户端据此解析引导任务并结束当前对话（关键：f5 必须包进 TaskAlterList.modified 这层嵌套，
 * 否则客户端读不到 —— 修复前本地把引导 key 直接放了重复 f5，导致对话无法关闭）。
 *
 * @param flags - 本次推进的 GuideFlags（{key: value}，转为 TaskInfo{seq_number, status}）
 * @param gold - 玩家当前奇象兑换券数（arkdex_1_gold 持有量，f2.f1/ItemChangeNotify.coin）
 * @param items - 本次领奖道具（{id, count}，f2.f2/ArkhubItem[]）
 */
function buildGuideFlagsNotify(
  flags: Record<string, number>,
  gold = 0,
  items: Array<{ id: number; count: number }> = [],
): Buffer {
  // f2 = ItemChangeNotify{ 1:coin, 2:modified[] }（官方字段号，ArkhubItem{item_id,count} 兼容）
  const f2 = Buffer.concat([
    fv(1, gold),
    ...(items ?? []).map((it) =>
      fb(2, Buffer.concat([fv(1, it.id), fv(2, it.count)])),
    ),
  ]);
  // f5 = TaskAlterList{ 1:modified:[TaskInfo{1:seq_number, 2:status}] }
  const modified = Object.entries(flags).map(([key, val]) =>
    fb(1, Buffer.concat([fb(1, Buffer.from(key, "utf8")), fv(2, val)])),
  );
  // f6 = feature_doc: FeatureFlagsDoc{ 1:flags:[{1:featureId, 2:value}] }（兜底双通道）
  // 仅下发能映射到 feature id 的功能位（如 pixel_unlock），供客户端 UpdateFuncStatus 解锁设施。
  const featureFlags = Object.entries(flags)
    .filter(([key]) => ARKHUB_FEATURE_IDS[key] !== undefined)
    .map(([key, val]) =>
      fb(1, Buffer.concat([fv(1, ARKHUB_FEATURE_IDS[key] as number), fv(2, val)])),
    );
  return Buffer.concat([
    fb(2, f2),
    ...(modified.length ? [fb(5, Buffer.concat(modified))] : []),
    ...(featureFlags.length ? [fb(6, Buffer.concat(featureFlags))] : []),
  ]);
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
    // 枢纽 GuideFlags（按连接维护——mmkabi 引导领奖后 capture_catch_guide_02 1→2）
    let guideState = defaultGuideFlags();
    /**
     * 本次捕捉的遭遇生物种类 id（capture 链路：EndCaptureReq 结算入参 + EncounterCreatureNotify
     * 推送数据源）。位于捕捉区时 StartCaptureReq 触发 onScanStart；若无遭遇回填本地兜底集。
     */
    let encounterCreatures: number[] = [];
    /**
     * 帧日志（完整记录收发——调试枢纽玩法帧协议用）
     *
     * 心跳（main=1）与位置同步（sub low32=38b32a34）为高频噪音帧 → DEBUG；
     * 其余帧 → INFO。日志可读化：已知帧类型显示语义名 + 解析后的字段摘要
     * （protobuf 轻解析），未知帧显示首字节 hex 预览。
     */
    const frameName = (low: string): string => {
      // 帧名标注（low32 → 官方消息名，见 docs/arkhub-gateway-protocol.md §9/§10/§11）
      const names: Record<string, string> = {
        "00000fa1": "登录(UserLoginReq)",
        "00000fa2": "登录响应(UserLoginResp)",
        "00000fa3": "重连登录(UserReconnectReq)",
        "00000fa4": "重连响应(UserReconnectResp)",
        "00000000": "心跳(Ping/Pong)",
        "0de29cdb": "场景hello(EnterSceneReq)", // 兼容旧 key
        "4de29cdb": "场景hello(EnterSceneReq)",
        "4de28c3f": "退出场景(SyncClientLogoutNotify)",
        "38b37d3d": "场景数据(SyncEnterSceneResultNotify/EnterSceneNotify)",
        "38b3b60b": "切场景(ChangeSceneReq)",
        "38b3a5a8": "切换完成(LeaveSceneNotify)",
        "38b3c3c9": "离开场景(LogoutSceneReq)",
        "38b32a34": "位置同步(MoveReq)",
        "38b32a35": "位置ACK",
        "38b3360a": "玩家同步(SyncSceneNotify)",
        "38b31d8f": "状态同步(SyncStateNotify)",
        "38b36462": "状态变更广播(SyncAlterDataNotify)",
        "38b3116d": "交互提交(SubmitActorOpReq)",
        "38b3116e": "交互响应(兼容旧key)",
        "38b38cd6": "交互ACK(SubmitActorOpResp)",
        "38b3170a": "表情(DoRolePlayingReq)",
        "38b36054": "设置更新(UpdatePlayerSettingsReq)",
        "38b322c3": "名片查看(GetBusinessCardReq)",
        "38b3d83c": "更换形象(ChangeOutlookReq)",
        "38b3ab0c": "活跃上报(ReportPlayerActiveReq)",
        "38b39680": "动作掩码(ModifyPlayerActionReq)",
        "30009df1": "错误提示(NotifyErrorMessageNotify)",
        "3000ee32": "Toast提示(NotifyToastMessageNotify)", // ⚠️ 原误标"奖励通知"
        "b7c2ad8b": "捕捉信息Req(GetCaptureInfoReq)",
        "b7c2b4de": "捕捉信息Resp(GetCaptureInfoResp)",
        "b7c267d7": "捕捉开始(StartCaptureReq)", // ⚠️ 原误标"ARKDUEL开始"
        "b7c2b07e": "捕捉开始Resp(StartCaptureResp)",
        "b7c20f13": "遭遇生物(EncounterCreatureNotify)", // ⚠️ 原误标"敌方/奖励"
        "b7c204e8": "捕捉结束(EndCaptureReq)", // ⚠️ 原误标"ARKDUEL结算"
        "b7c26451": "捕捉结算Resp(EndCaptureResp)",
        "b7c277bf": "对局入座(JoinDuelReq)", // ⚠️ 原误标"战斗确认"
        "b7c2a2e2": "对局入座Resp(JoinDuelResp)",
        "b7c2ef4f": "入座广播(OnJoinDuelNotify)",
        "b7c21661": "取消对局(CancelDuelReq)",
        "b7c264e3": "删除生物(DeleteCreatureReq)", // ⚠️ 原误标"战斗就绪"
        "b7c28d19": "生物点赞(SetCreatureLikeReq)",
        "b7c20b13": "跟随宠物(SetFollowingCreatureReq)",
        "b7c2cbf4": "生物编队(SetCreatureSquadReq)", // ⚠️ 原误标"战斗数据上传"
        "b7c2d119": "生物变更广播(CreatureAlterNotify)",
        "b7c283a3": "交换状态广播(CreatureExchangeStateNotify)",
        "b7c2369e": "预设交换(PresetCreatureExchangeReq)", // ⚠️ 原误标"遭遇生物上报"
        "b7c2394d": "发起交换(CreateCreatureExchangeReq)",
        "b7c2be4f": "应答交换(AnswerCreatureExchangeReq)",
        "b7c21f3a": "交换信息Req(GetAllCreatureExchangeInfoReq)", // ⚠️ 原误标"战斗触发"
        "b7c25f13": "交换信息Resp(GetAllCreatureExchangeInfoResp)",
        "f8faa515": "对局开始(StartDuelReq)",
        "f8fa2dce": "对局开始Resp(StartDuelResp)",
        "f8faf090": "加载完成(LoadingFinishReq)",
        "f8fa9c6e": "回合准备(RoundPrepareReq)",
        "f8fa293a": "回合结算上报(DuelRoundResultReportReq)",
        "f8faf4f3": "阶段广播(DuelStageChangeNotify)",
        "f8fad282": "离开对局(LeaveDuelReq)",
        "f8faab16": "战报上传(UploadBattleDataReq)",
        "31d603b3": "像素上传token(RequestPixelArtUploadTokenReq)", // ⚠️ 原误标"令牌帧"
        "31d60cf6": "像素token Resp",
        "31d674d5": "像素保存确认(SavePixelArtReq)",
        "31d62bbd": "像素变更广播(PixelArtDataAlterNotify)",
        "31d61490": "收集画像(CollectPixelArtReq)", // ⚠️ 原误标"查看游客"
        "31d6d13b": "删除像素(DeletePixelArtReq)", // ⚠️ 原误标"实体信息查询"
        "31d65453": "删除像素收藏(DeletePixelArtCollectionReq)",
        "31d67d3e": "删除像素Resp(DeletePixelArtResp)",
        "28f5ba6f": "商店信息(GetShopInfoReq)", // ⚠️ 原误标"ARKDUEL商店"
        "28f5229c": "商店信息Resp(GetShopInfoResp)",
        "28f56f2c": "购买道具(BuyItemReq)",
        "28f5568f": "购买Resp(BuyItemResp)",
        "28f5b1ab": "使用道具(UseItemReq)", // ⚠️ 原误当"第二购买形态"
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
      // 户籍裁剪：配置 resolveArkdexDocs 时把玩家奇象展册数据编进 PlayerSyncData f5-f9
      // （生物图鉴/道具/功能位），否则维持现状（不带 f5-f9）。
      const arkdocs = opts.resolveArkdexDocs?.(loginUid);
      send(8, GW_SCENE_DATA, buildEnterScene(loginUid, buildProfile(), mapId, guideState, arkdocs));
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
            // 进入大厅：首次自动完成"登录/入场引导"（arkhub_login）。
            // 渐进模式下 arkhub_login 初始为 0（触发入场引导对话）；这里在本连接把它置 1
            // 并经 onGuideAdvance→arkhubAdvanceGuide 持久化——本次场景仍播一次，之后不再重复
            // （否则每次进入都会重新触发该对话，与官服"入场引导完成后不再弹"不一致）。
            if (guideState.arkhub_login === 0) {
              guideState.arkhub_login = 1;
              try {
                opts.onGuideAdvance?.(loginUid, "arkhub_login", "");
              } catch (e) {
                logger.warn("arkhub-gateway", `登录引导自动完成失败: ${(e as Error).message}`);
              }
            }
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
            (subID & 0xffffffffn) === GW_PIXEL_UPLOAD_TOKEN_REQ
          ) {
            // 像素上传 token（RequestPixelArtUploadTokenReq）
            // 请求形状：[4B 请求序号] {1:pixel_art_id(ulong), 2:md5(string)}——
            // 官服抓包（2026-08-12）：新画布上传仅带 {2:md5}（pixel_art_id 不下发=0），
            // 已存在画布重传带 {1:pixel_art_id}。
            // 响应 [4B seq回显] + {1:code=100, 2:credential}（官方字节对齐，见
            // buildPixelUploadTokenResp）——客户端按 [seq]+proto 解析，缺前缀会错乱。
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            let pixelArtId = 0;
            let md5 = "";
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
                if (wire === 0) {
                  const v = rv2();
                  if (field === 1) pixelArtId = Number(v);
                } else if (wire === 2) {
                  const l = Number(rv2());
                  if (field === 2) md5 = payload.subarray(p, p + l).toString("utf8");
                  p += l;
                } else break;
              }
            } catch {
              // 解析失败按默认
            }
            logger.info(
              "arkhub-gateway",
              `像素上传 token pixel_art_id=${pixelArtId || "?"} md5=${md5 || "?"} (seq=${seq})`,
            );
            const cred = buildPixelUploadTokenResp(seq, pixelArtId, md5);
            // 登记上传 token → 分配的 id（HTTP savePixelArt 消费），保证客户端用该 id
            // 调 getPixelArt 加载画像时命中（上传后无法加载的根因：token id 与落盘 id 不一致）
            if (cred.id > 0) registerPixelUploadToken(cred.token, cred.id, md5);
            send(8, (subID & ~0xffffffffn) | GW_PIXEL_UPLOAD_TOKEN_RESP, cred.buffer);
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_CAPTURE_INFO_REQ
          ) {
            // 捕捉信息查询（GetCaptureInfoReq：{1:creature_inst_id}）→ GetCaptureInfoResp
            // {1:code, 2:battle_info}。单机回当前遭遇（可为空，结构按 GetCaptureInfoResp.cs）。
            logger.info("arkhub-gateway", `捕捉信息查询 → 捕捉信息 (uid=${loginUid || "?"})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_CAPTURE_INFO_RESP,
              buildGetCaptureInfoResp(
                buildCreatureBattleInfo(buildCreatureBriefs(encounterCreatures), SCAN_STAGE_ID),
              ),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_START_CAPTURE_REQ
          ) {
            // 捕捉开始（StartCaptureReq：{1:param=ArkDexStartParam{1:creature_inst_id,
            // 2:troop_index, 3:troop_info}}）→ StartCaptureResp{1:code, 2:battle_id}；
            // 随后服务端主动推 EncounterCreatureNotify{1:battle_info=CreatureBattleInfo{
            // 1:creatures[](CreatureBrief), 2:stage_id, 3:capture_type}}——客户端据此展示。
            // 捕捉区：onScanStart（arkhubStartEncounter 生成/记录遭遇）；遭遇非空直接用，
            // 空则回填本地兜底集（单机无法从客户端拿真实随机遭遇）。
            if (CAPTURE_MAP_IDS.includes(currentMapId)) {
              try {
                opts.onScanStart?.(loginUid, currentMapId);
              } catch (e) {
                logger.warn("arkhub-gateway", `捕捉遭遇生成失败: ${(e as Error).message}`);
              }
              if (encounterCreatures.length === 0) {
                encounterCreatures = [...CAPTURE_ENCOUNTER_CREATURES];
              }
            }
            const encounterBriefs = buildCreatureBriefs(encounterCreatures);
            logger.info(
              "arkhub-gateway",
              `捕捉开始 (map=${currentMapId}) → StartCaptureResp + 遭遇 ${encounterCreatures.join(",") || "无"} (${SCAN_STAGE_ID})`,
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_START_CAPTURE_RESP,
              buildStartCaptureResp(),
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_ENCOUNTER_CREATURE_NOTIFY,
              buildEncounterCreatureNotify(encounterBriefs, SCAN_STAGE_ID),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_END_CAPTURE_REQ
          ) {
            // 捕捉结束（EndCaptureReq：{1:battle_id, 2:param=ArkDexEndParam{1:complete_state,
            // 2:captured(packed)}}）→ EndCaptureResp{1:settle_info=ArkDexSettleInfo{
            // 1:is_success, 2:end_time, 3:creatures[]}}。
            // 本地遭遇生物非空即判成功：onScanSettle(uid, captured)（arkhubEndScan），随后清空。
            const captured = [...encounterCreatures];
            const isSuccess = captured.length > 0;
            if (isSuccess) {
              try {
                opts.onScanSettle?.(loginUid, captured);
              } catch (e) {
                logger.warn("arkhub-gateway", `捕捉结算奖励处理失败: ${(e as Error).message}`);
              }
            }
            encounterCreatures = [];
            logger.info(
              "arkhub-gateway",
              `捕捉结束 ${isSuccess ? `(捕获 ${captured.join(",")})` : "(未捕获)"} → settle_info`,
            );
            send(
              8,
              (subID & ~0xffffffffn) | GW_END_CAPTURE_RESP,
              buildEndCaptureResp(isSuccess, buildCreatureBriefs(captured)),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_JOIN_DUEL_REQ
          ) {
            // 对局入座（JoinDuelReq：{1:param=ArkDexDuelParam}）→ JoinDuelResp
            // {1:code, 2:mode_type}；随后服务端主动推 OnJoinDuelNotify（对局入座广播）。
            logger.info(
              "arkhub-gateway",
              `对局入座 → JoinDuelResp + OnJoinDuelNotify (uid=${loginUid || "?"})`,
            );
            send(8, (subID & ~0xffffffffn) | GW_JOIN_DUEL_RESP, buildJoinDuelResp());
            send(8, (subID & ~0xffffffffn) | GW_ON_JOIN_DUEL_NOTIFY, buildOnJoinDuelNotify());
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_CANCEL_DUEL_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_ROUND_PREPARE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_UPLOAD_BATTLE_DATA_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_LOADING_FINISH_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_LEAVE_DUEL_REQ
          ) {
            // 取消对局 / 回合准备 / 战报上传 / 加载完成 / 离开对局——官服多为 fire-and-forget，
            // 本地回 ACK {1:100}（subID+1，与通用兜底同形状）。
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_START_DUEL_REQ
          ) {
            // 对局开始（StartDuelReq：BattleParam{1:duel_id, 2:battle_id}）→
            // StartDuelResp{1:code=100}（协议定义 code 字段）。
            logger.info("arkhub-gateway", `对局开始 → StartDuelResp (uid=${loginUid || "?"})`);
            send(8, (subID & ~0xffffffffn) | GW_START_DUEL_RESP, buildStartDuelResp());
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DUEL_ROUND_RESULT_REPORT_REQ
          ) {
            // 对局回合结算上报（DuelRoundResultReportReq）→ 对局结算发券（onDuelSettle）+ ACK
            try {
              opts.onDuelSettle?.(loginUid);
            } catch (e) {
              logger.warn("arkhub-gateway", `对局结算奖励处理失败: ${(e as Error).message}`);
            }
            logger.info(
              "arkhub-gateway",
              `对局回合结算上报 → 发券 + ACK (uid=${loginUid || "?"})`,
            );
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_GET_ALL_EXCHANGE_INFO_REQ
          ) {
            // 交换信息（GetAllCreatureExchangeInfoReq：{1:exchange_type}）→
            // GetAllCreatureExchangeInfoResp（本地空状态，单机无真实交换请求）。
            logger.info("arkhub-gateway", `交换信息查询 → 空状态 (uid=${loginUid || "?"})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_GET_ALL_EXCHANGE_INFO_RESP,
              buildEmptyExchangeInfoResp(),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_PRESET_EXCHANGE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_CREATE_EXCHANGE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_ANSWER_EXCHANGE_REQ
          ) {
            // 预设交换 / 发起交换 / 应答交换——单机无真实玩家，回 ACK {1:100}
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_EXCHANGE_STATE_NOTIFY
          ) {
            // 交换状态广播（CreatureExchangeStateNotify，官方为服务端下发）——收到仅记录日志。
            logger.info("arkhub-gateway", `交换状态广播 (uid=${loginUid || "?"})`);
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DELETE_CREATURE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_SET_CREATURE_LIKE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_SET_FOLLOWING_CREATURE_REQ ||
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_SET_CREATURE_SQUAD_REQ
          ) {
            // 生物管理请求（删除/点赞/跟随/编队）——单机本地回官方 resp 或 {1:100} ACK
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_CREATURE_ALTER_NOTIFY
          ) {
            // 生物变更广播（CreatureAlterNotify，官方为服务端下发）——收到仅记录日志。
            logger.info("arkhub-gateway", `生物变更广播 (uid=${loginUid || "?"})`);
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
              // 引导更新广播（38b36462）push 两件事：
              //  ① capture_update_guide=1 —— 客户端据此"重新读取引导状态并结束当前对话"；
              //  ② 本次推进的其余 GuideFlags（如 pixel_unlock / pixel_unlock_system）——
              //     经 task_alter_data(TaskInfo{seq_number=key, status=值}) 下发，客户端据此
              //     解锁画像册等设施（缺失则引导推进后功能仍不解锁）。f2 对齐官服：
              //     {1: 当前券数, 2:[本次领奖道具 5012/5022]}（官服 f2={1:155,2:[...]}）
              const gold = opts.resolveArkDexGold?.(loginUid) ?? 0;
              guideBroadcast = buildGuideFlagsNotify(
                { ...(guideFlags as Record<string, number>), capture_update_guide: 1 },
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
            const ack = Buffer.alloc(4);
            ack.writeUInt32BE(seq, 0);
            send(8, (subID & ~0xffffffffn) | GW_INTERACT_ACK, Buffer.concat([ack, Buffer.from([0x08, GW_CODE_OK])]));
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
            (subID & 0xffffffffn) === GW_SAVE_PIXEL_ART_REQ
          ) {
            // 像素保存确认（SavePixelArtReq：{1:pixel_art_id, 2:upload_success, 3:do_publish}）
            // 官服抓包（2026-08-12）：body 为纯 protobuf 无 seq 前缀，fire-and-forget 无 ACK——
            // 服务端随后主动推 PixelArtDataAlterNotify（31d62bbd），客户端据此匹配 id+md5
            // 确认保存成功并刷新列表（缺此推送客户端会判定保存失败）。
            let pixelArtId = 0;
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
                if (wire === 0) {
                  const v = rv2();
                  if (field === 1) pixelArtId = Number(v);
                } else break;
              }
            } catch {
              // 解析失败按默认
            }
            // 像素索引读取 md5（savePixelArt 落盘后索引含 md5）——通知帧匹配用
            const meta = pixelMeta(pixelArtId);
            logger.info(
              "arkhub-gateway",
              `像素保存确认 id=${pixelArtId || "?"} md5=${meta?.md5?.slice(0, 8) ?? "?"} → PixelArtDataAlterNotify`,
            );
            // PixelArtDataAlterNotify：altered 新保存的条目 + 剩余发布次数（f9）——
            // 客户端据此刷新自己的像素列表/发布数（此前字段号错，客户端收不到列表）。
            send(
              8,
              (subID & ~0xffffffffn) | GW_PIXEL_DATA_ALTER_NOTIFY,
              buildPixelDataAlterNotify(loginUid, {
                altered: meta
                  ? [{ id: pixelArtId, md5: meta.md5, ts: meta.ts }]
                  : [],
              }),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_COLLECT_PIXEL_REQ
          ) {
            // 收集画像（CollectPixelArtReq：{1:target_uid, 2:pixel_art_id}）——单机无真实
            // 匿名画像，解析后记录日志，回 {1:100} ACK（subID+1）。
            let targetUid = "";
            let pixelArtId = 0;
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
                  if (field === 1) targetUid = body.subarray(p, p + l).toString("utf8");
                  p += l;
                } else if (wire === 0) {
                  const v = rv2();
                  if (field === 2) pixelArtId = Number(v);
                } else break;
              }
            } catch {
              // 解析失败按空 uid
            }
            logger.info(
              "arkhub-gateway",
              `收集画像 target_uid=${targetUid || "?"} pixel_art_id=${pixelArtId || "?"} → ACK`,
            );
            send(8, subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_USE_ITEM_REQ
          ) {
            // 使用道具（UseItemReq：{1:item_id, 2:count}）→ UseItemResp（0x28f5de74）{1:code=100}
            let itemId = 0;
            let count = 1;
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
                if (wire === 0) {
                  const v = rv2();
                  if (field === 1) itemId = Number(v);
                  else if (field === 2) count = Number(v);
                } else break;
              }
            } catch {
              // 解析失败按默认
            }
            logger.info("arkhub-gateway", `使用道具 item_id=${itemId || "?"} ×${count}`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_USE_ITEM_RESP,
              buildUseItemResp(),
            );
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_BUY_ITEM_REQ_1
          ) {
            // 道具购买（BuyItemReq，店铺按序号）→ 0x28f5568f 购买响应 + onBuyProp（扣券/道具箱/库存）
            // 28f56f2c：{1:商店序号, 2:数量}
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
            // 商店序号（28f56f2c f1）→ itemNumId
            const itemNumId = DUEL_SHOP_INDEX_TO_ITEM[f1] ?? 0;
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
            (subID & 0xffffffffn) === GW_DELETE_PIXEL_REQ
          ) {
            // 删除像素（DeletePixelArtReq）：[4B 请求序号] {1:pixel_art_id}（官服抓包 2026-08-12
            // 带 seq 前缀）→ DeletePixelArtResp（0x31d67d3e）[4B seq回显] {1:code=100}。
            // ⚠️ 此前按纯 protobuf 从 body[0] 解析把 seq 当 id（解析为 0）→ 删不掉；
            // 成功后同时删除本地像素文件（deletePixel：移除 .bin + 索引）。
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            let pixelArtId = 0;
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
              if (p < payload.length) {
                const tag = rv2();
                const wire = Number(tag & 7n);
                if (wire === 0) pixelArtId = Number(rv2());
              }
            } catch {
              // 解析失败按默认
            }
            if (pixelArtId > 0) {
              try {
                deletePixel(pixelArtId);
              } catch (e) {
                logger.warn("arkhub-gateway", `像素删除落盘失败: ${(e as Error).message}`);
              }
            }
            logger.info("arkhub-gateway", `删除像素 pixel_art_id=${pixelArtId || "?"} → Resp (seq=${seq})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_DELETE_PIXEL_RESP,
              buildDeletePixelResp(seq),
            );
            // 删除成功后推 PixelArtDataAlterNotify（deleted 该 id + 剩余发布次数 f9），
            // 客户端据此移除列表项并刷新发布次数（缺此推送删除 UI 不生效）
            if (pixelArtId > 0) {
              send(
                8,
                (subID & ~0xffffffffn) | GW_PIXEL_DATA_ALTER_NOTIFY,
                buildPixelDataAlterNotify(loginUid, { deleted: [pixelArtId] }),
              );
            }
          } else if (
            mainID === 8 &&
            (subID & 0xffffffffn) === GW_DELETE_PIXEL_COLLECTION_REQ
          ) {
            // 删除像素收藏（DeletePixelArtCollectionReq）：[4B 请求序号] {1:pixel_art_id} →
            // DeletePixelArtCollectionResp（0x31d6ea56）[4B seq回显] {1:code=100}。
            // （收藏他人画像不删本地文件，仅回 ACK。）
            const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
            let pixelArtId = 0;
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
              if (p < payload.length) {
                const tag = rv2();
                const wire = Number(tag & 7n);
                if (wire === 0) pixelArtId = Number(rv2());
              }
            } catch {
              // 解析失败按默认
            }
            logger.info("arkhub-gateway", `删除像素收藏 pixel_art_id=${pixelArtId || "?"} → Resp (seq=${seq})`);
            send(
              8,
              (subID & ~0xffffffffn) | GW_DELETE_PIXEL_COLLECTION_RESP,
              buildDeletePixelCollectionResp(seq),
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
