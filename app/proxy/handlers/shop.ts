/**
 * arkhub 网关商店/道具/像素画处理（handlers——逻辑层）
 *
 * ARKDUEL 商店价格表、道具购买/使用、像素画上传 token / 保存确认 / 收集 / 删除 / 收藏删除。
 * 帧形状均按官服抓包字节级对齐（docs/arkhub-gateway-protocol.md §10 商店/像素段）。
 * 路由注册入口：registerShopHandlers(router)。
 */
import { logger } from "@utils/logger";
import {
  encodeFieldBytes as fb,
  encodeFieldVarint as fv,
  ProtoReader,
} from "../arkhub-gateway-codec";
import { GW_CODE_OK } from "../arkhub-gateway-router";
import type {
  ArkhubFrameRouter,
  ArkhubGatewayHandlerContext,
  ArkhubGatewayFrame,
} from "../arkhub-gateway-router";
import {
  allocPixelArtId,
  pixelMeta,
  registerPixelUploadToken,
  deletePixel,
  listPixelsByUid,
  ARKPIXEL_MAX_PUBLISH,
} from "@game/service/activity/arkhub/arkpixel";

/* ---------- 帧 subID（low32，见 docs/arkhub-gateway-protocol.md §9.4/§9.5） ---------- */

/** ARKDUEL 商店请求（打开对战道具商店；请求体 [4B seq]）→ 0x28f5229c 价格表 */
const GW_DUEL_SHOP_REQ = BigInt(0x28f5ba6f);
const GW_DUEL_SHOP_RESP = BigInt(0x28f5229c);
/**
 * 道具购买（BuyItemReq → 店铺按序号）→ 0x28f5568f 购买响应（{1:100, 2:index, 3:item_id,
 * 4:数量, 5:价格, 6:当前券数}）——28f56f2c：{1:商店序号, 2:数量}，接 arkhubBuyProp
 * （扣券 + 道具箱 + 生效次数 + 每日库存限购）。用道具另见 GW_USE_ITEM_REQ(28f5b1ab)。
 */
const GW_BUY_ITEM_REQ = BigInt(0x28f56f2c);
const GW_BUY_ITEM_RESP = BigInt(0x28f5568f);
/** 使用道具（UseItemReq：{1:item_id, 2:count}）→ UseItemResp 0x28f5de74 {1:code=100} */
const GW_USE_ITEM_REQ = BigInt(0x28f5b1ab);
const GW_USE_ITEM_RESP = BigInt(0x28f5de74);
/** 像素上传 token 请求（RequestPixelArtUploadTokenReq：{1:pixel_art_id, 2:md5}）→ 0x31d60cf6 凭据 */
const GW_PIXEL_UPLOAD_TOKEN_REQ = BigInt(0x31d603b3);
const GW_PIXEL_UPLOAD_TOKEN_RESP = BigInt(0x31d60cf6);
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
 * ARKDUEL 商店价格表（0x28f5ba6f → 0x28f5229c）
 * 官服响应：{1:100, 3:{1:ts, 2:[{1:序号, 2:itemNumId, 3:价格, 4:库存}×7]}}
 * 道具与价格对齐官服（activity.ARK_HUB.itemData 的 itemNumId）：
 * 5004 标准诱引剂 40 / 5005 专业诱引剂 60 / 5006 稀有诱引剂 250 /
 * 5009 甜味诱引剂 60 / 5010 辣味诱引剂 60 / 5015 专业信息素 60 / 5021 苦味信息素 60
 */
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

/* ---------- 应答构建 ---------- */

/**
 * ARKDUEL 商店价格表响应（官服字节对齐：{1:100, 3:{1:ts, 2:[7 items]}} + [4B seq 回显]）
 *
 * @param seq - 请求序号（body 前 4B 大端）
 */
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
 * 像素画条目（PixelArtInfo，PixelArtData.f1 creations[] / PixelArtDataAlterNotify.f1）
 * 权威字段（PixelArtInfo_metadata）：f1 id(ulong)、f2 md5(string)、f3 status(uint)、
 * f4 create_time(int64)、f5 update_time(int64)、f6 publish_time(int64)、
 * f7 revision(uint)、f8 collected_count(uint)。
 *
 * @param id - 像素 id
 * @param md5 - 像素数据 md5
 * @param ts - 创建/更新时间（秒级时间戳）
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
 * （会话场景帧 EnterSceneNotify 的 f7 数据源，由 session.ts 引入。）
 *
 * @param uid - 当前玩家 uid（筛选其发布的像素为 creations；发布次数 = 上限 - 已发布数）
 */
export function buildPixelArtData(uid: string): Buffer {
  const creations = listPixelsByUid(uid).map((p) => fb(1, buildPixelArtInfo(p.id, p.md5, p.ts)));
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
 * 像素上传 token 响应（0x31d603b3 → 0x31d60cf6）
 * 官服形状（抓包 2026-08-12 实锤，字节级对齐）：
 *   [4B 请求序号回显] {1:code, 2:credential=PixelArtUploadCredential{
 *     1:pixel_art_id(ulong), 2:upload_token(32hex), 3:expire_time(now+1800s)}}。
 * ⚠️ 三处关键：① 响应必须带 4B 请求序号回显（客户端按 [seq]+proto 解析）；② code=100；
 *   ③ 新画布（请求未携带 pixel_art_id）时服务端分配真实 id 下发，不再回 0。
 *
 * @param seq - 请求序号（body 前 4B 大端；新画布上传为递增序号）
 * @param pixelArtId - 请求携带的 pixel_art_id（已存在画布重传；0 = 新画布需分配）
 * @param md5 - 请求携带的像素 md5（暂不校验，保持官服形状）
 * @returns { id, token, buffer }——分配/沿用的 pixel_art_id、upload_token、完整帧体
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

/* ---------- 帧处理 ---------- */

/** ARKDUEL 商店：请求体为 [4B seq] → 返回价格表（0x28f5229c） */
function handleGetShopInfo(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const seq = frame.body.length >= 4 ? frame.body.readUInt32BE(0) : 0;
  logger.info("arkhub-gateway", `ARKDUEL 商店 → 价格表 (seq=${seq})`);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_DUEL_SHOP_RESP, buildDuelShopResp(seq));
}

/**
 * 道具购买（BuyItemReq，店铺按序号）→ 0x28f5568f 购买响应 + onBuyProp（扣券/道具箱/库存）
 * 28f56f2c：{1:商店序号, 2:数量}，请求带 [4B seq] 前缀。
 */
function handleBuyItem(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const body = frame.body;
  const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
  const reader = new ProtoReader(body.subarray(4));
  let f1 = 0;
  let count = 1;
  for (;;) {
    const tag = reader.readTag();
    if (!tag || tag.wire !== 0) break;
    const v = Number(reader.readVarint());
    if (tag.field === 1) f1 = v;
    else if (tag.field === 2) count = v;
  }
  // 商店序号（28f56f2c f1）→ itemNumId
  const itemNumId = DUEL_SHOP_INDEX_TO_ITEM[f1] ?? 0;
  if (itemNumId > 0) {
    const resp = buildBuyItemResp(seq, itemNumId, Math.max(1, count));
    if (resp) {
      logger.info("arkhub-gateway", `道具购买 itemNumId=${itemNumId} ×${count} → 响应`);
      ctx.send(8, (frame.subID & ~0xffffffffn) | GW_BUY_ITEM_RESP, resp);
      try {
        ctx.opts.onBuyProp?.(ctx.state.uid, itemNumId, Math.max(1, count));
      } catch (e) {
        logger.warn("arkhub-gateway", `道具购买处理失败: ${(e as Error).message}`);
      }
      return;
    }
  }
  // 未知道具 → 通用 ACK
  ctx.send(8, frame.subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
}

/** 使用道具（UseItemReq：{1:item_id, 2:count}）→ UseItemResp（0x28f5de74）{1:code=100} */
function handleUseItem(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const reader = new ProtoReader(frame.body);
  let itemId = 0;
  let count = 1;
  for (;;) {
    const tag = reader.readTag();
    if (!tag || tag.wire !== 0) break;
    const v = Number(reader.readVarint());
    if (tag.field === 1) itemId = v;
    else if (tag.field === 2) count = v;
  }
  logger.info("arkhub-gateway", `使用道具 item_id=${itemId || "?"} ×${count}`);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_USE_ITEM_RESP, buildUseItemResp());
}

/**
 * 像素上传 token（RequestPixelArtUploadTokenReq）
 * 请求形状：[4B 请求序号] {1:pixel_art_id(ulong), 2:md5(string)}——
 * 官服抓包（2026-08-12）：新画布上传仅带 {2:md5}（pixel_art_id 不下发=0），
 * 已存在画布重传带 {1:pixel_art_id}。响应 [4B seq回显] + {1:code=100, 2:credential}。
 * 同时登记上传 token → 分配的 id（HTTP savePixelArt 消费），保证客户端用该 id
 * 调 getPixelArt 加载画像时命中（上传后无法加载的根因：token id 与落盘 id 不一致）。
 */
function handlePixelUploadToken(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const body = frame.body;
  const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
  const reader = new ProtoReader(body.subarray(4));
  let pixelArtId = 0;
  let md5 = "";
  for (;;) {
    const tag = reader.readTag();
    if (!tag) break;
    if (tag.wire === 0) {
      const v = reader.readVarint();
      if (tag.field === 1) pixelArtId = Number(v);
    } else if (tag.wire === 2) {
      const s = reader.readString();
      if (tag.field === 2) md5 = s;
    } else break;
  }
  logger.info(
    "arkhub-gateway",
    `像素上传 token pixel_art_id=${pixelArtId || "?"} md5=${md5 || "?"} (seq=${seq})`,
  );
  const cred = buildPixelUploadTokenResp(seq, pixelArtId, md5);
  if (cred.id > 0) registerPixelUploadToken(cred.token, cred.id, md5);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_PIXEL_UPLOAD_TOKEN_RESP, cred.buffer);
}

/**
 * 像素保存确认（SavePixelArtReq：{1:pixel_art_id, 2:upload_success, 3:do_publish}）
 * 官服抓包（2026-08-12）：body 为纯 protobuf 无 seq 前缀，fire-and-forget 无 ACK——
 * 服务端随后主动推 PixelArtDataAlterNotify（31d62bbd），客户端据此匹配 id+md5
 * 确认保存成功并刷新列表（缺此推送客户端会判定保存失败）。
 */
function handleSavePixelArt(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const reader = new ProtoReader(frame.body);
  let pixelArtId = 0;
  for (;;) {
    const tag = reader.readTag();
    if (!tag || tag.wire !== 0) break;
    const v = reader.readVarint();
    if (tag.field === 1) pixelArtId = Number(v);
  }
  // 像素索引读取 md5（savePixelArt 落盘后索引含 md5）——通知帧匹配用
  const meta = pixelMeta(pixelArtId);
  logger.info(
    "arkhub-gateway",
    `像素保存确认 id=${pixelArtId || "?"} md5=${meta?.md5?.slice(0, 8) ?? "?"} → PixelArtDataAlterNotify`,
  );
  // PixelArtDataAlterNotify：altered 新保存的条目 + 剩余发布次数（f9）——
  // 客户端据此刷新自己的像素列表/发布数（此前字段号错，客户端收不到列表）。
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_PIXEL_DATA_ALTER_NOTIFY,
    buildPixelDataAlterNotify(ctx.state.uid, {
      altered: meta ? [{ id: pixelArtId, md5: meta.md5, ts: meta.ts }] : [],
    }),
  );
}

/**
 * 收集画像（CollectPixelArtReq：{1:target_uid, 2:pixel_art_id}）——单机无真实
 * 匿名画像，解析后记录日志，回 {1:100} ACK（subID+1）。
 */
function handleCollectPixelArt(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const reader = new ProtoReader(frame.body);
  let targetUid = "";
  let pixelArtId = 0;
  for (;;) {
    const tag = reader.readTag();
    if (!tag) break;
    if (tag.wire === 2) {
      const s = reader.readString();
      if (tag.field === 1) targetUid = s;
    } else if (tag.wire === 0) {
      const v = reader.readVarint();
      if (tag.field === 2) pixelArtId = Number(v);
    } else break;
  }
  logger.info(
    "arkhub-gateway",
    `收集画像 target_uid=${targetUid || "?"} pixel_art_id=${pixelArtId || "?"} → ACK`,
  );
  ctx.send(8, frame.subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
}

/**
 * 删除像素（DeletePixelArtReq）：[4B 请求序号] {1:pixel_art_id}（官服抓包 2026-08-12
 * 带 seq 前缀）→ DeletePixelArtResp（0x31d67d3e）[4B seq回显] {1:code=100}。
 * ⚠️ 此前按纯 protobuf 从 body[0] 解析把 seq 当 id（解析为 0）→ 删不掉；
 * 成功后同时删除本地像素文件（deletePixel：移除 .bin + 索引）并推变更通知。
 */
function handleDeletePixel(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const body = frame.body;
  const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
  let pixelArtId = 0;
  const reader = new ProtoReader(body.subarray(4));
  const tag = reader.readTag();
  if (tag && tag.wire === 0) pixelArtId = Number(reader.readVarint());
  if (pixelArtId > 0) {
    try {
      deletePixel(pixelArtId);
    } catch (e) {
      logger.warn("arkhub-gateway", `像素删除落盘失败: ${(e as Error).message}`);
    }
  }
  logger.info("arkhub-gateway", `删除像素 pixel_art_id=${pixelArtId || "?"} → Resp (seq=${seq})`);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_DELETE_PIXEL_RESP, buildDeletePixelResp(seq));
  // 删除成功后推 PixelArtDataAlterNotify（deleted 该 id + 剩余发布次数 f9），
  // 客户端据此移除列表项并刷新发布次数（缺此推送删除 UI 不生效）
  if (pixelArtId > 0) {
    ctx.send(
      8,
      (frame.subID & ~0xffffffffn) | GW_PIXEL_DATA_ALTER_NOTIFY,
      buildPixelDataAlterNotify(ctx.state.uid, { deleted: [pixelArtId] }),
    );
  }
}

/**
 * 删除像素收藏（DeletePixelArtCollectionReq）：[4B 请求序号] {1:pixel_art_id} →
 * DeletePixelArtCollectionResp（0x31d6ea56）[4B seq回显] {1:code=100}。
 * （收藏他人画像不删本地文件，仅回 ACK。）
 */
function handleDeletePixelCollection(
  ctx: ArkhubGatewayHandlerContext,
  frame: ArkhubGatewayFrame,
): void {
  const body = frame.body;
  const seq = body.length >= 4 ? body.readUInt32BE(0) : 0;
  let pixelArtId = 0;
  const reader = new ProtoReader(body.subarray(4));
  const tag = reader.readTag();
  if (tag && tag.wire === 0) pixelArtId = Number(reader.readVarint());
  logger.info("arkhub-gateway", `删除像素收藏 pixel_art_id=${pixelArtId || "?"} → Resp (seq=${seq})`);
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_DELETE_PIXEL_COLLECTION_RESP,
    buildDeletePixelCollectionResp(seq),
  );
}

/** 注册商店/道具/像素画路由 */
export function registerShopHandlers(router: ArkhubFrameRouter): void {
  router.registerLow(8, GW_DUEL_SHOP_REQ, "商店信息(GetShopInfoReq)", handleGetShopInfo);
  router.registerLow(8, GW_BUY_ITEM_REQ, "购买道具(BuyItemReq)", handleBuyItem);
  router.registerLow(8, GW_USE_ITEM_REQ, "使用道具(UseItemReq)", handleUseItem);
  router.registerLow(8, GW_PIXEL_UPLOAD_TOKEN_REQ, "像素上传token(RequestPixelArtUploadTokenReq)", handlePixelUploadToken);
  router.registerLow(8, GW_SAVE_PIXEL_ART_REQ, "像素保存确认(SavePixelArtReq)", handleSavePixelArt);
  router.registerLow(8, GW_COLLECT_PIXEL_REQ, "收集画像(CollectPixelArtReq)", handleCollectPixelArt);
  router.registerLow(8, GW_DELETE_PIXEL_REQ, "删除像素(DeletePixelArtReq)", handleDeletePixel);
  router.registerLow(8, GW_DELETE_PIXEL_COLLECTION_REQ, "删除像素收藏(DeletePixelArtCollectionReq)", handleDeletePixelCollection);
}
