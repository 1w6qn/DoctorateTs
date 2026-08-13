/**
 * arkhub 网关 TCP 协议解析（arkodc）
 *
 * 官服网关（arkhub-gateway.hypergryph.com:30000）的帧格式（实测，见 capture-forward-mode 记忆）：
 *   [4B 大端总长度][4B 大端消息 ID][8B 头字段（seq/标志等，含义待确认）][protobuf payload]
 *
 * 实测 3176 帧 up 流零断帧；down 流登录阶段（65 帧）同格式，登录后变为另一类结构
 * （连续 protobuf/自定义封装，需进一步逆向——解析器对无法按长度前缀切分的余量如实报告）。
 *
 * 提供：
 *   splitGatewayFrames   —— 按长度前缀切帧（容错：断帧即停，返回余量）
 *   decodeProtobuf       —— 通用 protobuf 解码（varint/64bit/length-delimited/32bit + 嵌套消息）
 *   parseGatewayStream   —— 整流解析 → 帧数组（含解码 payload）+ 余量
 *   MSG_NAMES            —— 观测到的消息 ID → 名称映射（best-effort）
 */
import { logger } from "@utils/logger";

/** 帧头大小：4B 长度 + 4B 消息 ID + 8B 头字段 */
export const GATEWAY_HEADER_SIZE = 16;

/**
 * 观测到的消息 ID → 名称（best-effort，来自抓包 payload 字段 + 客户端协议列表）：
 *   1 — MoveReq（移动同步，payload 8B 非 protobuf：[0, 递增计数]，推测）
 *   2 — MoveNotify（位置广播，payload 16B，down 向，推测）
 *   4 — Login（UserLoginReq up 向：uid/token/设备；UserLoginResp down 向：code/token）
 *   8 — NetProbeData（心跳 08 00 / 网络探针 10 80 02 + 15B / 玩家数据通知 0a ... 多变体）
 */
export const MSG_NAMES: Record<number, string> = {
  1: "MoveReq",
  2: "MoveNotify",
  4: "Login",
  8: "NetProbeData",
};

/** protobuf wire type 名称 */
export const WIRE_NAMES: Record<number, string> = {
  0: "varint",
  1: "fixed64",
  2: "length-delimited",
  3: "start-group",
  4: "end-group",
  5: "fixed32",
};

/** 解码后的 protobuf 字段 */
export interface PbField {
  /** 字段号 */
  field: number;
  /** wire type（0/1/2/5） */
  wire: number;
  /** wire type 名称 */
  wireName: string;
  /** varint 数值 */
  varint?: bigint;
  /** 64-bit 数值 */
  fixed64?: bigint;
  /** 32-bit 数值 */
  fixed32?: number;
  /** length-delimited 原始字节（hex） */
  bytes?: string;
  /** length-delimited 若为合法 UTF-8 字符串则给出 */
  str?: string;
  /** length-delimited 若能再解为嵌套 protobuf 则给出子字段 */
  nested?: PbField[];
}

/**
 * 解码 protobuf 字段序列（通用，不依赖 schema）
 *
 * 支持 wire type 0(varint)/1(fixed64)/2(length-delimited)/5(fixed32)；
 * length-delimited 字段若字节可完整解码为 protobuf 且首个标签合法，则递归为 nested，
 * 否则保留 bytes（并尝试 str）。
 *
 * @param buf - 待解码字节
 * @returns 字段数组；首字节不是合法标签时返回空数组（调用方据此判断是否嵌套消息）
 */
export function decodeProtobuf(buf: Buffer): PbField[] {
  const fields: PbField[] = [];
  let off = 0;
  while (off < buf.length) {
    const tag = readVarint(buf, off);
    if (tag === null) break;
    const tagValue = tag.value;
    off = tag.next;
    const field = Number(tagValue >> 3n);
    const wire = Number(tagValue & 7n);
    if (field === 0 || wire === 6 || wire === 7) {
      // 非法标签：停止（余下字节视为无法解码）
      break;
    }
    const entry: PbField = { field, wire, wireName: WIRE_NAMES[wire] ?? `wire${wire}` };
    switch (wire) {
      case 0: {
        const v = readVarint(buf, off);
        if (!v) { fields.push(entry); off = buf.length; break; }
        entry.varint = v.value;
        off = v.next;
        break;
      }
      case 1: {
        if (off + 8 > buf.length) { fields.push(entry); off = buf.length; break; }
        entry.fixed64 = buf.readBigUInt64LE(off);
        off += 8;
        break;
      }
      case 2: {
        const len = readVarint(buf, off);
        if (!len) { fields.push(entry); off = buf.length; break; }
        const size = Number(len.value);
        off = len.next;
        if (off + size > buf.length) { fields.push(entry); off = buf.length; break; }
        const bytes = buf.subarray(off, off + size);
        entry.bytes = bytes.toString("hex");
        entry.str = toUtf8(bytes);
        // 尝试嵌套解码：仅当首个字段是 varint(0)/length-delimited(2) 且整体不是可读文本
        // （纯 ASCII 字符串如 "100566259" 会被 toUtf8 命中，判为文本而非嵌套消息）
        if (isPlausibleNestedStart(bytes)) {
          const nested = decodeProtobuf(bytes);
          if (nested.length > 0) entry.nested = nested;
        }
        off += size;
        break;
      }
      case 5: {
        if (off + 4 > buf.length) { fields.push(entry); off = buf.length; break; }
        entry.fixed32 = buf.readUInt32LE(off);
        off += 4;
        break;
      }
      default:
        // group 类型（3/4）不再支持：停止
        off = buf.length;
        break;
    }
    fields.push(entry);
  }
  return fields;
}

/** 读 varint，返回 { value, next }；超出边界或损坏返回 null */
function readVarint(buf: Buffer, start: number): { value: bigint; next: number } | null {
  let value = 0n;
  let shift = 0n;
  for (let i = start; i < buf.length && i < start + 10; i++) {
    const b = buf[i];
    value |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value, next: i + 1 };
    shift += 7n;
  }
  return null;
}

/**
 * 判断 length-delimited 字节是否可能为嵌套 protobuf：
 * 首个字段须为 varint(0) 或 length-delimited(2)（游戏消息首字段几乎都是小字段号），
 * 且整体不是可读 UTF-8 文本（纯 ASCII 字符串如 uid 判为文本，避免误判嵌套）
 */
function isPlausibleNestedStart(buf: Buffer): boolean {
  if (buf.length < 2) return false;
  const wire = buf[0] & 7;
  if (wire !== 0 && wire !== 2) return false;
  if (toUtf8(buf) !== undefined) return false;
  return true;
}

/** 尝试 UTF-8 解码（仅当全部字节可解码且无控制字符时给出） */
function toUtf8(buf: Buffer): string | undefined {
  try {
    const s = buf.toString("utf8");
    // 全 ASCII 可打印或合法 UTF-8 中文；含不可见控制符（除 \n\r\t）视为二进制
    if (buf.length > 0 && /^[\x20-\x7e\n\r\t\u00a0-\uffff]*$/.test(s) && s.length === buf.length) {
      return s;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** 单帧解析结果 */
export interface GatewayFrame {
  /** 帧总长（含帧头） */
  len: number;
  /** 消息 ID */
  msgId: number;
  /** 消息名称（MSG_NAMES 命中或未知） */
  name: string;
  /** 头字段 8-11（uint32，疑似 seq） */
  seq: number;
  /** 头字段 12-15（uint32，疑似 flag/计数） */
  flag: number;
  /** 原始头 8B（hex） */
  headerHex: string;
  /** protobuf 解码后的字段（空表示非 protobuf payload） */
  fields: PbField[];
  /** 原始 payload（hex） */
  payloadHex: string;
}

/** 整流解析结果 */
export interface GatewayStreamResult {
  /** 成功切分的帧 */
  frames: GatewayFrame[];
  /** 剩余未解析字节（登录后 down 流等无法按长度前缀切分的部分） */
  remainder: Buffer;
}

/**
 * 按长度前缀切帧
 *
 * @param buffer - 完整字节流
 * @returns 帧数组 + 余量（断帧即停止解析，余量如实保留）
 */
export function splitGatewayFrames(buffer: Buffer): GatewayFrame[] {
  const frames: GatewayFrame[] = [];
  let off = 0;
  while (off + 4 <= buffer.length) {
    const len = buffer.readUInt32BE(off);
    if (len < GATEWAY_HEADER_SIZE || off + len > buffer.length) break;
    const msgId = buffer.readUInt32BE(off + 4);
    const seq = buffer.readUInt32BE(off + 8);
    const flag = buffer.readUInt32BE(off + 12);
    const payload = buffer.subarray(off + GATEWAY_HEADER_SIZE, off + len);
    frames.push({
      len,
      msgId,
      name: MSG_NAMES[msgId] ?? `Msg${msgId}`,
      seq,
      flag,
      headerHex: buffer.subarray(off + 8, off + 16).toString("hex"),
      fields: decodeProtobuf(payload),
      payloadHex: payload.toString("hex"),
    });
    off += len;
  }
  return frames;
}

/**
 * 解析整条网关字节流
 *
 * @param buffer - 原始字节流（up 或 down）
 * @param label - 方向（"up"/"down"，日志用）
 * @returns 解析结果
 */
export function parseGatewayStream(buffer: Buffer, label: string): GatewayStreamResult {
  const frames = splitGatewayFrames(buffer);
  const consumed = frames.reduce((sum, f) => sum + f.len, 0);
  const remainder = buffer.subarray(consumed);
  if (remainder.length > 0) {
    logger.warn(
      "arkodc",
      `${label} 流解析 ${frames.length} 帧后余 ${remainder.length}B 无法按长度前缀切分（登录后 down 流可能为连续 protobuf/自定义封装，需进一步逆向）`,
    );
  }
  return { frames, remainder };
}

/** 将 protobuf 字段树序列化为 JSON 友好对象 */
function fieldsToJson(fields: PbField[]): unknown[] {
  return fields.map((field) => ({
    field: field.field,
    wire: field.wireName,
    varint: field.varint !== undefined ? field.varint.toString() : undefined,
    fixed64: field.fixed64 !== undefined ? field.fixed64.toString() : undefined,
    fixed32: field.fixed32,
    str: field.str,
    bytes: field.bytes,
    nested: field.nested ? fieldsToJson(field.nested) : undefined,
  }));
}

/** 将解析结果序列化为 JSON 友好对象（bytes/varint 等转字符串） */
export function framesToJson(frames: GatewayFrame[]): unknown[] {
  return frames.map((f) => ({
    len: f.len,
    msgId: f.msgId,
    name: f.name,
    seq: f.seq,
    flag: f.flag,
    headerHex: f.headerHex,
    payload: f.fields.length ? fieldsToJson(f.fields) : undefined,
  }));
}
