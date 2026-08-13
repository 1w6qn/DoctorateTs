import { describe, it, expect } from "vitest";
import {
  decodeProtobuf,
  splitGatewayFrames,
  parseGatewayStream,
  framesToJson,
  decodeWithSchema,
  decodeFixedPayload,
  recoverProtobufRegion,
  recoverProtobufWithPrefixSkip,
  MSG_NAMES,
  MSG_SCHEMAS,
  GATEWAY_HEADER_SIZE,
} from "../../../app/proxy/arkodc";

/** 构造一帧：[4B大端总长][4B消息ID][8B头][payload] */
function frame(msgId: number, payload: Buffer, seq = 0, flag = 0): Buffer {
  const len = GATEWAY_HEADER_SIZE + payload.length;
  const head = Buffer.alloc(16);
  head.writeUInt32BE(len, 0);
  head.writeUInt32BE(msgId, 4);
  head.writeUInt32BE(seq, 8);
  head.writeUInt32BE(flag, 12);
  return Buffer.concat([head, payload]);
}

describe("decodeProtobuf（通用 protobuf 解码）", () => {
  it("varint / length-delimited / fixed64 / fixed32", () => {
    const buf = Buffer.concat([
      Buffer.from([0x08, 0x64]),          // field1 varint 100
      Buffer.from([0x12, 0x03]), Buffer.from("abc"), // field2 len 3
      Buffer.from([0x19]), Buffer.alloc(8), // field3 fixed64 0
      Buffer.from([0x2d]), Buffer.alloc(4), // field5 fixed32 0
    ]);
    const fields = decodeProtobuf(buf);
    expect(fields[0]).toMatchObject({ field: 1, wire: 0, varint: 100n });
    expect(fields[1]).toMatchObject({ field: 2, wire: 2, str: "abc" });
    expect(fields[2]).toMatchObject({ field: 3, wire: 1 });
    expect(fields[3]).toMatchObject({ field: 5, wire: 5 });
  });

  it("length-delimited 嵌套消息递归解码", () => {
    // field2 内嵌 {field1: varint 1}：12 02 08 01
    const fields = decodeProtobuf(Buffer.from([0x12, 0x02, 0x08, 0x01]));
    const nested = fields.find((f) => f.field === 2);
    expect(nested).toBeDefined();
    expect(nested!.nested).toContainEqual(expect.objectContaining({ field: 1, varint: 1n }));
  });

  it("损坏输入（非法 wire type）停止解码不抛异常", () => {
    const fields = decodeProtobuf(Buffer.from([0x0f, 0x01, 0x02])); // field1 wire7
    expect(Array.isArray(fields)).toBe(true);
  });
});

describe("splitGatewayFrames / parseGatewayStream（帧切分）", () => {
  it("按长度前缀切帧，识别 msgId/seq/flag 并解码 payload", () => {
    // 模拟真实 UserLoginReq：field1=uid "100566259", field2=token
    const loginPayload = Buffer.concat([
      Buffer.from([0x0a, 0x09]), Buffer.from("100566259"),
      Buffer.from([0x12, 0x04]), Buffer.from("tok!"),
    ]);
    const stream = Buffer.concat([frame(4, loginPayload, 0, 4001), frame(8, Buffer.from([0x08, 0x00]), 5, 102326)]);
    const result = parseGatewayStream(stream, "test");
    expect(result.remainder.length).toBe(0);
    expect(result.frames).toHaveLength(2);
    expect(result.frames[0]).toMatchObject({ msgId: 4, name: "Login", seq: 0, flag: 4001 });
    expect(result.frames[0].fields).toContainEqual(expect.objectContaining({ field: 1, str: "100566259" }));
    expect(result.frames[1]).toMatchObject({ msgId: 8, name: "NetProbeData" });
    // framesToJson 可序列化
    const json = framesToJson(result.frames) as any[];
    expect(json[0].payload[0]).toMatchObject({ field: 1, str: "100566259" });
  });

  it("未知 msgId 命名为 Msg<N>", () => {
    const stream = frame(77, Buffer.from([0x08, 0x01]));
    const [f] = splitGatewayFrames(stream);
    expect(f.name).toBe("Msg77");
  });

  it("断帧（长度越界/过短）即停止，余量如实保留", () => {
    // 合法帧 + 截断的半帧（长度声明 100 但实际只有 4 字节）
    const good = frame(4, Buffer.from([0x08, 0x01]));
    const trunc = Buffer.from([0x00, 0x00, 0x00, 0x64, 0x00]); // len=100, 但流在这里结束
    const result = parseGatewayStream(Buffer.concat([good, trunc]), "test");
    expect(result.frames).toHaveLength(1);
    expect(result.remainder.length).toBe(5);
  });

  it("MSG_NAMES 覆盖已观测消息", () => {
    expect(MSG_NAMES[1]).toBeDefined();
    expect(MSG_NAMES[4]).toBe("Login");
    expect(MSG_NAMES[8]).toBe("NetProbeData");
  });
});

describe("命名解码（MSG_SCHEMAS → 正常游戏 JSON）", () => {
  it("decodeWithSchema 按字段名映射（字段号 i+1 → fieldNames[i]）", () => {
    const fields = decodeProtobuf(
      Buffer.concat([Buffer.from([0x0a, 0x03]), Buffer.from("abc"), Buffer.from([0x10, 0x2a])]),
    );
    const named = decodeWithSchema(fields, ["name", "count"]);
    expect(named).toEqual({ name: "abc", count: "42" });
  });

  it("splitGatewayFrames 带方向时 Login 帧命名解码（模拟真实 UserLoginReq）", () => {
    const payload = Buffer.concat([
      Buffer.from([0x0a, 0x09]), Buffer.from("100566259"), // field1 uid
      Buffer.from([0x12, 0x04]), Buffer.from("tok!"),      // field2 secret
      Buffer.from([0x18, 0x01]),                           // field3 loginChannel
    ]);
    const [f] = splitGatewayFrames(frame(4, payload), "up");
    expect(f.name).toBe("Login");
    expect(f.named).toMatchObject({ uid: "100566259", secret: "tok!", loginChannel: "1" });
  });

  it("未知 schema 的帧不产生 named 字段", () => {
    const [f] = splitGatewayFrames(frame(8, Buffer.from([0x08, 0x00])), "up");
    expect(f.named).toBeUndefined();
  });

  it("未知定长二进制 payload 按 4B uint32 解释（fixed）", () => {
    const payload = Buffer.alloc(8);
    payload.writeUInt32BE(0, 0);
    payload.writeUInt32BE(1590574, 4);
    const [f] = splitGatewayFrames(frame(99, payload), "up");
    expect(f.fixed).toEqual([0, 1590574]);
  });

  it("已知 FIXED_SCHEMAS 的定长 payload 输出 named（msgId1 = {type, param}）", () => {
    const payload = Buffer.alloc(8);
    payload.writeUInt32BE(0, 0);
    payload.writeUInt32BE(1590574, 4);
    const [f] = splitGatewayFrames(frame(1, payload), "up");
    expect(f.named).toEqual({ type: 0, param: 1590574 });
  });

  it("MSG_SCHEMAS 登录双向字段名齐全", () => {
    expect(MSG_SCHEMAS[4].up).toEqual(["uid", "secret", "loginChannel", "deviceId", "gameContext"]);
    expect(MSG_SCHEMAS[4].down).toEqual(["code", "heartbeatInterval", "reconnectToken", "ip", "port"]);
  });
});

describe("余量恢复（down 登录后连续 protobuf）", () => {
  it("recoverProtobufRegion 扫描最佳起点恢复字段", () => {
    // 构造：3 字节垃圾 + 一段合法 protobuf（field1 varint + field2 len）
    const data = Buffer.concat([
      Buffer.from([0xff, 0xff, 0xff]),
      Buffer.from([0x08, 0x2a]),                     // field1 = 42
      Buffer.from([0x12, 0x03]), Buffer.from("abc"), // field2 = "abc"
      Buffer.from([0x18, 0x01]),                     // field3 = 1
    ]);
    const rec = recoverProtobufRegion(data);
    expect(rec).not.toBeNull();
    expect(rec!.start).toBe(3);
    expect(rec!.fields).toContainEqual(expect.objectContaining({ field: 1, varint: 42n }));
  });

  it("recoverProtobufWithPrefixSkip 跳过 4B 前缀继续解（down 记录流 [00 00 00 type][protobuf]）", () => {
    const record = (uid: string) =>
      Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, 0x05]),      // 4B 前缀
        Buffer.from([0x0a, uid.length]), Buffer.from(uid), // field1 uid
        Buffer.from([0x10, 0x01]),                   // field2 varint
      ]);
    const data = Buffer.concat([record("10001"), record("10002"), record("10003")]);
    const rec = recoverProtobufWithPrefixSkip(data);
    expect(rec).not.toBeNull();
    expect(rec!.prefixSkips).toBe(3); // 3 条记录 = 3 个前缀
    const uids = rec!.fields.filter((f) => f.field === 1 && f.str).map((f) => f.str);
    expect(uids).toEqual(["10001", "10002", "10003"]);
  });

  it("parseGatewayStream 余量含恢复结果", () => {
    const good = frame(4, Buffer.from([0x08, 0x01]));
    // 2 条记录（各 2 字段 = 4 字段 ≥ 阈值）
    const record = (uid: string) =>
      Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, 0x05]),
        Buffer.from([0x0a, uid.length]), Buffer.from(uid),
        Buffer.from([0x10, 0x01]),
      ]);
    const remain = Buffer.concat([record("10001"), record("10002")]);
    const result = parseGatewayStream(Buffer.concat([good, remain]), "down");
    expect(result.frames).toHaveLength(1);
    expect(result.recovered).toBeDefined();
    const uids = result.recovered!.fields.filter((f) => f.field === 1 && f.str).map((f) => f.str);
    expect(uids).toEqual(["10001", "10002"]);
  });
});
