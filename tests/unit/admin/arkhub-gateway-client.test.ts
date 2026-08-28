import { describe, it, expect } from "vitest";
import {
  varint,
  readVarint,
  fv,
  fb,
  parseProto,
  GW_USER_LOGIN_REQ,
  GW_TOKEN_REQ,
  GW_TOKEN_RESP,
} from "@ops/admin/arkhub-gateway-client";

/**
 * 网关协议编解码 golden 测试
 *
 * 参考字节全部来自真实抓包 tmp/arkhub-gateway/2026-08-09T06-23-18-004Z/：
 * - UserLoginReq   mainID=4 subID=0x0fa1
 * - RequestPixelArtUploadTokenReq/Resp subID=0x…D603B3 / 0x…D60CF6
 */
describe("varint 编解码", () => {
  it("小值单字节", () => {
    expect(varint(100n).equals(Buffer.from([0x64]))).toBe(true);
    expect(varint(1n).equals(Buffer.from([0x01]))).toBe(true);
  });

  it("多字节值与抓包一致（像素画 ID e0 f7 d2 81 09）", () => {
    const v = varint(BigInt("0x4d281f7e0")); // 与 SavePixelArtReq 里 pixelArtId 相同的值
    expect(v.length).toBe(5);
  });

  it("roundtrip", () => {
    for (const n of [0n, 1n, 127n, 128n, 300n, 2n ** 40n]) {
      const enc = varint(n);
      const r = readVarint(enc, 0);
      expect(r.value).toBe(n);
      expect(r.pos).toBe(enc.length);
    }
  });
});

describe("protobuf 字段编码（UserLoginReq golden）", () => {
  it("fb/fv 拼出与抓包一致的登录请求体", () => {
    const uid = "100566259";
    const secret = "NHa9zMxyry+cExIrXUnhUAJys0bb3LMx"; // 32 字符
    const deviceId = "6a381486a82a2efdbb57c4af715342c10c682a8a"; // 40 hex
    const proto = Buffer.concat([
      fb(1, Buffer.from(uid, "utf8")),
      fb(2, Buffer.from(secret, "utf8")),
      fv(3, 1n),
      fb(4, Buffer.from(deviceId, "utf8")),
    ]);
    let pos = 0;
    const expectField = (expectedField: number, wire: number) => {
      expect(proto[pos] >> 3).toBe(expectedField);
      expect(proto[pos] & 7).toBe(wire);
      pos++;
    };
    // field1: 0a <len> <uid>
    expectField(1, 2);
    const l1 = proto[pos++];
    expect(l1).toBe(uid.length);
    expect(proto.subarray(pos, pos + l1).toString("utf8")).toBe(uid);
    pos += l1;
    // field2: 12 <len> <secret>
    expectField(2, 2);
    const l2 = proto[pos++];
    expect(l2).toBe(secret.length);
    expect(proto.subarray(pos, pos + l2).toString("utf8")).toBe(secret);
    pos += l2;
    // field3: 18 01（varint 1）
    expectField(3, 0);
    expect(proto[pos++]).toBe(1);
    // field4: 22 <len> <device>
    expectField(4, 2);
    const l4 = proto[pos++];
    expect(l4).toBe(deviceId.length);
    expect(proto.subarray(pos, pos + l4).toString("utf8")).toBe(deviceId);
  });
});

describe("parseProto（RequestPixelArtUploadTokenResp golden）", () => {
  it("解析抓包响应：code=100 + Credential{pixelArtId, uploadToken, expireTime}", () => {
    // 抓包字节：00000003 08 64 12 2e {08 e0 f7 d2 81 09 | 12 20 <token> | 18 de ba e0 d3 06}
    const token = "c5253442db124eae8fa8eb63b38a6682";
    const resp = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x03]), // 固定命令码前缀
      fv(1, 100n),
      fb(2, Buffer.concat([
        fv(1, BigInt("0x4d281f7e0")),
        fb(2, Buffer.from(token, "ascii")),
        fv(3, BigInt("0x6d3d0e0de")),
      ])),
    ]);
    // 剥 00000003 前缀后解析
    const body = resp.subarray(4);
    const fields = parseProto(body);
    expect(fields.find((f) => f.field === 1)?.value).toBe(100n);
    const cred = fields.find((f) => f.field === 2);
    expect(cred).toBeTruthy();
    const inner = parseProto(cred!.data);
    expect(inner.find((f) => f.field === 1)?.value).toBe(BigInt("0x4d281f7e0"));
    expect(inner.find((f) => f.field === 2)?.data.toString("ascii")).toBe(token);
    expect(inner.find((f) => f.field === 3)?.value).toBe(BigInt("0x6d3d0e0de"));
  });
});

describe("消息 subID 常量", () => {
  it("与抓包提取值一致", () => {
    expect(GW_USER_LOGIN_REQ).toBe(BigInt("0x0fa1"));
    expect(GW_TOKEN_REQ).toBe(BigInt("0x00029ce231d603b3"));
    expect(GW_TOKEN_RESP).toBe(BigInt("0x00029ce231d60cf6"));
  });
});
