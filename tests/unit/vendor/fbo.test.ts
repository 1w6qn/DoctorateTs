/**
 * FBO 解码器：窄整型与报文内建表的读取
 *
 * 覆盖 2026-09-12 修复的两处解码缺陷：
 *   - 窄整型（`ubyte`/`sbyte`/`short`/`ushort`）：CS 的 Byte/Int16 在报文里就是 1/2 字节，
 *     旧实现一律按 i32 读 → 越读相邻字节（实测 BuildingData.ObstaclePoint.edgeWalkableMask）
 *   - `hg__internal__*` 报文内建表：解码器不把它当子表 → 返回 null
 *     （实测 gacha DynMeta/LinkageParam/LimitParam、activity DynActs 全为空）
 *
 * 测试用**手工构造的 FlatBuffers 缓冲区**，不依赖 reference/ 下的真实数据。
 */
import { describe, it, expect } from "vitest";
import { FBO, type FieldInfo, type Schema } from "../../../scripts/vendor/fbo";

/**
 * 构造「根表只含一个标量字段（slot 4）」的缓冲区
 * @param fieldType - 字段类型 token
 * @param put - 把值写进缓冲区（参数为字段字节偏移）
 */
function scalarBuf(fieldType: string, put: (buf: Uint8Array, off: number) => void): Uint8Array {
  const buf = new Uint8Array(32);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 16, true); // 根表偏移
  dv.setUint16(4, 6, true); // vtable 大小（1 个字段 = 2 + 2*1）
  dv.setUint16(6, 4, true); // 表大小（读取器未用）
  dv.setUint16(8, 8, true); // slot 4 的字段项：pos + 8 = 24
  dv.setUint32(16, 12, true); // soffset → vtable 在 4
  put(buf, 24);
  return buf;
}

const schema = (type: string): Schema => ({
  root: "clz_Root",
  tables: { clz_Root: [{ name: "Value", type, slot: 4 }] },
});

describe("FBO 标量读取", () => {
  it("ubyte 只读 1 字节（不被相邻字节污染）", () => {
    const buf = scalarBuf("ubyte", (b, off) => {
      b[off] = 200;
      b[off + 1] = 0xff; // 相邻字节若被并入会得到 0x0000ffc8
      b[off + 2] = 0xff;
      b[off + 3] = 0xff;
    });
    expect(new FBO(buf, schema("ubyte")).toJson().Value).toBe(200);
  });

  it("sbyte 按有符号 1 字节读", () => {
    const buf = scalarBuf("sbyte", (b, off) => {
      b[off] = 0x80; // -128
      b[off + 1] = 0xff;
    });
    expect(new FBO(buf, schema("sbyte")).toJson().Value).toBe(-128);
  });

  it("short / ushort 按 2 字节读", () => {
    const sBuf = scalarBuf("short", (b, off) => {
      b[off] = 0x00;
      b[off + 1] = 0x80; // -32768
      b[off + 2] = 0xff;
      b[off + 3] = 0xff;
    });
    expect(new FBO(sBuf, schema("short")).toJson().Value).toBe(-32768);
    const uBuf = scalarBuf("ushort", (b, off) => {
      b[off] = 0xff;
      b[off + 1] = 0xff; // 65535
    });
    expect(new FBO(uBuf, schema("ushort")).toJson().Value).toBe(65535);
  });

  it("负样本自证：同一数据按 int 读会越读相邻字节", () => {
    const buf = scalarBuf("int", (b, off) => {
      b[off] = 200;
      b[off + 1] = 0xff;
      b[off + 2] = 0xff;
      b[off + 3] = 0xff;
    });
    // 0xffffffc8 → -56：正是「用 i32 读 ubyte」时的错误值
    expect(new FBO(buf, schema("int")).toJson().Value).toBe(-56);
  });
});

describe("FBO 向量与内建表", () => {
  it("vec:ubyte 元素步长为 1", () => {
    const buf = new Uint8Array(48);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 16, true);
    dv.setUint16(4, 6, true);
    dv.setUint16(6, 4, true);
    dv.setUint16(8, 8, true); // 字段在 24：uoffset → 24 + 12 = 36（向量头）
    dv.setUint32(16, 12, true);
    dv.setUint32(24, 12, true);
    dv.setUint32(36, 3, true); // 长度 3
    buf[40] = 7;
    buf[41] = 8;
    buf[42] = 9;
    expect(new FBO(buf, schema("vec:ubyte")).toJson().Value).toEqual([7, 8, 9]);
  });

  it("hg__internal__ 前缀按子表读（不再是 null）", () => {
    const buf = new Uint8Array(72);
    const dv = new DataView(buf.buffer);
    // 根表：一个 hg__internal__JObject 字段
    dv.setUint32(0, 16, true);
    dv.setUint16(4, 6, true);
    dv.setUint16(6, 4, true);
    dv.setUint16(8, 24, true); // 字段在 16 + 24 = 40... 见下
    dv.setUint32(16, 12, true);
    dv.setUint32(24, 16, true); // 子表位置 = 24 + 16 = 40
    // 子表 vtable 在 28
    dv.setUint16(28, 6, true);
    dv.setUint16(30, 4, true);
    dv.setUint16(32, 8, true); // 子表字段（Base64）在 40 + 8 = 48
    dv.setUint32(40, 12, true); // soffset → 28
    dv.setUint32(48, 8, true); // 字符串位置 = 48 + 8 = 56
    dv.setUint32(56, 2, true); // 字符串长度 2
    buf[60] = 0x68;
    buf[61] = 0x69; // "hi"
    const s: Schema = {
      root: "clz_Root",
      tables: {
        clz_Root: [{ name: "DynMeta", type: "hg__internal__JObject", slot: 6 }] as FieldInfo[],
        hg__internal__JObject: [{ name: "Base64", type: "string", slot: 4 }],
      },
    };
    // slot 6 的字段项在 vtable 偏移 6 处（= 字节 10）
    dv.setUint16(10, 8, true); // 字段在 16 + 8 = 24
    dv.setUint16(4, 8, true); // vtable 扩到 2 个字段
    expect(new FBO(buf, s).toJson().DynMeta).toEqual({ Base64: "hi" });
  });
});
