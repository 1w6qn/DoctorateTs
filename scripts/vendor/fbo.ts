/**
 * 通用 FlatBuffers Objects (FBO) 读取器（Arknights excel FBO 解码，行为对齐 fbo.py）。
 * 由 schema JSON（scripts/vendor/fbs-schemas/*.json）驱动：字段名 + 类型 + vtable slot。
 * 纯 Key/Value 表折叠为 dict（同 _is_pure_kv），DataPair 保留完整对象。
 *
 * 解码产物是 excel 表数据（只读 JSON 域）→ 统一用 `JsonValue`（见 docs/type-system-audit.md §3.1）。
 */
import { isJsonObject, type JsonObject, type JsonValue } from "@excel/json-value";

export interface FieldInfo {
  name: string;
  type: string; // string | bool | enum | long | float | double | int | clz_... | dict__... | vec:...
  slot: number;
}
export interface Schema {
  root: string;
  tables: Record<string, FieldInfo[]>;
  enums?: Record<string, Record<string, number>>;
}

function truncateFloat(value: number): number {
  // CompatibleFloat：7 位有效数字截断
  if (value === 0) return 0;
  const l = Math.floor(Math.log10(Math.abs(value))) + 1;
  const r = l < 7 ? 7 - l : 0;
  const s = value.toFixed(r);
  return parseFloat(s);
}

/**
 * 可选的**报文真值审计钩子**：每读到一个表对象就回调一次
 *
 * 用途见 `scripts/schema-audit.ts`：vtable 声明的字段数 = 官方写入方的表结构字段数，
 * 与本地 schema 的字段数比对即可发现「本地缺字段/多字段」。默认未设置，零开销。
 */
export type TableObserver = (cls: string, vtableFields: number, present: (field: string) => boolean) => void;

export class FBO {
  private buf: Uint8Array;
  private depth = 0;
  /** 审计钩子（可选） */
  static observer: TableObserver | null = null;

  constructor(buf: Uint8Array, private schema: Schema) {
    this.buf = buf;
  }

  toJson(): JsonValue {
    const pos = this.u32(0);
    return this.tableToJson(this.schema.root, pos);
  }

  private u32(off: number): number {
    const b = this.buf;
    return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
  }
  private i32(off: number): number {
    return this.u32(off) | 0;
  }
  private f32(off: number): number {
    return new DataView(this.buf.buffer, this.buf.byteOffset + off, 4).getFloat32(0, true);
  }
  private f64(off: number): number {
    return new DataView(this.buf.buffer, this.buf.byteOffset + off, 8).getFloat64(0, true);
  }

  /** 读表对象的字段偏移（slot = flatbuffers Offset(N)，vtable 条目在 vtablePos+slot） */
  private fieldOffset(pos: number, slot: number): number {
    if (pos < 4 || pos >= this.buf.length) return 0;
    const soffset = this.u32(pos);
    if (soffset === 0) return 0;
    const vtablePos = (pos - soffset) >>> 0; // u32 回绕
    if (vtablePos >= this.buf.length) return 0;
    // 关键：slot 超出 vtable 声明大小 → 字段缺省（flatbuffers Offset 语义）
    const vtableSize = (this.buf[vtablePos] | (this.buf[vtablePos + 1] << 8)) >>> 0;
    if (slot >= vtableSize) return 0;
    const entry = (this.buf[vtablePos + slot] | (this.buf[vtablePos + slot + 1] << 8)) >>> 0;
    if (entry === 0) return 0;
    return pos + entry;
  }

  private readString(off: number): string {
    if (off + 4 > this.buf.length) return "";
    const strPos = off + this.u32(off);
    if (strPos < 4 || strPos + 4 > this.buf.length) return "";
    const len = this.u32(strPos); // 字符串：uoffset 指向长度，字节在 strPos+4
    if (len > this.buf.length) return "";
    const bytes = this.buf.subarray(strPos + 4, strPos + 4 + len);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }

  private tableToJson(cls: string, pos: number): JsonValue {
    if (++this.depth > 200) {
      this.depth--;
      return null;
    }
    const out = this._tableToJson(cls, pos);
    this.depth--;
    return out;
  }
  private _tableToJson(cls: string, pos: number): JsonObject {
    const fields = this.schema.tables[cls];
    if (!fields) return {};
    const names = fields.map((f) => f.name);
    // 纯 Key/Value 表 → 折叠为 {key: value}（同 fbo._is_pure_kv）
    const pureKv =
      names.length >= 1 && names.includes("Key") && names.includes("Value") &&
      names.every((n) => n === "Key" || n === "Value");
    const keyField = fields.find((f) => f.name === "Key");
    const valField = fields.find((f) => f.name === "Value");
    if (pureKv && keyField && valField) {
      const keyOff = this.fieldOffset(pos, keyField.slot);
      const valOff = this.fieldOffset(pos, valField.slot);
      const out: JsonObject = {};
      if (keyOff) out[String(this.readFieldValue(keyField, keyOff))] = valOff ? this.readFieldValue(valField, valOff) : null;
      return out;
    }
    // 完整对象
    const out: JsonObject = {};
    if (FBO.observer) {
      const soffset0 = this.u32(pos);
      const vpos0 = (pos - soffset0) >>> 0;
      if (soffset0 !== 0 && vpos0 < this.buf.length) {
        const vsize = (this.buf[vpos0] | (this.buf[vpos0 + 1] << 8)) >>> 0;
        FBO.observer(cls, vsize / 2 - 2, (name: string) => {
          const f = fields.find((x) => x.name === name);
          return f ? this.fieldOffset(pos, f.slot) !== 0 : false;
        });
      }
    }
    for (const f of fields) {
      const off = this.fieldOffset(pos, f.slot);
      if (off === 0) {
        // flatbuffers 缺省语义：官方序列化器对等于默认值的字段不写入
        //（如 StageType=MAIN=0 → 所有主线关卡缺省该字段），缺失即默认值——
        // 标量（int/enum/long/float/double）→ 0、bool → false、string/对象 → null。
        // 修复：原实现直接跳过缺省字段 → 解码记录缺 30 字段（对齐 ArknightsGameData/
        // OpenArknightsFBS 读取行为后 stageType/goldGain 等与 AGD 完全一致）。
        const dv = this.defaultValue(f.type);
        if (dv !== undefined) out[f.name] = dv;
        continue;
      }
      out[f.name] = this.readFieldValue(f, off);
    }
    return out;
  }

  /** 缺省字段的默认值（flatbuffers 标量 0/false；对象/字符串 null） */
  private defaultValue(t: string): JsonValue | undefined {
    switch (t) {
      case "bool":
        return false;
      case "int":
      case "enum":
      case "long":
      case "float":
      case "double":
      case "ubyte":
      case "sbyte":
      case "short":
      case "ushort":
        return 0;
      case "string":
        return null;
      default:
        // vec:/clz_/dict__/kvp_ 等对象字段缺省 → null
        if (
          t.startsWith("vec:") ||
          t.startsWith("clz_") ||
          t.startsWith("dict__") ||
          t.startsWith("kvp__") ||
          t.startsWith("hg__internal__")
        ) {
          return null;
        }
        return undefined; // 未知类型：不输出
    }
  }

  private readFieldValue(f: FieldInfo, off: number): JsonValue {
    if (off < 4 || off >= this.buf.length) return null;
    const t = f.type;
    switch (t) {
      case "string":
        return this.readString(off);
      case "bool":
        return this.buf[off] !== 0;
      case "int":
      case "enum":
        return this.i32(off);
      // 窄整型：FBO 线上就是 1/2 字节（CS 的 Byte/Int16 等），按 i32 读会越读相邻字节
      case "ubyte":
        return this.buf[off];
      case "sbyte":
        return (this.buf[off] << 24) >> 24;
      case "short":
        return off + 2 <= this.buf.length ? ((this.buf[off] | (this.buf[off + 1] << 8)) << 16) >> 16 : null;
      case "ushort":
        return off + 2 <= this.buf.length ? this.buf[off] | (this.buf[off + 1] << 8) : null;
      case "long":
        // i64 低位读取（Arknights 数据无超 2^53 场景）
        return off + 8 <= this.buf.length ? this.u32(off) + this.u32(off + 4) * 4294967296 : null;
      case "float":
        return off + 4 <= this.buf.length ? truncateFloat(this.f32(off)) : null;
      case "double":
        return off + 8 <= this.buf.length ? truncateFloat(this.f64(off)) : null;
      default:
        if (t.startsWith("vec:")) {
          return this.readVector(t.slice(4), off);
        }
        // 子表（clz_ 类表 / dict__/kvp__ 键值对表 / hg__internal__* 报文内建表）
        if (t.startsWith("clz_") || t.startsWith("dict__") || t.startsWith("kvp__") || t.startsWith("hg__internal__")) {
          if (off + 4 > this.buf.length) return null;
          const childPos = off + this.u32(off);
          if (childPos >= this.buf.length) return null;
          return this.tableToJson(t, childPos);
        }
        return null;
    }
  }

  private readVector(elemType: string, off: number): JsonValue {
    if (off + 4 > this.buf.length) return null;
    const vecPos = off + this.u32(off);
    if (vecPos < 4 || vecPos >= this.buf.length) return null;
    const len = this.u32(vecPos); // 长度在 vecPos（元素区从 vecPos+4 起）
    if (len > this.buf.length / 4) return null; // 防御：长度不合理
    const base = vecPos + 4;
    // 标量元素步长（bool/ubyte/sbyte=1, short/ushort=2, long/double=8, 其余 4）
    let stride = 4;
    if (elemType === "bool" || elemType === "ubyte" || elemType === "sbyte") stride = 1;
    else if (elemType === "short" || elemType === "ushort") stride = 2;
    else if (elemType === "long" || elemType === "double") stride = 8;
    // 元素为纯 KV 表 → 折叠为 dict（同 fbo.py 的 vector 分支）
    const elemFields = this.schema.tables[elemType];
    if (elemFields) {
      const names = elemFields.map((x) => x.name);
      if (
        names.includes("Key") && names.includes("Value") &&
        names.every((n) => n === "Key" || n === "Value")
      ) {
        const out: JsonObject = {};
        for (let i = 0; i < len; i++) {
          const childPos = base + 4 * i;
          const pos2 = childPos + this.u32(childPos);
          if (pos2 < 4 || pos2 >= this.buf.length) continue;
          const item = this.tableToJson(elemType, pos2);
          if (isJsonObject(item)) Object.assign(out, item);
        }
        return out;
      }
    }
    const out: JsonValue[] = [];
    for (let i = 0; i < len; i++) {
      const childPos = base + stride * i;
      if (elemType === "string") {
        out.push(this.readString(childPos));
      } else if (elemType === "bool") {
        out.push(this.buf[childPos] !== 0);
      } else if (elemType === "int" || elemType === "enum") {
        out.push(this.i32(childPos));
      } else if (elemType === "ubyte") {
        out.push(this.buf[childPos]);
      } else if (elemType === "sbyte") {
        out.push((this.buf[childPos] << 24) >> 24);
      } else if (elemType === "short") {
        out.push(childPos + 2 <= this.buf.length ? ((this.buf[childPos] | (this.buf[childPos + 1] << 8)) << 16) >> 16 : null);
      } else if (elemType === "ushort") {
        out.push(childPos + 2 <= this.buf.length ? this.buf[childPos] | (this.buf[childPos + 1] << 8) : null);
      } else if (elemType === "long") {
        out.push(childPos + 8 <= this.buf.length ? this.u32(childPos) + this.u32(childPos + 4) * 4294967296 : null);
      } else if (elemType === "float") {
        out.push(childPos + 4 <= this.buf.length ? truncateFloat(this.f32(childPos)) : null);
      } else if (elemType === "double") {
        out.push(childPos + 8 <= this.buf.length ? truncateFloat(this.f64(childPos)) : null);
      } else if (elemType.startsWith("list_")) {
        // list_* 是 flatbuffers 的"列表表"（表类型，唯一字段 Data@4 = vec:<inner>）：
        // 元素是 uoffset 指向该表对象，须读其 Data 字段（uoffset → 向量头 [len][元素...]）。
        // 修复：原实现把 list 表位置当向量头直接读 len → 把 Data 字段的 uoffset 值当整数、
        // 长度虚读（gamedata_const.characterExpMap/maxLevel 解码成垃圾长数组、sandbox_perm
        // Triangles 99760 元素 → JSON.stringify 超限 OOM；旧缓存数据由更早正确解码器生成，
        // 重解码后即暴露）。list_string 同样经 Data 字段读。
        const pos2 = childPos + this.u32(childPos); // list 表位置
        if (pos2 < 4 || pos2 >= this.buf.length) {
          out.push(null);
          continue;
        }
        const lvt = (pos2 - this.u32(pos2)) >>> 0;
        const dataEntry = lvt + 4 < this.buf.length ? (this.buf[lvt + 4] | (this.buf[lvt + 5] << 8)) : 0;
        if (!dataEntry) {
          out.push([]);
          continue;
        }
        const dataOff = pos2 + dataEntry; // Data 字段（uoffset）
        const vecPos2 = dataOff + this.u32(dataOff);
        if (vecPos2 < 4 || vecPos2 >= this.buf.length) {
          out.push([]);
          continue;
        }
        const innerLen = this.u32(vecPos2);
        const innerBase = vecPos2 + 4;
        const innerType = elemType.slice("list_".length); // string | int | float | long | double ...
        const inner: JsonValue[] = [];
        for (let j = 0; j < innerLen && innerBase + 4 * j + 4 <= this.buf.length; j++) {
          if (innerType === "string") {
            inner.push(this.readString(innerBase + 4 * j));
          } else if (innerType === "float") {
            inner.push(truncateFloat(this.f32(innerBase + 4 * j)));
          } else if (innerType === "long") {
            inner.push(this.u32(innerBase + 4 * j) + this.u32(innerBase + 4 * j + 4) * 4294967296);
          } else {
            inner.push(this.i32(innerBase + 4 * j));
          }
        }
        out.push(inner);
      } else {
        // 表元素（Indirect，4 字节 uoffset）
        const pos2 = childPos + this.u32(childPos);
        if (pos2 < 4 || pos2 >= this.buf.length) {
          out.push(null);
          continue;
        }
        out.push(this.tableToJson(elemType, pos2));
      }
    }
    return out;
  }
}
