/**
 * 通用 FlatBuffers Objects (FBO) 读取器（Arknights excel FBO 解码，行为对齐 fbo.py）。
 * 由 schema JSON（scripts/vendor/fbs-schemas/*.json）驱动：字段名 + 类型 + vtable slot。
 * 纯 Key/Value 表折叠为 dict（同 _is_pure_kv），DataPair 保留完整对象。
 */

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

export class FBO {
  private buf: Uint8Array;
  private depth = 0;

  constructor(buf: Uint8Array, private schema: Schema) {
    this.buf = buf;
  }

  toJson(): any {
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

  private tableToJson(cls: string, pos: number): any {
    if (++this.depth > 200) {
      this.depth--;
      return null;
    }
    const out = this._tableToJson(cls, pos);
    this.depth--;
    return out;
  }
  private _tableToJson(cls: string, pos: number): any {
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
      const out: any = {};
      if (keyOff) out[String(this.readFieldValue(keyField, keyOff))] = valOff ? this.readFieldValue(valField, valOff) : null;
      return out;
    }
    // 完整对象
    const out: any = {};
    for (const f of fields) {
      const off = this.fieldOffset(pos, f.slot);
      if (off === 0) continue; // 字段缺省 → null（不输出）
      out[f.name] = this.readFieldValue(f, off);
    }
    return out;
  }

  private readFieldValue(f: FieldInfo, off: number): any {
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
        // 子表
        if (t.startsWith("clz_") || t.startsWith("dict__") || t.startsWith("kvp__")) {
          if (off + 4 > this.buf.length) return null;
          const childPos = off + this.u32(off);
          if (childPos >= this.buf.length) return null;
          return this.tableToJson(t, childPos);
        }
        return null;
    }
  }

  private readVector(elemType: string, off: number): any {
    if (off + 4 > this.buf.length) return null;
    const vecPos = off + this.u32(off);
    if (vecPos < 4 || vecPos >= this.buf.length) return null;
    const len = this.u32(vecPos); // 长度在 vecPos（元素区从 vecPos+4 起）
    if (len > this.buf.length / 4) return null; // 防御：长度不合理
    const base = vecPos + 4;
    // 标量元素步长（bool=1, long/double=8, 其余 4）
    let stride = 4;
    if (elemType === "bool") stride = 1;
    else if (elemType === "long" || elemType === "double") stride = 8;
    // 元素为纯 KV 表 → 折叠为 dict（同 fbo.py 的 vector 分支）
    const elemFields = this.schema.tables[elemType];
    if (elemFields) {
      const names = elemFields.map((x) => x.name);
      if (
        names.includes("Key") && names.includes("Value") &&
        names.every((n) => n === "Key" || n === "Value")
      ) {
        const out: any = {};
        for (let i = 0; i < len; i++) {
          const childPos = base + 4 * i;
          const pos2 = childPos + this.u32(childPos);
          if (pos2 < 4 || pos2 >= this.buf.length) continue;
          const item = this.tableToJson(elemType, pos2);
          if (item && typeof item === "object") Object.assign(out, item);
        }
        return out;
      }
    }
    const out: any[] = [];
    for (let i = 0; i < len; i++) {
      const childPos = base + stride * i;
      if (elemType === "string") {
        out.push(this.readString(childPos));
      } else if (elemType === "bool") {
        out.push(this.buf[childPos] !== 0);
      } else if (elemType === "int" || elemType === "enum") {
        out.push(this.i32(childPos));
      } else if (elemType === "long") {
        out.push(childPos + 8 <= this.buf.length ? this.u32(childPos) + this.u32(childPos + 4) * 4294967296 : null);
      } else if (elemType === "float") {
        out.push(childPos + 4 <= this.buf.length ? truncateFloat(this.f32(childPos)) : null);
      } else if (elemType === "double") {
        out.push(childPos + 8 <= this.buf.length ? truncateFloat(this.f64(childPos)) : null);
      } else if (elemType.startsWith("list_")) {
        // 嵌套向量（vec:list_int / vec:list_float → 元素本身为向量，Indirect uoffset）
        // 修复：原实现把 list_* 当子表解码 → 空对象 {}（gamedata_const 的
        // characterExpMap/maxLevel/evolveGoldCost/characterUpgradeCostMap 全部解码成空数组）
        const pos2 = childPos + this.u32(childPos);
        if (pos2 < 4 || pos2 >= this.buf.length) {
          out.push(null);
          continue;
        }
        const innerLen = this.u32(pos2);
        const innerBase = pos2 + 4;
        const innerType = elemType.slice("list_".length); // int | float | long | double ...
        const inner: number[] = [];
        for (let j = 0; j < innerLen && innerBase + 4 * j + 4 <= this.buf.length; j++) {
          if (innerType === "float") {
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
