#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dump-cs-signature.py — 从 Cpp2IL 产出的 dummy DLL 生成签名文件

产出格式与 reference/com.hypergryph.arknights_2.7.61.cs 一致（Il2CppDumper 风格签名 dump，
无方法体），供 scripts/generate-types.ts（parseFile）消费：
  - public class/struct Torappu.* : base, ifaces { public <Type> <field>; ... }
  - public enum Torappu.* : { public const <Enum> NAME = <n>; ... }
  - 嵌套类型点号展平（Outer.Inner）；Torappu 类型带命名空间前缀，其余仅渲染嵌套路径

用法：
  python scripts/dump-cs-signature.py --in <cpp2il_out目录> --out <输出.cs>
  # --in 默认 tmp/decompile/cpp2il_out；--out 缺省输出到 stdout；--only 限定程序集

说明：字段/方法偏移注释统一为 // 0x0（解析器不消费；真实偏移见 Cpp2IL 的
Cpp2IlInjected.FieldOffset/Address 属性或 reference/arknights-<ver>-csharp/）。
纯 Python ECMA-335 元数据读取，零第三方依赖。
"""

import argparse
import struct
import sys
from pathlib import Path

# ---------------- ECMA-335 常量 ----------------
ELEMENT_TYPE = {
    0x01: "System.Void", 0x02: "System.Boolean", 0x03: "System.Char",
    0x04: "System.SByte", 0x05: "System.Byte", 0x06: "System.Int16", 0x07: "System.UInt16",
    0x08: "System.Int32", 0x09: "System.UInt32", 0x0A: "System.Int64", 0x0B: "System.UInt64",
    0x0C: "System.Single", 0x0D: "System.Double", 0x0E: "System.String", 0x1C: "System.Object",
    0x16: "System.TypedReference", 0x18: "System.IntPtr", 0x19: "System.UIntPtr",
}

# 表 ID -> 列布局（对齐 Mono.Cecil 实际写入：Module 的 Enc* 为 u2、Constant 的 Type|Pad 合并 u2、
# ClassLayout 第三列为 TypeDef 简单索引；"i:0xNN"=指向表的简单索引，宽度 2/4 字节）
TABLE_LAYOUT = {
    0x00: ["u2", "s", "g", "u2", "u2"],                              # Module
    0x01: ["c:ResolutionScope", "s", "s"],                           # TypeRef
    0x02: ["u4", "s", "s", "c:TypeDefOrRef", "i:0x04", "i:0x06"],    # TypeDef
    0x03: ["i:0x04"],                                                # FieldPtr
    0x04: ["u2", "s", "b"],                                          # Field
    0x05: ["i:0x06"],                                                # MethodPtr
    0x06: ["u4", "u2", "u2", "s", "b", "i:0x08"],                    # MethodDef
    0x07: ["i:0x08"],                                                # ParamPtr
    0x08: ["u2", "u2", "s"],                                         # Param
    0x09: ["i:0x02", "c:TypeDefOrRef"],                              # InterfaceImpl
    0x0A: ["c:MemberRefParent", "s", "b"],                           # MemberRef
    0x0B: ["u2", "c:HasConstant", "b"],                              # Constant（Type|Pad 合并 u2）
    0x0C: ["c:HasCustomAttribute", "c:CustomAttributeType", "b"],    # CustomAttribute
    0x0D: ["c:HasFieldMarshal", "b"],                                # FieldMarshal
    0x0E: ["u2", "c:HasDeclSecurity", "b"],                          # DeclSecurity
    0x0F: ["u2", "u4", "i:0x02"],                                    # ClassLayout
    0x10: ["u4", "i:0x04"],                                          # FieldLayout
    0x11: ["b"],                                                     # StandAloneSig
    0x12: ["i:0x02", "i:0x14"],                                      # EventMap
    0x13: ["i:0x14"],                                                # EventPtr
    0x14: ["u2", "s", "c:TypeDefOrRef"],                             # Event
    0x15: ["i:0x02", "i:0x17"],                                      # PropertyMap
    0x16: ["i:0x17"],                                                # PropertyPtr
    0x17: ["u2", "s", "b"],                                          # Property
    0x18: ["u2", "i:0x06", "c:HasSemantics"],                        # MethodSemantics
    0x19: ["i:0x02", "c:MethodDefOrRef", "c:MethodDefOrRef"],        # MethodImpl
    0x1A: ["s"],                                                     # ModuleRef
    0x1B: ["b"],                                                     # TypeSpec
    0x1C: ["u2", "c:MemberForwarded", "s", "i:0x1A"],                # ImplMap
    0x1D: ["u4", "i:0x04"],                                          # FieldRVA
    0x1E: ["u4", "u4"],                                              # ENCLog
    0x1F: ["u4"],                                                    # ENCMap
    0x20: ["u4", "u2", "u2", "u2", "u2", "u4", "b", "s", "s"],       # Assembly
    0x21: ["u4"],                                                    # AssemblyProcessor
    0x22: ["u4", "u4", "u4"],                                        # AssemblyOS
    0x23: ["u2", "u2", "u2", "u2", "u4", "b", "s", "s", "b"],        # AssemblyRef
    0x24: ["u4", "i:0x23"],                                          # AssemblyRefProcessor
    0x25: ["u4", "u4", "u4"],                                        # AssemblyRefOS
    0x26: ["u4", "s", "b"],                                          # File
    0x27: ["u4", "u4", "s", "s", "c:Implementation"],                # ExportedType
    0x28: ["u4", "u4", "s", "c:Implementation"],                     # ManifestResource
    0x29: ["i:0x02", "i:0x02"],                                      # NestedClass
    0x2A: ["u2", "u2", "c:TypeOrMethodDef", "s"],                    # GenericParam
    0x2B: ["c:MethodDefOrRef", "b"],                                 # MethodSpec
    0x2C: ["i:0x2A", "c:TypeDefOrRef"],                              # GenericParamConstraint
    # 调试表（Mono.Cecil 可写）
    0x30: ["b", "g", "b", "g"],                                      # Document
    0x31: ["i:0x30", "b"],                                           # MethodDebugInformation
    0x32: ["i:0x06", "i:0x35", "i:0x33", "i:0x34", "u4", "u4"],      # LocalScope
    0x33: ["u2", "u2", "s"],                                         # LocalVariable
    0x34: ["s", "b"],                                                # LocalConstant
    0x35: ["i:0x35", "b"],                                           # ImportScope
    0x36: ["i:0x06", "i:0x06"],                                      # StateMachineMethod
    0x37: ["c:HasCustomDebugInformation", "g", "b"],                 # CustomDebugInformation
}

CODED_GROUPS = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)),
    "CustomAttributeType": (3, (0, 0, 0x06, 0x0A, 0x2B)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "HasCustomDebugInformation": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B, 0x30, 0x32, 0x33, 0x34, 0x35)),
}

TYPE_DEF, TYPE_REF, TYPE_SPEC = 0x02, 0x01, 0x1B
FIELD_T, METHOD_T = 0x04, 0x06

ACC_VIS_MASK = 0x7
MD_FAMANDASSEM, MD_ASSEMBLY, MD_FAMILY, MD_FAMORASSEM, MD_PUBLIC = 0x2, 0x3, 0x4, 0x5, 0x6
MD_STATIC, MD_FINAL, MD_VIRTUAL, MD_NEWSLOT = 0x10, 0x20, 0x40, 0x100
MD_ABSTRACT, MD_LITERAL, MD_INITONLY = 0x400, 0x40, 0x20
TD_INTERFACE, TD_ABSTRACT, TD_SEALED = 0x20, 0x80, 0x100


def read_compressed_uint(b, i):
    v = b[i]
    if v & 0x80 == 0:
        return v, i + 1
    if v & 0xC0 == 0x80:
        return ((v & 0x3F) << 8) | b[i + 1], i + 2
    return ((v & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4


class Assembly:
    """单个 dummy DLL 的 ECMA-335 元数据读取器"""

    def __init__(self, path):
        self.path = path
        self.tables = {}
        self.strings = b""
        self.blobs = b""
        self.data = None
        self._coded_sizes = {}
        self._read()
        self._build_caches()

    def _build_caches(self):
        """预计算所有 O(1) 查找缓存（大程序集下避免 O(n²) 扫描）"""
        typedefs = self.tables.get(TYPE_DEF, [])
        n = len(typedefs)
        # 字段/方法区间 = [本行 FieldList/MethodList, 下一行 FieldList/MethodList)
        self._field_end = [typedefs[i + 1][4] if i + 1 < n else len(self.tables.get(FIELD_T, [])) + 1
                           for i in range(n)]
        self._method_end = [typedefs[i + 1][5] if i + 1 < n else len(self.tables.get(METHOD_T, [])) + 1
                            for i in range(n)]
        # 嵌套类型父级
        self._nested_parent = {nc: ec for nc, ec in self.tables.get(0x29, [])}
        # 泛型参数名：owner_table(0=TypeDef,1=MethodDef) -> owner_idx -> [名字按Number排序]
        self._gen_param_map = {}
        for num, _flags, owner, name_idx in self.tables.get(0x1A, []):
            key = (owner & 1, owner >> 1)
            self._gen_param_map.setdefault(key, {})[num] = self.str(name_idx)
        # 常量表：field_idx -> (etype, blob)；行 = [u2(Type|Pad), c:HasConstant, b]，Type 在低字节
        self._constant_by_field = {}
        for typepad, parent, val_idx in self.tables.get(0x0B, []):
            if (parent & 0x3) == 0:
                self._constant_by_field[parent >> 2] = (typepad & 0xFF, self.blob(val_idx))
        # 接口：class_idx -> [iface_coded]
        self._ifaces_by_class = {}
        for cls_idx, iface_coded in self.tables.get(0x09, []):
            self._ifaces_by_class.setdefault(cls_idx, []).append(iface_coded)
        # TypeDef 路径 + 泛型参数
        self._type_paths = {}
        self._gparams = {}
        for i in range(1, n + 1):
            path, gp = self._type_path_of(i)
            self._type_paths[i] = path
            self._gparams[i] = gp
        # TypeRef / TypeSpec 名称 memo
        self._typeref_cache = {}
        self._typedeforref_cache = {}

    # ---------- PE / CLI ----------
    def _read(self):
        d = Path(self.path).read_bytes()
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e_lfanew:e_lfanew + 4] == b"PE\0\0", "非 PE 文件"
        num_sections = struct.unpack_from("<H", d, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", d, e_lfanew + 20)[0]
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        dd_off = opt + (112 if magic == 0x20B else 96)
        cli_rva = struct.unpack_from("<I", d, dd_off + 14 * 8)[0]
        sec_off = opt + opt_size
        rva2off = []
        for i in range(num_sections):
            base = sec_off + i * 40
            vsize, vaddr, _rsize, rawptr = struct.unpack_from("<IIII", d, base + 8)
            rva2off.append((vaddr, vsize, rawptr))

        def rva_to_off(rva):
            for vaddr, vsize, rawptr in rva2off:
                if vaddr <= rva < vaddr + vsize:
                    return rawptr + (rva - vaddr)
            raise ValueError(f"RVA 0x{rva:x} 不在任何节内")

        self.data = d
        cli = rva_to_off(cli_rva)
        meta_rva = struct.unpack_from("<I", d, cli + 8)[0]
        self._parse_metadata_root(d, rva_to_off(meta_rva))

    # ---------- 元数据根 / 流 ----------
    def _parse_metadata_root(self, d, off):
        assert d[off:off + 4] == b"BSJB", "无 BSJB 元数据"
        ver_len = struct.unpack_from("<I", d, off + 12)[0]
        # 布局：BSJB(4) Major(2) Minor(2) Reserved(4) VersionLength(4) Version(n) Flags(2) Streams(2) ...
        nstreams = struct.unpack_from("<H", d, off + 16 + ver_len + 2)[0]
        pos = off + 18 + ver_len + 2
        streams = {}
        for _ in range(nstreams):
            so, size = struct.unpack_from("<II", d, pos)
            pos += 8
            end = d.index(b"\0", pos)
            streams[d[pos:end].decode("utf-8")] = (off + so, size)
            pos = (end + 4) & ~3  # 流名按 4 字节对齐
        self._parse_tables_stream(d, *streams["#~"])
        self.strings = d[streams["#Strings"][0]:streams["#Strings"][0] + streams["#Strings"][1]]
        self.blobs = d[streams["#Blob"][0]:streams["#Blob"][0] + streams["#Blob"][1]]

    # ---------- #~ 表流 ----------
    def _parse_tables_stream(self, d, off, _size):
        self.heap_wide = d[off + 6] & 0x7
        valid = struct.unpack_from("<Q", d, off + 8)[0]
        pos = off + 24
        row_counts = {}
        for tid in range(64):
            if valid >> tid & 1:
                row_counts[tid] = struct.unpack_from("<I", d, pos)[0]
                pos += 4
        for name, (tag_bits, tables) in CODED_GROUPS.items():
            mx = max((row_counts.get(t, 0) for t in tables), default=0)
            # 表列 coded 索引：Mono.Cecil 仅 2/4 字节（max < 2^(16-tagbits) 时 2 字节）
            self._coded_sizes[name] = 4 if mx >= (1 << (16 - tag_bits)) else 2
        # 简单索引宽度：行数 < 65536 为 2 字节，否则 4 字节
        self._simple_sizes = {tid: (4 if rc >= 0x10000 else 2) for tid, rc in row_counts.items()}
        for tid in range(64):
            if not (valid >> tid & 1):
                continue
            layout = TABLE_LAYOUT.get(tid)
            if layout is None:
                raise ValueError(f"未知表 0x{tid:02X}（行数 {row_counts[tid]}）")
            parsed = []
            for _ in range(row_counts[tid]):
                row = []
                for col in layout:
                    row.append(self._read_col(d, pos, col))
                    pos = self._advance(pos, col)
                parsed.append(tuple(row))
            self.tables[tid] = parsed
        self.tables.setdefault(0x29, [])

    def _read_col(self, d, pos, col):
        if col == "u1":
            return d[pos]
        if col == "u2":
            return struct.unpack_from("<H", d, pos)[0]
        if col == "u4":
            return struct.unpack_from("<I", d, pos)[0]
        if col == "s":
            return struct.unpack_from("<I", d, pos)[0] if self.heap_wide & 1 else struct.unpack_from("<H", d, pos)[0]
        if col == "b":
            return struct.unpack_from("<I", d, pos)[0] if self.heap_wide & 4 else struct.unpack_from("<H", d, pos)[0]
        if col == "g":
            return struct.unpack_from("<I", d, pos)[0] if self.heap_wide & 2 else struct.unpack_from("<H", d, pos)[0]
        if col.startswith("c:"):
            size = self._coded_sizes[col[2:]]
            fmt = "<I" if size == 4 else ("<H" if size == 2 else "<B")
            return struct.unpack_from(fmt, d, pos)[0]
        if col.startswith("i:"):
            size = self._simple_sizes.get(int(col[2:], 16), 2)
            fmt = "<I" if size == 4 else ("<H" if size == 2 else "<B")
            return struct.unpack_from(fmt, d, pos)[0]
        raise ValueError(f"未知列 {col}")

    def _advance(self, pos, col):
        if col == "u1":
            return pos + 1
        if col == "u2":
            return pos + 2
        if col == "u4":
            return pos + 4
        if col in ("s", "b", "g"):
            return pos + (4 if self.heap_wide & {"s": 1, "b": 4, "g": 2}[col] else 2)
        if col.startswith("c:"):
            return pos + self._coded_sizes[col[2:]]
        if col.startswith("i:"):
            return pos + self._simple_sizes.get(int(col[2:], 16), 2)
        raise ValueError(f"未知列 {col}")

    # ---------- heap ----------
    def str(self, idx):
        if idx == 0:
            return ""
        end = self.strings.index(b"\0", idx)
        return self.strings[idx:end].decode("utf-8", "replace")

    def blob(self, idx):
        if idx == 0:
            return b""
        n, pos = read_compressed_uint(self.blobs, idx)
        return self.blobs[pos:pos + n]

    # ---------- 名称解析 ----------
    def _gen_param_names(self, owner_table, owner_idx):
        d = self._gen_param_map.get((0 if owner_table == TYPE_DEF else 1, owner_idx), {})
        return [d[k] for k in sorted(d)]

    def _nested_enclosing(self, typedef_idx):
        return self._nested_parent.get(typedef_idx)

    def type_path(self, idx):
        """预计算路径 + 泛型参数名"""
        return self._type_paths[idx], self._gparams[idx]

    def _type_path_of(self, idx):
        names, cur, ns = [], idx, ""
        while True:
            _flags, name_idx, ns_idx, _e, _f, _m = self.tables[TYPE_DEF][cur - 1]
            gparams = self._gen_param_names(TYPE_DEF, cur)
            names.append(self.str(name_idx).split("`")[0])
            p = self._nested_enclosing(cur)
            if p is None:
                ns = self.str(ns_idx)
                break
            cur = p
        path = ".".join(reversed(names))
        return (ns + "." + path) if ns else path, gparams

    def typeref_path(self, idx):
        if idx in self._typeref_cache:
            return self._typeref_cache[idx]
        scope, name_idx, ns_idx = self.tables[TYPE_REF][idx - 1]
        name = self.str(name_idx).split("`")[0]
        if (scope & 0x3) == 3:  # 嵌套 TypeRef
            path = self.typeref_path(scope >> 2) + "." + name
        else:
            ns = self.str(ns_idx)
            path = (ns + "." if ns else "") + name
        self._typeref_cache[idx] = path
        return path

    def _read_coded_value(self, pos, group):
        size = self._coded_sizes[group]
        fmt = "<I" if size == 4 else ("<H" if size == 2 else "<B")
        return struct.unpack_from(fmt, self.data, pos)[0]

    def typedeforref_name(self, coded):
        if coded in self._typedeforref_cache:
            return self._typedeforref_cache[coded]
        tag, rid = coded & 0x3, coded >> 2
        if tag == 0:
            name = self._type_paths[rid]
        elif tag == 1:
            name = self.typeref_path(rid)
        elif tag == 2:  # TypeSpec：解析 GENERICINST 等
            blob = self.blob(self.tables[TYPE_SPEC][rid - 1][0])
            name = self.parse_type(blob, 0, {}, set())[0]
        else:
            name = "?"
        self._typedeforref_cache[coded] = name
        return name

    def is_system_type(self, coded, name):
        if (coded & 0x3) != 1:
            return False
        scope, name_idx, ns_idx = self.tables[TYPE_REF][(coded >> 2) - 1]
        return self.str(name_idx) == name and self.str(ns_idx) == "System"

    # ---------- 签名解析 ----------
    def parse_type(self, b, i, type_gparams, method_gparams):
        while True:
            t = b[i]
            if t in (0x1F, 0x20):  # CMOD_REQD / CMOD_OPT：跟随压缩 TypeDefOrRef（TypeToken）
                i += 1
                _coded, i = read_compressed_uint(b, i)
                continue
            if t in (0x40, 0x45):  # MODIFIER / PINNED：仅修饰符字节
                i += 1
                continue
            break
        t = b[i]
        if t in ELEMENT_TYPE:
            return ELEMENT_TYPE[t], i + 1
        if t in (0x11, 0x12):  # VALUETYPE / CLASS：TypeDefOrRef 为压缩整数
            coded, i = read_compressed_uint(b, i + 1)
            return self.typedeforref_name(coded), i
        if t == 0x15:  # GENERICINST
            kind = b[i + 1]
            assert kind in (0x11, 0x12), f"GENERICINST kind 0x{kind:x}"
            coded, i = read_compressed_uint(b, i + 2)
            base = self.typedeforref_name(coded)
            n, i = read_compressed_uint(b, i)
            args = []
            for _ in range(n):
                a, i = self.parse_type(b, i, type_gparams, method_gparams)
                args.append(a)
            return base + "<" + ",".join(args) + ">", i
        if t == 0x1D:  # SZARRAY
            elem, i = self.parse_type(b, i + 1, type_gparams, method_gparams)
            return elem + "[]", i
        if t == 0x14:  # ARRAY（多维）
            elem, i = self.parse_type(b, i + 1, type_gparams, method_gparams)
            rank, i = read_compressed_uint(b, i)
            n, i = read_compressed_uint(b, i)
            for _ in range(n):
                _, i = read_compressed_uint(b, i)
            n2, i = read_compressed_uint(b, i)
            for _ in range(n2):
                _, i = read_compressed_uint(b, i)
            return elem + "[" + "," * max(0, rank - 1) + "]", i
        if t == 0x0F:  # PTR
            inner, i = self.parse_type(b, i + 1, type_gparams, method_gparams)
            return inner + "*", i
        if t == 0x10:  # BYREF
            inner, i = self.parse_type(b, i + 1, type_gparams, method_gparams)
            return inner + "&", i
        if t in (0x13, 0x1E):  # VAR / MVAR：位置在标记字节之后
            idx, i = read_compressed_uint(b, i + 1)
            names = type_gparams if t == 0x13 else method_gparams
            return (names[idx] if idx < len(names) else f"T{idx}"), i
        if t == 0x1B:  # FNPTR：跟随函数指针签名，直接跳过
            cc, i = b[i + 1], i + 2
            if cc & 0x10:
                _, i = read_compressed_uint(b, i)
            n, i = read_compressed_uint(b, i)
            for _ in range(n + 1):
                _, i = self.parse_type(b, i, type_gparams, method_gparams)
            return "<fnptr>", i
        if t in (0x21, 0x41):  # INTERNAL / SENTINEL（vararg 哨兵）
            return "System.IntPtr", i + 1
        raise ValueError(f"未知元素类型 0x{t:x}")

    def parse_field_sig(self, blob, type_gparams):
        assert blob[0] == 0x06, "非 FieldSig"
        return self.parse_type(blob, 1, type_gparams, {})[0]

    def parse_method_sig(self, blob, type_gparams, method_gparams):
        cc, i = blob[0], 1
        if cc & 0x10:
            _, i = read_compressed_uint(blob, i)
        pcount, i = read_compressed_uint(blob, i)
        ret, i = self.parse_type(blob, i, type_gparams, method_gparams)
        params = []
        for _ in range(pcount):
            t, i = self.parse_type(blob, i, type_gparams, method_gparams)
            params.append(t)
        return ret, params

    # ---------- 常量 ----------
    def constant_of_field(self, field_idx):
        return self._constant_by_field.get(field_idx, (None, None))

    @staticmethod
    def format_constant(ctype, blob):
        fmt = {
            0x04: ("<b", 1), 0x05: ("<B", 1), 0x06: ("<h", 2), 0x07: ("<H", 2),
            0x08: ("<i", 4), 0x09: ("<I", 4), 0x0A: ("<q", 8), 0x0B: ("<Q", 8),
            0x0C: ("<f", 4), 0x0D: ("<d", 8),
        }
        if ctype in fmt:
            f, n = fmt[ctype]
            return str(struct.unpack(f, blob[:n])[0])
        if ctype == 0x0E:
            return '"' + blob.decode("utf-8", "replace") + '"'
        if ctype == 0x1C:
            return "1" if blob[0] else "0"
        return "?"


def render_field_member(vis):
    return {
        0x1: "private",
        MD_FAMANDASSEM: "protected internal",
        MD_ASSEMBLY: "internal",
        MD_FAMILY: "protected",
        MD_FAMORASSEM: "protected internal",
        MD_PUBLIC: "public",
    }.get(vis, "private")


def dump_assembly(asm):
    lines = []
    typedefs = asm.tables.get(TYPE_DEF, [])
    # 参数名（sequence -> name），整个程序集只构建一次
    param_names = {}
    for _pflags, seq, pname_idx in asm.tables.get(0x08, []):
        param_names[seq] = asm.str(pname_idx)
    for i, (flags, name_idx, _ns, extends, field_list, method_list) in enumerate(typedefs):
        idx = i + 1
        name = asm.str(name_idx)
        fend = asm._field_end[i]
        mend = asm._method_end[i]

        is_enum = asm.is_system_type(extends, "Enum")
        is_struct = not is_enum and asm.is_system_type(extends, "ValueType")
        is_interface = bool(flags & TD_INTERFACE)
        path, gparams = asm.type_path(idx)
        decl_name = path + ("<" + ",".join(gparams) + ">" if gparams else "")

        if is_enum:
            mods, kind = "public", "enum"
        elif is_interface:
            mods, kind = "public", "interface"
        elif is_struct:
            mods, kind = "public", "struct"
        elif (flags & TD_ABSTRACT) and (flags & TD_SEALED):
            mods, kind = "public static", "class"
        elif flags & TD_ABSTRACT:
            mods, kind = "public abstract", "class"
        elif flags & TD_SEALED:
            mods, kind = "public sealed", "class"
        else:
            mods, kind = ("public" if (flags & ACC_VIS_MASK) in (1, 2) else "internal"), "class"

        # 基类 / 接口（枚举、结构体：基类槽显示接口；类：基类 + 接口）
        bases = []
        if extends != 0 and not (is_enum or is_struct):
            try:
                bases.append(asm.typedeforref_name(extends))
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {path}: 基类解析失败 {e}", file=sys.stderr)
        for iface_coded in asm._ifaces_by_class.get(idx, []):
            if iface_coded != 0:
                try:
                    bases.append(asm.typedeforref_name(iface_coded))
                except Exception as e:  # noqa: BLE001
                    print(f"[warn] {path}: 接口解析失败 {e}", file=sys.stderr)

        header = f"{mods} {kind} {decl_name}"
        header += " : " + ", ".join(bases) if bases else " : "

        lines.append(header)
        lines.append("{")
        lines.append("\t// Fields")

        # ---- 枚举：value__ + 常量值 ----
        if is_enum:
            underlying = "System.Int32"
            for f_idx in range(field_list, fend):
                fflags, fname_idx, fsig_idx = asm.tables[FIELD_T][f_idx - 1]
                fname = asm.str(fname_idx)
                if fname == "value__":
                    underlying = asm.parse_field_sig(asm.blob(fsig_idx), gparams)
                    lines.append(f"\t{render_field_member(fflags & ACC_VIS_MASK)} {underlying} {fname}; // 0x0")
                elif fflags & MD_LITERAL:
                    ctype, cblob = asm.constant_of_field(f_idx)
                    value = asm.format_constant(ctype, cblob) if ctype else "?"
                    short = decl_name.split("<")[0].split(".")[-1]
                    lines.append(f"\tpublic const {short} {fname} = {value}; // 0x0")
            lines.append("")
            lines.append("\t// Methods")
            lines.append("")
            lines.append("}")
            continue

        # ---- 字段 ----
        for f_idx in range(field_list, fend):
            fflags, fname_idx, fsig_idx = asm.tables[FIELD_T][f_idx - 1]
            fname = asm.str(fname_idx)
            try:
                ftype = asm.parse_field_sig(asm.blob(fsig_idx), gparams)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {path}.{fname}: 字段签名解析失败 {e}", file=sys.stderr)
                continue
            mods = ["const"] if fflags & MD_LITERAL else []
            if not mods:
                if fflags & MD_STATIC:
                    mods.append("static")
                if fflags & MD_INITONLY:
                    mods.append("readonly")
            prefix = " ".join([render_field_member(fflags & ACC_VIS_MASK)] + mods)
            lines.append(f"\t{prefix} {ftype} {fname}; // 0x0")
        lines.append("")
        lines.append("\t// Methods")

        # ---- 方法 ----
        for m_idx in range(method_list, mend):
            _rva, _implf, mflags, mname_idx, msig_idx, _plist = asm.tables[METHOD_T][m_idx - 1]
            mname = asm.str(mname_idx)
            m_gparams = asm._gen_param_names(METHOD_T, m_idx)
            try:
                ret, params = asm.parse_method_sig(asm.blob(msig_idx), gparams, m_gparams)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {path}.{mname}: 方法签名解析失败 {e}", file=sys.stderr)
                continue
            mods = []
            if mflags & MD_ABSTRACT:
                mods.append("abstract")
            elif mflags & MD_VIRTUAL:
                mods.append("virtual" if mflags & MD_NEWSLOT else "override")
            if mflags & MD_STATIC:
                mods.append("static")
            prefix = " ".join([render_field_member(mflags & ACC_VIS_MASK)] + mods)
            rendered = []
            for k, ptype in enumerate(params, start=1):
                rendered.append(f"{ptype} {param_names.get(k) or f'arg{k}'}")
            lines.append(f"\t{prefix} {ret} {mname}({', '.join(rendered)}); // 0x0")
        lines.append("")
        lines.append("}")
    return lines


def main():
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="从 Cpp2IL dummy DLL 生成签名文件")
    ap.add_argument("--in", dest="indir", default=str(repo / "tmp" / "decompile" / "cpp2il_out"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", default=None, help="只处理指定程序集（逗号分隔）")
    args = ap.parse_args()

    indir = Path(args.indir)
    dlls = sorted(indir.glob("*.dll"))
    if args.only:
        names = {n.strip() for n in args.only.split(",")}
        dlls = [d for d in dlls if d.name in names]
    if not dlls:
        sys.exit(f"未找到 DLL: {indir}")

    out_lines, errors = [], []
    for dll in dlls:
        try:
            asm = Assembly(str(dll))
            out_lines.append(f"// {dll.name}")
            out_lines.extend(dump_assembly(asm))
        except Exception as e:  # noqa: BLE001
            errors.append(f"  {dll.name}: {e}")

    text = "\n".join(out_lines) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已生成 {Path(args.out)}（{len(out_lines)} 行，{len(text)/1024/1024:.1f} MB）")
    else:
        sys.stdout.write(text)
    if errors:
        print("跳过无法解析的程序集：", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)


if __name__ == "__main__":
    main()
