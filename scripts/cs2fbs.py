# -*- coding: utf-8 -*-
"""从 C# 反编译源生成 flatbuffers Python schema（解码官方 FBO excel 用）
原理：C# 运行时模型字段序 = 客户端 .fbs 声明序 = FBO vtable slot 序（已对 character_table 验证）。
用法: python scripts/cs2fbs.py <表名> [--out 输出.py]
例如: python scripts/cs2fbs.py range_table
"""
import re
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "scripts/vendor/fbs/CN")


def resolve_cs_path():
    """探测 reference/ 下最新的 com.hypergryph.arknights_*.cs。

    历史缺陷：此处曾硬编码 _2.7.61.cs，客户端升版改名后脚本直接读不到源。
    与 scripts/lib/cs-source.ts 保持同一探测策略（按文件名排序取最新），
    可用环境变量 GENERATE_CS 显式覆盖。
    """
    env = os.environ.get("GENERATE_CS")
    if env and os.path.exists(env):
        return env
    ref_dir = os.path.join(ROOT, "reference")
    if os.path.isdir(ref_dir):
        cands = sorted(
            f for f in os.listdir(ref_dir)
            if re.match(r"^com\.hypergryph\.arknights_.+\.cs$", f)
        )
        if cands:
            return os.path.join(ref_dir, cands[-1])
    raise SystemExit(
        "未找到 CS 反编译源：reference/ 下不存在 com.hypergryph.arknights_*.cs"
        "（请先运行 pnpm run decompile，或设置 GENERATE_CS）"
    )


CS_PATH = resolve_cs_path()

# 表名 → C# 根类（SimpleKVTable 根 = SimpleKVTable<T, X> 基类）
TABLE_ROOTS = {
    "range_table": ("RangeDB", "simplekv"),
    "player_avatar_table": ("PlayerAvatarData", "plain"),
    "roguelike_table": ("RoguelikeActivityTable", "plain"),
    "uniequip_data": ("UniEquipData", "plain"),
}

SCALAR = {
    "System.String": "string",
    "System.Int32": "int",
    "System.Int64": "long",
    "System.Single": "float",
    "System.Double": "double",
    "System.Boolean": "bool",
    "System.Byte": "ubyte",
    "System.Int16": "short",
}


def norm_type(t):
    """C# 类型短名（Torappu.CharacterData.PowerData → CharacterData.PowerData）"""
    return t.replace("Torappu.", "").strip()


class CsParser:
    def __init__(self):
        self.classes = {}  # 短名 -> {"fields": [(type, name)], "base": short_base}
        self.enums = {}  # 短名 -> {value: name}
        self._parse()

    def _parse(self):
        cs = open(CS_PATH, encoding="utf-8").read()
        # 枚举
        for m in re.finditer(r'public enum (Torappu\.[A-Za-z0-9_.]+)\s*(?::[^\{]*)?\{([^}]*)\}', cs):
            name = norm_type(m.group(1))
            vals = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)', m.group(2))
            if vals:
                self.enums[name] = {int(v): k for k, v in vals}
        # 类 / 结构
        cls_re = re.compile(
            r'(?:public|internal)\s+(?:abstract\s+|sealed\s+)?(?:class|struct)\s+'
            r'(Torappu\.[A-Za-z0-9_.]+)\s*(?::\s*([^{]+))?\{'
        )
        for m in cls_re.finditer(cs):
            name = norm_type(m.group(1))
            base = m.group(2).strip() if m.group(2) else ""
            body, end = self._extract_body(cs, m.end())
            fields = re.findall(r'public\s+([^()]+?)\s+(\w+);', body)
            fields = [
                (t.strip(), n) for t, n in fields
                if " " not in n.strip() and not any(
                    k in t for k in ("const ", "static ", "readonly ", " delegate ", " event ")
                )
            ]
            self.classes[name] = {
                "fields": fields,
                "base": norm_type(base) if base else "",
            }

    @staticmethod
    def _extract_body(cs, start):
        depth = 1
        i = start
        while depth > 0 and i < len(cs):
            if cs[i] == "{":
                depth += 1
            elif cs[i] == "}":
                depth -= 1
            i += 1
        return cs[start:i - 1], i


class FbsGenerator:
    def __init__(self, parser):
        self.p = parser
        self.tables = {}  # clz 名 -> [FBS 字段描述]
        self.enums_needed = {}  # enum 短名 -> {value: name}
        self.dicts = {}  # "K__V" -> [K, V]
        self.order = []  # 表生成顺序（依赖优先）

    def gen(self, root_short, mode):
        """生成根表。mode: plain=根类直接是表; simplekv=SimpleKVTable<T,X> 包装"""
        if mode == "simplekv":
            # SimpleKVTable<T, Singleton> → clz_Torappu_SimpleKVTable_clz_Torappu_T 单字段包装
            cls = self.p.classes[root_short]
            base = cls["base"]
            m = re.match(r'.*SimpleKVTable<([^,>]+)', base)
            if not m:
                raise RuntimeError(f"{root_short} 的基类不是 SimpleKVTable: {base}")
            tval = norm_type(m.group(1))
            fbs_t = self._fbs_type(tval, f"root")
            wrapper = f"clz_Torappu_SimpleKVTable_{self._clz(tval)}"
            field_name = self._plural(tval.split(".")[-1])
            self._ensure_table(wrapper, [(field_name, f"dict::{fbs_t[2][0]}::{fbs_t[2][1]}" if fbs_t[0] == "dict" else fbs_t)])
            return wrapper, wrapper
        root_fbs = self._fbs_type(root_short, "root")
        root_clz = root_fbs[1]
        return root_clz, root_clz

    def _plural(self, name):
        return name + "s"

    def _clz(self, short):
        return "clz_Torappu_" + short.replace(".", "_")

    def _fbs_type(self, ctype, path):
        """C# 类型 → (kind, fbs_type, payload)"""
        t = ctype.strip()
        if t.startswith("System.Collections.Generic.List<") and t.endswith(">"):
            elem = t[len("System.Collections.Generic.List<"):-1]
            k, ft, pay = self._fbs_type(elem, path)
            return ("vector", f"[{ft}]", (k, ft, pay))
        if t.endswith("[]"):
            elem = t[:-2]
            k, ft, pay = self._fbs_type(elem, path)
            return ("vector", f"[{ft}]", (k, ft, pay))
        if t.startswith("System.Collections.Generic.Dictionary<") and t.endswith(">"):
            inner = t[len("System.Collections.Generic.Dictionary<"):-1]
            # 取最外层逗号切分 K, V
            kk, vv = self._split_generic(inner)
            k, fk, _ = self._fbs_type(kk, path)
            v, fv, _ = self._fbs_type(vv, path)
            dkey = f"{fk}__{fv}"
            self._ensure_dict(dkey, (k, fk, v, fv))
            return ("dict", f"dict__{dkey}", (k, fk, v, fv))
        if t.startswith("Torappu.Undefinable<") and t.endswith(">"):
            inner = t[len("Torappu.Undefinable<"):-1]
            k, ft, pay = self._fbs_type(inner, path)
            uname = f"clz_Torappu_Undefinable_{self._clz(inner)}" if k == "table" else f"clz_Torappu_Undefinable_{ft}"
            self._ensure_table(uname, [("mDefined", "bool"), ("mValue", ft)])
            return ("table", uname, None)
        # 标量 / 枚举 / 类：用短名匹配
        short = norm_type(t)
        if short in SCALAR:
            return ("scalar", SCALAR[short], None)
        if short in self.p.enums:
            self.enums_needed[short] = self.p.enums[short]
            return ("enum", f"enum__Torappu_{short.replace('.', '_')}", None)
        if short in self.p.classes:
            ct = self._clz(short)
            self._ensure_table(ct, None)  # 占位，随后填充
            return ("table", ct, short)
        if short == "System.Object":
            return ("scalar", "ubyte", None)
        raise RuntimeError(f"未知类型: {ctype} (路径 {path})")

    @staticmethod
    def _split_generic(inner):
        depth = 0
        for i, c in enumerate(inner):
            if c == "<":
                depth += 1
            elif c == ">":
                depth -= 1
            elif c == "," and depth == 0:
                return inner[:i].strip(), inner[i + 1:].strip()
        return inner, "System.Object"

    def _ensure_table(self, clz_name, fields):
        if clz_name not in self.tables:
            self.tables[clz_name] = None  # 占位
            self.order.append(clz_name)

    def _ensure_dict(self, dkey, parts):
        if dkey not in self.dicts:
            self.dicts[dkey] = parts

    def fill_fields(self):
        """工作队列解析所有表的字段（处理相互/嵌套引用）"""
        i = 0
        while i < len(self.order):
            clz = self.order[i]
            i += 1
            if self.tables[clz] is not None:
                continue
            short = clz[len("clz_Torappu_"):].replace("_", ".")
            cls = self.p.classes.get(short)
            if cls is None:
                self.tables[clz] = []
                continue
            fields = []
            for t, n in cls["fields"]:
                try:
                    k, ft, pay = self._fbs_type(t, f"{short}.{n}")
                    fields.append((n, ft))
                except RuntimeError as e:
                    print(f"  [warn] 跳过 {short}.{n}: {e}")
            self.tables[clz] = fields

    def emit(self):
        out = ["# automatically generated by the FlatBuffers compiler, do not modify",
               "", "# namespace: ", "", "import flatbuffers",
               "from flatbuffers.compat import import_numpy",
               "np = import_numpy()", ""]
        # 枚举
        for ename, vmap in sorted(self.enums_needed.items()):
            out.append(f"class enum__Torappu_{ename.replace('.', '_')}(object):")
            for v, name in sorted(vmap.items()):
                out.append(f"    {name} = {v}")
            out.append("")
        # dict 表
        for dkey, (k, fk, v, fv) in sorted(self.dicts.items()):
            out += self._emit_dict(dkey, fk, fv)
        # 表
        for clz in self.order:
            if self.tables[clz] is not None:
                out += self._emit_table(clz, self.tables[clz])
        return "\n".join(out) + "\n"

    def _emit_dict(self, dkey, fk, fv):
        d = f"dict__{dkey}"
        return self._emit_table(d, [("Key", fk), ("Value", fv)])

    def _emit_table(self, clz, fields):
        out = [f"class {clz}(object):", "    __slots__ = ['_tab']", "",
               "    @classmethod", "    def GetRootAs(cls, buf, offset=0):",
               "        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)",
               f"        x = {clz}()", "        x.Init(buf, n + offset)", "        return x", "",
               "    @classmethod",
               f"    def GetRootAs{clz}(cls, buf, offset=0):",
               '        """This method is deprecated. Please switch to GetRootAs."""',
               "        return cls.GetRootAs(buf, offset)",
               f"    # {clz}", "    def Init(self, buf, pos):",
               "        self._tab = flatbuffers.table.Table(buf, pos)", ""]
        for i, (fname, ftype) in enumerate(fields):
            slot = 4 + 2 * i
            out += self._emit_accessor(fname, ftype, slot)
        return out

    def _emit_accessor(self, fname, ftype, slot):
        is_vec = ftype.startswith("[")
        is_dict = ftype.startswith("dict__")
        elem = ftype[1:-1] if is_vec else ftype
        out = [f"    # {clz_name(fname) if False else fname}"]
        if is_vec or is_dict:
            out += [
                f"    def {fname}(self, j):",
                f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                "        if o != 0:",
                "            x = self._tab.Vector(o)",
                "            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4",
                "            x = self._tab.Indirect(x)",
                f"            obj = {elem}()",
                "            obj.Init(self._tab.Bytes, x)",
                "            return obj",
                f"    def {fname}Length(self):",
                f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                "        if o != 0:",
                "            return self._tab.VectorLen(o)",
                "        return 0",
                f"    def {fname}IsNone(self):",
                f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                "        return o == 0",
            ]
        elif elem == "string":
            out += [
                f"    def {fname}(self):",
                f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                "        if o != 0:",
                "            return self._tab.String(o + self._tab.Pos)",
                "        return None",
            ]
        elif ftype in ("bool", "int", "long", "float", "double", "ubyte", "short"):
            flags, default = {
                "bool": ("BoolFlags", "False"), "int": ("Int32Flags", "0"),
                "long": ("Int64Flags", "0"), "float": ("Float32Flags", "0.0"),
                "double": ("Float64Flags", "0.0"), "ubyte": ("Uint8Flags", "0"),
                "short": ("Int16Flags", "0"),
            }[ftype]
            getter = f"bool(self._tab.Get(flatbuffers.number_types.{flags}, o + self._tab.Pos))" if flags == "BoolFlags" else f"self._tab.Get(flatbuffers.number_types.{flags}, o + self._tab.Pos)"
            out += [
                f"    def {fname}(self):",
                f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                "        if o != 0:",
                f"            return {getter}",
                f"        return {default}",
            ]
        else:
            # 枚举 / 表
            if ftype.startswith("enum__"):
                out += [
                    f"    def {fname}(self):",
                    f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                    "        if o != 0:",
                    f"            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)",
                    "        return 0",
                ]
            else:
                out += [
                    f"    def {fname}(self):",
                    f"        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset({slot}))",
                    "        if o != 0:",
                    f"            x = self._tab.Indirect(o + self._tab.Pos)",
                    f"            obj = {ftype}()",
                    "            obj.Init(self._tab.Bytes, x)",
                    "            return obj",
                    "        return None",
                ]
        return out


def clz_name(x):
    return x


def generate(table_name, out_path=None):
    parser = CsParser()
    root_short, mode = TABLE_ROOTS.get(table_name, (None, None))
    if not root_short:
        raise RuntimeError(f"未知表 {table_name}，TABLE_ROOTS 未配置")
    gen = FbsGenerator(parser)
    root_clz, _ = gen.gen(root_short, mode)
    gen.fill_fields()
    src = gen.emit()
    src = src + f"\nROOT_TYPE = {root_clz}\n"
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(src)
        print(f"已生成 {out_path}: {len(src)//1024}KB, {len(gen.tables)} 表, {len(gen.dicts)} dict, {len(gen.enums_needed)} 枚举")
    return src


if __name__ == "__main__":
    table = sys.argv[1] if len(sys.argv) > 1 else "range_table"
    out = os.path.join(OUT_DIR, f"{table}.py")
    generate(table, out)
