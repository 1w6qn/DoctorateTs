#!/usr/bin/env python3
"""从反编译 C# 提取客户端 API 路由（/ 开头字符串字面量 + 插值串）"""
import re
import os

ROOT = "reference/arknights-2.7.61-csharp"
LIBS = ["Assembly-CSharp", "Assembly-CSharp-firstpass"]
# 普通字符串 + 插值字符串字面量
STR_RE = re.compile(r'("[^"\n]*")|(\$"[^"\n]*")')
# 路由：/ 开头，允许大写/数字/下划线/连字符/点（排除含空白、{}、; 的）
ROUTE_RE = re.compile(r"^/[A-Za-z0-9_.][A-Za-z0-9_./-]*$")

routes = set()
for lib in LIBS:
    base = os.path.join(ROOT, lib)
    for dirpath, _dirs, files in os.walk(base):
        for f in files:
            if not f.endswith(".cs"):
                continue
            p = os.path.join(dirpath, f)
            try:
                text = open(p, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for m in STR_RE.finditer(text):
                s = m.group(1) or m.group(2)
                s = s[1:-1]  # 去引号
                # 插值串去 {expr}（含路径拼段时）
                s = re.sub(r"\{[^}]*\}", "X", s)
                if s.startswith("/") and ROUTE_RE.match(s) and "/" in s[1:]:
                    routes.add(s)

routes = sorted(routes)
out = "reference/client-routes.txt"
with open(out, "w", encoding="utf-8") as fp:
    fp.write("\n".join(routes) + "\n")
print(f"提取 {len(routes)} 条路由 -> {out}")

# 按首段统计
from collections import Counter
first = Counter(r.split("/")[1] for r in routes)
print("--- 按首段计数 ---")
for seg, n in first.most_common(30):
    print(f"  /{seg}/ ... x{n}")
