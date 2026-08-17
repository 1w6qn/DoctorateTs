#!/usr/bin/env python3
"""统计 activity.ts stub 批量区间的路由数与清单"""
import re

src = open(r"D:\develop\DoctorateTs\app\game\router\activity.ts", encoding="utf-8").read()
lines = src.splitlines()

# stub 区间: 行 1689-2464（1-based）
seg = "\n".join(lines[1688:2464])

# 直接注册
direct = sorted(set(re.findall(r'router\.post\(\s*["\']([^"\']+)["\']', seg)))
# 循环注册
loops = {}
for m in re.finditer(
    r'for \(const (\w+) of \[([^\]]+)\]\) \{\s*router\.post\(`/([^`]*)\$\{\1\}([^`]*)`',
    seg,
):
    var, arr, pre, post = m.group(1), m.group(2), m.group(3), m.group(4)
    items = [x.strip().strip("'\"") for x in arr.split(",") if x.strip()]
    loops[var] = [(pre + it + post) for it in items]

print("=== 直接注册 (%d) ===" % len(direct))
for r in direct:
    print("  ", r)
for var, routes in loops.items():
    print(f"=== 循环 [{var}] ({len(routes)} 条) ===")
    for r in routes:
        print("  ", r)
total = len(direct) + sum(len(v) for v in loops.values())
print("\nstub 区间路由总数:", total)
