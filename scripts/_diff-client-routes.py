#!/usr/bin/env python3
"""对比官方客户端路由（reference/client-routes.txt，提取自反编译 C#）与 DoctorateTs 实际实现路由。

数据源：
- 官方：reference/client-routes.txt（scripts/_extract-routes.py 从反编译 C# 提取）
- 服务器：app/game/routes.ts 挂载表 + app/game/router/*.ts + app/auth/auth.ts + index.ts 别名

还原完整客户端可见 URL（处理双前缀、URL 重写别名、rootRouter 分节、循环注册、大小写），输出缺失清单。
"""
import re
import os
import json
from collections import Counter

ROOT = r"D:\develop\DoctorateTs"
APP = os.path.join(ROOT, "app")
GAME = os.path.join(APP, "game")

# 直接 router.post("/path") 注册
DIRECT_REG = re.compile(
    r"\b(?:rootRouter|router)\.(get|post|put|delete|patch)\(\s*([\"'`])([^\"'`]+)\2"
)
# 循环注册: for (const X of ["a","b"]) { router.post(`/pre/${X}/post`, ...) }
LOOP_REG = re.compile(
    r"for \((?:const|let) [A-Za-z_][A-Za-z0-9_]* of \[([^\]]+)\]\) \{"
    r"[^}]*?\.(get|post|put|delete|patch)\(`([^`$]*)\$\{[A-Za-z_][A-Za-z0-9_]*\}([^`]*)`"
)
# 循环注册（变量传参变体）: for (const X of [...]) { router.post/all(X, ...) }
LOOP_ALL_REG = re.compile(
    r"for \((?:const|let) [A-Za-z_][A-Za-z0-9_]* of \[([^\]]+)\]\) \{"
    r"[^}]*?\.(?:get|post|put|delete|patch|all)\(\s*[A-Za-z_][A-Za-z0-9_]*"
)
# 直接 router.all("/path")
DIRECT_ALL_REG = re.compile(r"\brouter\.all\(\s*([\"'`])([^\"'`]+)\1")


def read(p):
    if not os.path.exists(p):
        return ""
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_routes_table():
    """解析 routes.ts 里的路由表条目"""
    src = read(os.path.join(GAME, "routes.ts"))
    entries = []
    for m in re.finditer(
        r'\{\s*prefix:\s*"([^"]*)"[^}]*?module:\s*"\./router/([^"]+)"(?:[^}]*?exportName:\s*"([^"]+)")?(?:[^}]*?rewrite:\s*([A-Za-z_]+))?',
        src,
    ):
        entries.append(
            {
                "prefix": m.group(1),
                "module": m.group(2),
                "exportName": m.group(3) or "default",
                "rewrite": m.group(4),
            }
        )
    return entries


def _extract_section(src, var_re):
    """从一段源码中抽取 {path: methods}，只统计 var_re 匹配的 router 变量"""
    paths = {}
    for lm in LOOP_REG.finditer(src):
        items = [x.strip().strip("'\"") for x in lm.group(1).split(",")]
        for item in items:
            p = lm.group(3) + item + lm.group(4)
            paths.setdefault(p, set()).add(lm.group(2).upper())
    for m in var_re.finditer(src):
        # group(1)=method, group(2)=引号, group(3)=路径
        paths.setdefault(m.group(3), set()).add(m.group(1).upper())
    return paths


def extract_router_paths(module_name):
    """从 router 文件抽取内部路径 -> 方法集。

    返回 (default_paths, root_paths)：
    - default_paths：整个文件中注册在 `router`（default 导出实例）上的路径
      （activity.ts 等文件在 rootRouter 声明之后仍用 `router` 注册 /arkhub/* 等，
      因此 default 必须扫全文件，不能按行分割）
    - root_paths：注册在 `rootRouter` 上的路径
    """
    fn = os.path.join(GAME, "router", module_name + ".ts")
    if not os.path.exists(fn):
        return {}, {}
    src = read(fn)
    default_re = re.compile(
        r"\brouter\.(get|post|put|delete|patch)\(\s*([\"'`])([^\"'`]+)\2"
    )
    root_re = re.compile(
        r"\brootRouter\.(get|post|put|delete|patch)\(\s*([\"'`])([^\"'`]+)\2"
    )
    default_paths = _extract_section(src, default_re)
    root_paths = _extract_section(src, root_re)

    # 循环 router.all(X)（misc-alignment 的 telemetry/pay/admin/en stub 数组）
    for lm in LOOP_ALL_REG.finditer(src):
        items = [x.strip().strip("'\"") for x in lm.group(1).split(",")]
        for item in items:
            default_paths.setdefault(item, set()).add("ALL")
    # 直接 router.all("/path")
    for m in DIRECT_ALL_REG.finditer(src):
        default_paths.setdefault(m.group(2), set()).add("ALL")
    return default_paths, root_paths


def resolve_full_paths():
    """把挂载表 + router 内部路径还原为客户端可见完整 URL"""
    entries = parse_routes_table()
    full = {}  # url -> set(methods)
    module_paths_cache = {}
    for e in entries:
        if e["module"] not in module_paths_cache:
            module_paths_cache[e["module"]] = extract_router_paths(e["module"])
        default_paths, root_paths = module_paths_cache[e["module"]]
        paths = root_paths if e["exportName"] == "rootRouter" else default_paths
        prefix = e["prefix"]
        rewrite = e["rewrite"]
        for inner, methods in paths.items():
            if rewrite == "crisisV2Rewrite":
                assert inner.startswith("/v2/"), inner
                url = "/crisisV2" + inner[3:]
            elif rewrite == "sandboxPermRewrite":
                if inner.startswith("/v2/"):
                    url = "/sandboxPerm/sandboxV2" + inner[3:]
                elif inner.startswith("/v3/"):
                    url = "/sandboxPerm/sandboxV3" + inner[3:]
                else:
                    url = "/sandboxPerm" + inner
            elif prefix == "/":
                url = inner
            else:
                url = prefix.rstrip("/") + inner
            full.setdefault(url, set()).update(methods)
    return full


def add_auth_and_index_aliases(full):
    """补充认证层路由（app/auth/auth.ts，根级挂载）与 index.ts 的 OLD_AUTH_ALIASES 别名"""
    auth_src = read(os.path.join(APP, "auth", "auth.ts"))
    for m in re.finditer(r"\brouter\.(get|post|put|delete)\(\s*([\"'`])([^\"'`]+)\2", auth_src):
        full.setdefault(m.group(3), set()).add(m.group(1).upper())
    idx_src = read(os.path.join(ROOT, "index.ts"))
    for m in re.finditer(
        r'"(/(?:user|account)/[^"]+)":\s*"(/[^"]+)"', idx_src
    ):
        full.setdefault(m.group(1), set()).add("POST")
    # /user/info/v1/logout 等 auth 层其他端点也已在上方正则覆盖
    return full


def load_client_routes():
    out = []
    with open(os.path.join(ROOT, "reference", "client-routes.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def norm(p):
    return re.sub(r"\{([^}]+)\}", r":\1", p)


def main():
    server = resolve_full_paths()
    server = add_auth_and_index_aliases(server)
    client = load_client_routes()

    # 归一化（参数占位符）
    server_norm = {norm(k): (k, v) for k, v in server.items()}

    missing = []
    case_only = []  # 大小写不同但 Express 大小写不敏感可覆盖
    for c in client:
        n = norm(c)
        if n in server_norm:
            continue
        # 大小写不敏感兜底（Express 默认 case-insensitive）
        nl = n.lower()
        if nl in {norm(k).lower() for k in server}:
            case_only.append(c)
        else:
            missing.append(c)

    extra = [k for k in server if norm(k) not in {norm(c) for c in client}]

    print(f"官方路由: {len(client)} 条")
    print(f"服务器实现: {len(server)} 条")
    print(f"已匹配: {len(client) - len(missing) - len(case_only)} 条")
    print(f"大小写变体(运行时可达): {len(case_only)} 条")
    print(f"未实现: {len(missing)} 条")
    print(f"服务器额外: {len(extra)} 条")

    cnt = Counter(m.split("/")[1] if "/" in m[1:] else m for m in missing)
    print("\n=== 未实现路由按模块统计 ===")
    for seg, n in cnt.most_common():
        print(f"  /{seg}/ ... x{n}")

    with open(
        os.path.join(ROOT, "reference", "client-routes-missing-current.json"),
        "w",
        encoding="utf-8",
    ) as fp:
        json.dump(
            {
                "official_total": len(client),
                "server_total": len(server),
                "missing": sorted(missing),
                "case_only": sorted(case_only),
                "extra_count": len(extra),
            },
            fp,
            ensure_ascii=False,
            indent=1,
        )
    print("\n明细已写入 reference/client-routes-missing-current.json")


if __name__ == "__main__":
    main()
