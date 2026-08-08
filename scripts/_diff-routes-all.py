"""对比 DoctorateTs 与四个参考项目（DoctoratePy/ODPY/OBS/LocalArknight）的路由差异"""
import re
import os

ROOT = r"D:\develop\DoctorateTs"
DTS = os.path.join(ROOT, "app")
DPY = os.path.join(ROOT, "reference", "DoctoratePy", "server")
ODPY = os.path.join(ROOT, "reference", "opendoctoratepy-ex-public", "server")
OBS = os.path.join(ROOT, "reference", "OpenBachelorS-master", "src", "openbachelors")
LA = os.path.join(ROOT, "reference", "LocalArknight-main", "src", "main", "java")

TS_ROUTER = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*outer|app|r)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']')

ROOT_MOUNTS = [
    ("/config/prod", "config/prod.ts"),
    ("/api/remote_config", "config/remote-config.ts"),
    ("/api/gate", "config/gate.ts"),
    ("/api/game", "config/launcher.ts"),
    ("/assetbundle", "asset.ts"),
]
GAME_MOUNTS = [
    ("/businessCard", "game/router/businessCard.ts"),
    ("/account", "game/router/account.ts"),
    ("/charBuild", "game/router/charBuild.ts"),
    ("/building", "game/router/building.ts"),
    ("/quest", "game/router/quest.ts"),
    ("/user", "game/router/user.ts"),
    ("/activity", "game/router/activity.ts"),
    ("/storyreview", "game/router/storyreview.ts"),
    ("/mission", "game/router/mission.ts"),
    ("/shop", "game/router/shop.ts"),
    ("/rlv2", "game/router/rlv2.ts"),
    ("/gacha", "game/router/gacha.ts"),
    ("/mail", "game/router/mail.ts"),
    ("/social", "game/router/social.ts"),
    ("/retro", "game/router/retro.ts"),
    ("/aprilFool", "game/router/aprilFool.ts"),
    ("/crisis", "game/router/crisis.ts"),
    ("/deepsea", "game/router/deepsea.ts"),
    ("/tower", "game/router/tower.ts"),
    ("/charm", "game/router/charm.ts"),
    ("/charRotation", "game/router/charRotation.ts"),
    ("/depot", "game/router/depot.ts"),
    ("/sandbox", "game/router/sandbox.ts"),
    ("/templateShop", "game/router/templateShop.ts"),
    ("/mailCollection", "game/router/mailCollection.ts"),
    ("/multiplayer", "game/router/multiplayer.ts"),
    ("/roguelike", "game/router/roguelike.ts"),
    ("/campaignV2", "game/router/campaignV2.ts"),
    ("/vecbreak", "game/router/vecbreak.ts"),
    ("/interlock", "game/router/interlock.ts"),
    ("/autochess", "game/router/autochess.ts"),
    ("/pay", "game/router/pay.ts"),
    ("/", "game/router/home.ts"),
    ("/", "game/router/user.ts"),
    ("/", "auth/auth.ts"),
]
# activity 模块的根级路由（act25side/act29side/act36side/actcheckinvs 等客户端无 /activity 前缀的接口）
ROOT_MOUNTS += [("/", "game/router/activity.ts#rootRouter")]
# 客户端将 roguelike/interlock/vecBreakV2 挂在 /activity 前缀下（router 自带 /roguelike|/interlock|/vecBreakV2 路径）
GAME_MOUNTS += [
    ("/activity", "game/router/roguelike.ts"),
    ("/activity", "game/router/interlock.ts"),
    ("/activity", "game/router/vecbreak.ts"),
]

# 既有双前缀设计：以下 router 自带模块前缀，app.ts 挂载前缀 + 模块内前缀 → 双前缀
DOUBLE_PREFIX = ["retro", "campaignV2", "vecbreak", "interlock", "roguelike", "aprilFool"]


def read(p):
    if not os.path.exists(p):
        return ""
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def dts_routes():
    routes = {}
    for prefix, fn in ROOT_MOUNTS + GAME_MOUNTS:
        if "#" in fn:
            # 同一文件导出的多个 router（activity.ts 的 rootRouter），按导出名读取对应块
            src = read(os.path.join(DTS, fn.split("#")[0]))
            block = src.split(f"export const {fn.split('#')[1]} = Router();", 1)
            src = block[1] if len(block) > 1 else ""
        else:
            src = read(os.path.join(DTS, fn))
        for m in TS_ROUTER.finditer(src):
            if m.group(2) == "use":
                continue
            path = m.group(3)
            if not path.startswith("/"):
                continue
            module = fn.split("/")[-1].replace(".ts", "").split("#")[0]
            if prefix != "/" and module in DOUBLE_PREFIX and not path.startswith(prefix):
                # 双前缀设计：/retro/retro/xxx、/campaignV2/campaignV2/xxx
                full = prefix + prefix + path
            elif prefix != "/":
                full = prefix.rstrip("/") + path
            else:
                full = path
            routes.setdefault(full, set()).add(m.group(2).upper())
    return routes


def py_routes(dirpath, patterns):
    """从 Python 项目提取 {full_path: methods}。patterns: [(regex, transform)]"""
    routes = {}
    for dirpath_, _, files in os.walk(dirpath):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            src = read(os.path.join(dirpath_, fn))
            for pat, fix in patterns:
                for m in pat.finditer(src):
                    path = m.group(1) if fix is None else fix(m.group(1))
                    if path.startswith("/"):
                        routes.setdefault(path, set()).add(m.group(2).upper() if len(m.groups()) > 1 else "POST")
    return routes


def obs_routes():
    routes = {}
    OBS_ROUTER = re.compile(r'@router\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']')
    bp_dir = os.path.join(OBS, "bp")
    for fn in sorted(os.listdir(bp_dir)):
        if not fn.endswith(".py"):
            continue
        src = read(os.path.join(bp_dir, fn))
        for m in OBS_ROUTER.finditer(src):
            routes.setdefault(m.group(2), set()).add(m.group(1).upper())
    # app 根挂载（auth/config 等，bp 之外）
    app_src = read(os.path.join(OBS, "app.py"))
    for m in re.finditer(r'@app\.(get|post)\(\s*["\']([^"\']+)["\']', app_src):
        routes.setdefault(m.group(2), set()).add(m.group(1).upper())
    return routes


def dpy_routes():
    pat = re.compile(r'add_url_rule\(["\']([^"\']+)["\']')
    routes = {}
    for fn in ["app.py"]:
        src = read(os.path.join(DPY, fn))
        for m in pat.finditer(src):
            routes.setdefault(m.group(1), set()).add("POST")
    return routes


def odpy_routes():
    pat = re.compile(r'add_url_rule\(["\']([^"\']+)["\']')
    routes = {}
    for fn in ["app.py"]:
        src = read(os.path.join(ODPY, fn))
        for m in pat.finditer(src):
            routes.setdefault(m.group(1), set()).add("POST")
    return routes


def la_routes():
    routes = {}
    # Java: @PostMapping/@GetMapping/@RequestMapping 或路由映射
    pats = [
        re.compile(r'@(PostMapping|GetMapping|RequestMapping)\(\s*["\']([^"\']+)["\']'),
        re.compile(r'(?:post|get|put|delete)\(["\']([^"\']+)["\']'),
    ]
    for dirpath_, _, files in os.walk(LA):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            src = read(os.path.join(dirpath_, fn))
            for m in pats[0].finditer(src):
                path = m.group(2)
                if not path.startswith("/"):
                    continue
                methods = "POST" if m.group(1) == "PostMapping" else ("GET" if m.group(1) == "GetMapping" else "POST")
                routes.setdefault(path, set()).add(methods)
    return routes


def norm(p):
    return re.sub(r"\{([^}]+)\}", r":\1", p)


def diff(name, ref_routes):
    dts = dts_routes()
    dts_keys = {norm(k): v for k, v in dts.items()}
    missing = {}
    for path, methods in sorted(ref_routes.items()):
        n = norm(path)
        if n in dts_keys:
            have = dts_keys[n]
            miss_m = methods - have
            if miss_m:
                missing[path] = miss_m
        else:
            missing[path] = methods
    print(f"\n===== {name}（参考 {len(ref_routes)} 条，本项目缺失 {len(missing)} 条）=====")
    for path, methods in sorted(missing.items()):
        print(f"  [{','.join(sorted(methods))}] {path}")
    return missing


if __name__ == "__main__":
    print(f"本项目(DoctorateTs)路由数: {len(dts_routes())}")
    diff("DoctoratePy(优先级1)", dpy_routes())
    diff("LocalArknight(优先级2)", la_routes())
    diff("opendoctoratepy-ex-public(优先级3.1)", odpy_routes())
    diff("OpenBachelorS(优先级3.2)", obs_routes())
